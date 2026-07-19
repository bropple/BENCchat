package oscar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// ClientIdentity is what BENCchat reports to the server in TLV 0x03. The server
// stores it on the session and echoes it into the auth cookie.
const ClientIdentity = "BENCchat"

// authDeadline mirrors the server's own 30-second budget for the entire auth
// exchange. Failing on our side produces a real error instead of a socket that
// dies mid-handshake for no visible reason.
const authDeadline = 30 * time.Second

// CookieLifetime is how long the auth cookie stays valid. The server stamps a
// 60-second expiry, so the BOS reconnect has to happen promptly — this is much
// tighter than the classic AOL behavior and is a likely source of "worked in
// testing, fails under a slow DNS lookup" bugs.
const CookieLifetime = 60 * time.Second

// LoginError is a sign-on rejection carrying the server's error subcode.
type LoginError struct {
	Code       uint16
	ScreenName string
}

func (e *LoginError) Error() string { return wire.LoginErrString(e.Code) }

// Credentials is a single sign-on attempt. The password lives here only for the
// duration of Login and is never retained or persisted.
//
// It is sent to the server as-is rather than hashed, which is safe only because
// the connection is TLS — the server needs the cleartext to verify it against an
// argon2id hash. Anything that could route a Login over an unencrypted transport
// is therefore a credential leak, not merely a downgrade.
type Credentials struct {
	ScreenName string
	Password   string
}

// LoginResult is a successful authorization: where to reconnect and the cookie
// proving we may.
type LoginResult struct {
	// ScreenName is the server's canonical form (correct casing/spacing), which
	// may differ from what the user typed.
	ScreenName string
	// BOSAddress is the "host:port" to open the second connection to.
	BOSAddress string
	// Cookie is an opaque 256-byte blob. Do not parse, trim, or re-pad it — it is
	// HMAC-signed and length-sensitive.
	Cookie []byte
	// ExpiresAt is when Cookie stops being accepted by the server.
	ExpiresAt time.Time
	// Transport is how this login connected, carried forward so the BOS
	// reconnect and every chat connection use the same protection. A session
	// that started encrypted must not continue in the clear.
	Transport Transport
	// authPort is the port the user configured, used to correct a
	// server-advertised redirect that points at a plaintext listener.
	authPort string
}

// Expired reports whether the cookie is past its lifetime.
func (r *LoginResult) Expired() bool { return time.Now().After(r.ExpiresAt) }

// Login runs the FLAP sign-on against the authorizer at addr and returns the
// BOS address plus auth cookie. It opens and closes its own connection: the
// server always signs off the auth connection once it has answered, so this
// connection is never reused for messaging.
func Login(ctx context.Context, addr string, creds Credentials, tr ...Transport) (*LoginResult, error) {
	if creds.ScreenName == "" {
		return nil, errors.New("oscar: screen name is required")
	}
	var t Transport
	if len(tr) > 0 {
		t = tr[0]
	}

	conn, err := t.dial(ctx, addr, 0)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(authDeadline)); err != nil {
		return nil, fmt.Errorf("oscar: set auth deadline: %w", err)
	}
	res, err := loginOn(conn, creds)
	if err != nil {
		return nil, err
	}
	// Carry the transport forward: the BOS reconnect and every chat connection
	// this session opens must get the same protection the login had. Without
	// this, a TLS login would hand off to plaintext for everything after it.
	res.Transport = t.withPort(authPortOf(addr)).withAddr(addr)
	res.authPort = authPortOf(addr)
	return res, nil
}

// loginOn runs the sign-on exchange over an already-connected Conn. Split from
// Login so tests can drive the full handshake over a net.Pipe.
//
// This is the FLAP sign-on path, not BUCP. BENCchat used to do the two-step BUCP
// challenge-response: ask for the user's salt, hash the password against it,
// send the digest. BENCoscar no longer supports that, because it requires the
// server to store a value it can reproduce the client's digest from — a password
// equivalent — which rules out hashing passwords with a one-way KDF. The server
// now verifies a password against argon2id, so the password itself goes on the
// wire, inside TLS.
//
// That is one round trip instead of two, and it deletes the MD5 entirely.
func loginOn(conn *Conn, creds Credentials) (*LoginResult, error) {
	// The server greets us first.
	if _, err := conn.ReadSignonFrame(); err != nil {
		return nil, fmt.Errorf("oscar: server hello: %w", err)
	}

	// The server picks the auth mechanism by inspecting this frame's TLVs: a
	// login cookie (0x06) means service reconnect, and an EMPTY list selects
	// BUCP. Carrying a screen name plus a password TLV selects the FLAP path,
	// where 0x1339 specifically means "this is the password in the clear".
	tlvs := []wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte(creds.ScreenName)),
		wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, []byte(creds.Password)),
		wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, []byte(ClientIdentity)),
		// Announce multi-connection support. This opts into concurrent sessions
		// and, just as importantly, makes the server use modern FLAP signoff
		// frames on a forced disconnect rather than the legacy 4-byte disconnect
		// frame, which has no length field and would desynchronize our reader.
		wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
	}

	// Stamp expiry before the round trip so a slow response eats into the budget
	// rather than being credited against it.
	issued := time.Now()

	if err := conn.WriteSignonFrame(tlvs); err != nil {
		return nil, fmt.Errorf("oscar: send signon: %w", err)
	}

	return readLoginResponse(conn, creds, issued)
}

// readLoginResponse reads the server's verdict.
//
// Unlike BUCP, the FLAP path answers with a bare TLV block in a FLAP SIGNOFF
// frame rather than a SNAC — the auth server states its result and hangs up in
// the same breath, which is why Login never reuses this connection.
func readLoginResponse(conn *Conn, creds Credentials, issued time.Time) (*LoginResult, error) {
	frame, err := conn.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("oscar: read login response: %w", err)
	}
	if frame.FrameType != wire.FLAPFrameSignoff {
		return nil, fmt.Errorf("oscar: unexpected FLAP frame type 0x%02x while awaiting login response", frame.FrameType)
	}

	var resp wire.TLVRestBlock
	if err := wire.UnmarshalBE(&resp, bytes.NewReader(frame.Payload)); err != nil {
		return nil, fmt.Errorf("oscar: decode login response: %w", err)
	}

	// Success is signalled by the presence of the cookie TLV, not by the absence
	// of an error TLV — this is how the server's own code discriminates.
	cookie, ok := resp.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		return nil, parseLoginError(resp)
	}

	bosAddr, ok := resp.String(wire.LoginTLVTagsReconnectHere)
	if !ok {
		return nil, errors.New("oscar: login succeeded but server sent no BOS address")
	}

	screenName, ok := resp.String(wire.LoginTLVTagsScreenName)
	if !ok {
		screenName = creds.ScreenName
	}

	return &LoginResult{
		ScreenName: screenName,
		BOSAddress: bosAddr,
		Cookie:     cookie,
		ExpiresAt:  issued.Add(CookieLifetime),
	}, nil
}

// parseLoginError turns a failed login response into a *LoginError. The screen
// name TLV is present on some rejections and absent on others, so it is treated
// as optional.
func parseLoginError(resp wire.TLVRestBlock) error {
	code, ok := resp.Uint16BE(wire.LoginTLVTagsErrorSubcode)
	if !ok {
		return errors.New("oscar: login rejected without an error code")
	}
	screenName, _ := resp.String(wire.LoginTLVTagsScreenName)
	return &LoginError{Code: code, ScreenName: screenName}
}
