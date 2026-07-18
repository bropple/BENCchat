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
// duration of Login; it is hashed and never retained or persisted.
type Credentials struct {
	ScreenName string
	Password   string
}

// LoginResult is a successful BUCP authorization: where to reconnect and the
// cookie proving we may.
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

// Login runs the BUCP (MD5) sign-on against the authorizer at addr and returns
// the BOS address plus auth cookie. It opens and closes its own connection: the
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

// loginOn runs the BUCP exchange over an already-connected Conn. Split from
// Login so tests can drive the full handshake over a net.Pipe.
func loginOn(conn *Conn, creds Credentials) (*LoginResult, error) {
	// The server greets us first.
	if _, err := conn.ReadSignonFrame(); err != nil {
		return nil, fmt.Errorf("oscar: server hello: %w", err)
	}

	// Our sign-on frame must carry NO TLVs. The server picks the auth mechanism
	// by inspecting this frame: a login cookie (0x06) means service reconnect, a
	// screen name (0x01) means the legacy roasted-password FLAP path, and only an
	// empty TLV list selects BUCP. Putting the screen name here — the obvious
	// thing to do — silently routes us down the wrong path and fails later with a
	// misleading error.
	if err := conn.WriteSignonFrame(nil); err != nil {
		return nil, fmt.Errorf("oscar: send signon: %w", err)
	}

	authKey, err := requestChallenge(conn, creds.ScreenName)
	if err != nil {
		return nil, err
	}

	return sendLogin(conn, creds, authKey)
}

// requestChallenge asks for the screen name's auth key (a per-user salt).
func requestChallenge(conn *Conn, screenName string) (string, error) {
	req := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte(screenName)))

	if err := conn.WriteSNAC(wire.SNACFrame{
		FoodGroup: wire.BUCP,
		SubGroup:  wire.BUCPChallengeRequest,
		RequestID: 1,
	}, req); err != nil {
		return "", fmt.Errorf("oscar: send challenge request: %w", err)
	}

	frame, body, err := conn.ReadSNAC()
	if err != nil {
		return "", fmt.Errorf("oscar: read challenge response: %w", err)
	}

	switch {
	case frame.FoodGroup == wire.BUCP && frame.SubGroup == wire.BUCPChallengeResponse:
		var resp wire.SNAC_0x17_0x07_BUCPChallengeResponse
		if err := wire.UnmarshalBE(&resp, bytes.NewReader(body)); err != nil {
			return "", fmt.Errorf("oscar: decode challenge response: %w", err)
		}
		return resp.AuthKey, nil

	case frame.FoodGroup == wire.BUCP && frame.SubGroup == wire.BUCPLoginResponse:
		// An unknown screen name is rejected at the challenge stage rather than at
		// login. This response carries only the error TLV — no screen name.
		return "", parseLoginError(body)

	default:
		return "", fmt.Errorf("oscar: unexpected SNAC %s while awaiting challenge", snacName(frame))
	}
}

// sendLogin hashes the password against the auth key and completes sign-on.
func sendLogin(conn *Conn, creds Credentials, authKey string) (*LoginResult, error) {
	// Strong hashing: md5(authKey + md5(password) + magic). The server stores both
	// digests and accepts either, but strong is what every client since AIM 4.8
	// sends and it keeps the raw password out of the outer digest.
	hash := wire.StrongMD5PasswordHash(creds.Password, authKey)

	req := wire.SNAC_0x17_0x02_BUCPLoginRequest{}
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte(creds.ScreenName)))
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, hash))
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, []byte(ClientIdentity)))
	// Announce multi-connection support. This opts into concurrent sessions and,
	// just as importantly, makes the server use modern FLAP signoff frames on a
	// forced disconnect rather than the legacy 4-byte disconnect frame, which has
	// no length field and would desynchronize our reader.
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))

	if err := conn.WriteSNAC(wire.SNACFrame{
		FoodGroup: wire.BUCP,
		SubGroup:  wire.BUCPLoginRequest,
		RequestID: 2,
	}, req); err != nil {
		return nil, fmt.Errorf("oscar: send login request: %w", err)
	}

	// Stamp expiry before the round trip so a slow response eats into the budget
	// rather than being credited against it.
	issued := time.Now()

	frame, body, err := conn.ReadSNAC()
	if err != nil {
		return nil, fmt.Errorf("oscar: read login response: %w", err)
	}
	if frame.FoodGroup != wire.BUCP || frame.SubGroup != wire.BUCPLoginResponse {
		return nil, fmt.Errorf("oscar: unexpected SNAC %s while awaiting login response", snacName(frame))
	}

	var resp wire.SNAC_0x17_0x03_BUCPLoginResponse
	if err := wire.UnmarshalBE(&resp, bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("oscar: decode login response: %w", err)
	}

	// Success is signalled by the presence of the cookie TLV, not by the absence
	// of an error TLV — this is how the server's own code discriminates.
	cookie, ok := resp.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		return nil, parseLoginError(body)
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

// parseLoginError turns a failed BUCPLoginResponse body into a *LoginError. The
// screen name TLV is present on login failures but absent on challenge-stage
// failures, so it is treated as optional.
func parseLoginError(body []byte) error {
	var resp wire.SNAC_0x17_0x03_BUCPLoginResponse
	if err := wire.UnmarshalBE(&resp, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("oscar: decode login error: %w", err)
	}

	code, ok := resp.Uint16BE(wire.LoginTLVTagsErrorSubcode)
	if !ok {
		return errors.New("oscar: login rejected without an error code")
	}
	screenName, _ := resp.String(wire.LoginTLVTagsScreenName)
	return &LoginError{Code: code, ScreenName: screenName}
}
