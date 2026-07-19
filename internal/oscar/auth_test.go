package oscar

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// fakeServer plays the server role over a loopback connection. It asserts on
// what the client sends and replies with what the real server would, so the
// handshake is exercised end-to-end without a live server.
type fakeServer struct {
	t *testing.T
	c *Conn // wraps the server end, reusing the framing code to read/write
}

func newFakeServer(t *testing.T) (*Conn, *fakeServer) {
	t.Helper()
	// Sequence 100 matches what open-oscar-server opens every connection with.
	client, serverEnd := connPair(t, 0)
	return client, &fakeServer{t: t, c: NewConn(serverEnd, 100)}
}

// hello sends the server's opening signon frame.
func (f *fakeServer) hello() {
	f.t.Helper()
	if err := f.c.WriteSignonFrame(nil); err != nil {
		f.t.Errorf("fake server hello: %v", err)
	}
}

// expectSignon reads the client's signon frame and returns its TLVs.
func (f *fakeServer) expectSignon() wire.FLAPSignonFrame {
	f.t.Helper()
	sf, err := f.c.ReadSignonFrame()
	if err != nil {
		f.t.Errorf("fake server read signon: %v", err)
	}
	return sf
}

// expectSNAC reads one SNAC and asserts its foodgroup/subgroup.
func (f *fakeServer) expectSNAC(fg, sg uint16) []byte {
	f.t.Helper()
	frame, body, err := f.c.ReadSNAC()
	if err != nil {
		f.t.Errorf("fake server read SNAC: %v", err)
		return nil
	}
	if frame.FoodGroup != fg || frame.SubGroup != sg {
		f.t.Errorf("got SNAC(0x%04x,0x%04x), want SNAC(0x%04x,0x%04x)",
			frame.FoodGroup, frame.SubGroup, fg, sg)
	}
	return body
}

func (f *fakeServer) send(fg, sg uint16, body any) {
	f.t.Helper()
	if err := f.c.WriteSNAC(wire.SNACFrame{FoodGroup: fg, SubGroup: sg}, body); err != nil {
		f.t.Errorf("fake server send SNAC(0x%04x,0x%04x): %v", fg, sg, err)
	}
}

// sendLoginResult writes the server's verdict the way the FLAP sign-on path
// does: a bare TLV block inside a SIGNOFF frame, not a SNAC. The auth server
// states its result and hangs up in the same breath.
func (f *fakeServer) sendLoginResult(tlvs wire.TLVRestBlock) {
	f.t.Helper()
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(tlvs, buf); err != nil {
		f.t.Fatalf("marshal login result: %v", err)
	}
	if err := f.c.WriteFrame(wire.FLAPFrameSignoff, buf.Bytes()); err != nil {
		f.t.Errorf("fake server send login result: %v", err)
	}
}

// loginErrTLVs builds a rejection carrying an error subcode, optionally with the
// screen name the server echoes back on some failures but not others.
func loginErrTLVs(code uint16, screenName string) wire.TLVRestBlock {
	tlvs := wire.TLVRestBlock{}
	if screenName != "" {
		tlvs.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte(screenName)))
	}
	tlvs.Append(wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, code))
	return tlvs
}

// tlvsOf decodes a bare TLV block from a SNAC body.
func tlvsOf(t *testing.T, body []byte) wire.TLVRestBlock {
	t.Helper()
	var b wire.TLVRestBlock
	if err := wire.UnmarshalBE(&b, bytes.NewReader(body)); err != nil {
		t.Fatalf("decode TLV block: %v", err)
	}
	return b
}

const (
	testScreenName = "triy"
	testPassword   = "hunter2"
)

// testCookie is the 256-byte opaque blob the server pads its cookie to.
func testCookie() []byte {
	c := make([]byte, 256)
	copy(c, "cookie-payload")
	return c
}

func TestLoginSuccess(t *testing.T) {
	client, fs := newFakeServer(t)

	type result struct {
		res *LoginResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := loginOn(client, Credentials{ScreenName: testScreenName, Password: testPassword})
		done <- result{res, err}
	}()

	fs.hello()

	// The whole handshake is this one frame now. The server selects the auth
	// mechanism from its TLVs: an EMPTY list would select BUCP, which BENCoscar
	// refuses, and a login cookie would mean a service reconnect.
	sf := fs.expectSignon()
	login := wire.TLVRestBlock{TLVList: sf.TLVList}

	if sn, ok := login.String(wire.LoginTLVTagsScreenName); !ok || sn != testScreenName {
		t.Fatalf("signon screen name = %q (found=%v), want %q", sn, ok, testScreenName)
	}

	// The password goes in TLV 0x1339, verbatim. This is only acceptable because
	// the transport is TLS; the server verifies it against argon2id.
	gotPass, ok := login.Bytes(wire.LoginTLVTagsPlaintextPassword)
	if !ok {
		t.Fatal("signon frame missing plaintext password TLV 0x1339")
	}
	if string(gotPass) != testPassword {
		t.Fatalf("password TLV = %q, want %q", gotPass, testPassword)
	}

	// No MD5 may survive anywhere in the frame. If either of these appears, the
	// client is still speaking a challenge-response dialect the server dropped.
	if login.HasTag(wire.LoginTLVTagsPasswordHash) {
		t.Error("signon frame must not carry BUCP password hash TLV 0x25")
	}
	if login.HasTag(wire.LoginTLVTagsRoastedPassword) {
		t.Error("signon frame must not carry roasted password TLV 0x02")
	}

	if flags, ok := login.Bytes(wire.LoginTLVTagsMultiConnFlags); !ok || flags[0] != wire.MultiConnFlagsRecentClient {
		t.Errorf("multi-conn flags = %v (found=%v), want 0x01", flags, ok)
	}

	resp := wire.TLVRestBlock{}
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("Triy")))
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, []byte("bos.example.com:5190")))
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, testCookie()))
	fs.sendLoginResult(resp)

	got := <-done
	if got.err != nil {
		t.Fatalf("Login: %v", got.err)
	}
	// The server's canonical casing must win over what the user typed.
	if got.res.ScreenName != "Triy" {
		t.Errorf("ScreenName = %q, want server's canonical %q", got.res.ScreenName, "Triy")
	}
	if got.res.BOSAddress != "bos.example.com:5190" {
		t.Errorf("BOSAddress = %q", got.res.BOSAddress)
	}
	if len(got.res.Cookie) != 256 {
		t.Errorf("cookie length = %d, want 256 (must be passed through verbatim)", len(got.res.Cookie))
	}
	if got.res.Expired() {
		t.Error("fresh cookie reported as expired")
	}
}

func TestLoginBadPassword(t *testing.T) {
	client, fs := newFakeServer(t)

	done := make(chan error, 1)
	go func() {
		_, err := loginOn(client, Credentials{ScreenName: testScreenName, Password: "wrong"})
		done <- err
	}()

	fs.hello()
	fs.expectSignon()
	fs.sendLoginResult(loginErrTLVs(wire.LoginErrInvalidPassword, testScreenName))

	err := <-done
	var le *LoginError
	if !errors.As(err, &le) {
		t.Fatalf("got %v (%T), want *LoginError", err, err)
	}
	if le.Code != wire.LoginErrInvalidPassword {
		t.Fatalf("error code = 0x%02x, want 0x%02x", le.Code, wire.LoginErrInvalidPassword)
	}
}

// TestLoginUnknownUserOmitsScreenName covers a rejection that carries only TLV
// 0x08 and no screen name. The server does this for an unknown account, so
// parsing must not require the screen name to be present.
func TestLoginUnknownUserOmitsScreenName(t *testing.T) {
	client, fs := newFakeServer(t)

	done := make(chan error, 1)
	go func() {
		_, err := loginOn(client, Credentials{ScreenName: "nobody", Password: testPassword})
		done <- err
	}()

	fs.hello()
	fs.expectSignon()
	fs.sendLoginResult(loginErrTLVs(wire.LoginErrInvalidUsernameOrPassword, ""))

	err := <-done
	var le *LoginError
	if !errors.As(err, &le) {
		t.Fatalf("got %v (%T), want *LoginError", err, err)
	}
	if le.Code != wire.LoginErrInvalidUsernameOrPassword {
		t.Fatalf("error code = 0x%02x, want 0x%02x", le.Code, wire.LoginErrInvalidUsernameOrPassword)
	}
}

func TestLoginRequiresScreenName(t *testing.T) {
	if _, err := Login(context.Background(), "127.0.0.1:1", Credentials{Password: "x"}); err == nil {
		t.Fatal("expected error for empty screen name")
	}
}

func TestLoginResultExpired(t *testing.T) {
	r := &LoginResult{ExpiresAt: time.Now().Add(-time.Second)}
	if !r.Expired() {
		t.Fatal("cookie past ExpiresAt should report Expired")
	}
}

func TestSignoffErrorReportsNewLogin(t *testing.T) {
	// A BOS signoff with reason 0x01 means the account signed on elsewhere; the
	// message must say so rather than surfacing a bare code.
	tlvs := wire.TLVRestBlock{}
	tlvs.Append(wire.NewTLVBE(wire.OServiceTLVTagsDisconnectReason, wire.OServiceDiscErrNewLogin))
	tlvs.Append(wire.NewTLVBE(wire.OServiceTLVTagsDisconnectInfo, []byte("https://example.com/help")))

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(tlvs, buf); err != nil {
		t.Fatalf("marshal signoff TLVs: %v", err)
	}

	err := decodeSignoff(buf.Bytes())
	if !errors.Is(err, ErrSignedOff) {
		t.Fatalf("signoff error must unwrap to ErrSignedOff, got %v", err)
	}
	var se *SignoffError
	if !errors.As(err, &se) {
		t.Fatalf("got %T, want *SignoffError", err)
	}
	if se.Reason != wire.OServiceDiscErrNewLogin {
		t.Errorf("Reason = 0x%02x, want 0x%02x", se.Reason, wire.OServiceDiscErrNewLogin)
	}
	if se.Info != "https://example.com/help" {
		t.Errorf("Info = %q", se.Info)
	}
}

// TestReadSNACSkipsKeepAlive ensures a keepalive between SNACs doesn't get
// mistaken for a response.
//
// The SNAC it uses is incidental — this is a framing test, not an auth test. It
// still carries a BUCP challenge response because that type remains a correct
// description of the wire format, even though BENCchat no longer sends one.
func TestReadSNACSkipsKeepAlive(t *testing.T) {
	const testAuthKey = "the-auth-key"

	client, fs := newFakeServer(t)

	go func() {
		_ = fs.c.SendKeepAlive()
		fs.send(wire.BUCP, wire.BUCPChallengeResponse,
			wire.SNAC_0x17_0x07_BUCPChallengeResponse{AuthKey: testAuthKey})
	}()

	frame, body, err := client.ReadSNAC()
	if err != nil {
		t.Fatalf("ReadSNAC: %v", err)
	}
	if frame.SubGroup != wire.BUCPChallengeResponse {
		t.Fatalf("got subgroup 0x%04x, want challenge response", frame.SubGroup)
	}
	var resp wire.SNAC_0x17_0x07_BUCPChallengeResponse
	if err := wire.UnmarshalBE(&resp, bytes.NewReader(body)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AuthKey != testAuthKey {
		t.Fatalf("AuthKey = %q, want %q", resp.AuthKey, testAuthKey)
	}
}
