package oscar

import (
	"bytes"
	"context"
	"crypto/md5"
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
	testAuthKey    = "the-auth-key"
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

	// The BUCP branch is selected by an EMPTY TLV list. A screen name here would
	// silently route the server into the legacy FLAP roasted-password path.
	if sf := fs.expectSignon(); len(sf.TLVList) != 0 {
		t.Fatalf("client signon frame must carry no TLVs (BUCP selector), got %d", len(sf.TLVList))
	}

	chal := tlvsOf(t, fs.expectSNAC(wire.BUCP, wire.BUCPChallengeRequest))
	if sn, ok := chal.String(wire.LoginTLVTagsScreenName); !ok || sn != testScreenName {
		t.Fatalf("challenge screen name = %q (found=%v), want %q", sn, ok, testScreenName)
	}
	fs.send(wire.BUCP, wire.BUCPChallengeResponse,
		wire.SNAC_0x17_0x07_BUCPChallengeResponse{AuthKey: testAuthKey})

	login := tlvsOf(t, fs.expectSNAC(wire.BUCP, wire.BUCPLoginRequest))

	// The hash must be strong MD5: md5(authKey + md5(password) + magic).
	inner := md5.Sum([]byte(testPassword))
	outer := md5.New()
	outer.Write([]byte(testAuthKey))
	outer.Write(inner[:])
	outer.Write([]byte("AOL Instant Messenger (SM)"))
	wantHash := outer.Sum(nil)

	gotHash, ok := login.Bytes(wire.LoginTLVTagsPasswordHash)
	if !ok {
		t.Fatal("login request missing password hash TLV 0x25")
	}
	if !bytes.Equal(gotHash, wantHash) {
		t.Fatalf("password hash:\n got %x\nwant %x", gotHash, wantHash)
	}

	// The roasted-password TLV must never accompany the BUCP hash.
	if login.HasTag(wire.LoginTLVTagsRoastedPassword) {
		t.Error("login request must not carry roasted password TLV 0x02 alongside 0x25")
	}
	if flags, ok := login.Bytes(wire.LoginTLVTagsMultiConnFlags); !ok || flags[0] != wire.MultiConnFlagsRecentClient {
		t.Errorf("multi-conn flags = %v (found=%v), want 0x01", flags, ok)
	}

	resp := wire.SNAC_0x17_0x03_BUCPLoginResponse{}
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("Triy")))
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, []byte("bos.example.com:5190")))
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, testCookie()))
	fs.send(wire.BUCP, wire.BUCPLoginResponse, resp)

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
	fs.expectSNAC(wire.BUCP, wire.BUCPChallengeRequest)
	fs.send(wire.BUCP, wire.BUCPChallengeResponse,
		wire.SNAC_0x17_0x07_BUCPChallengeResponse{AuthKey: testAuthKey})
	fs.expectSNAC(wire.BUCP, wire.BUCPLoginRequest)

	resp := wire.SNAC_0x17_0x03_BUCPLoginResponse{}
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte(testScreenName)))
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword))
	fs.send(wire.BUCP, wire.BUCPLoginResponse, resp)

	err := <-done
	var le *LoginError
	if !errors.As(err, &le) {
		t.Fatalf("got %v (%T), want *LoginError", err, err)
	}
	if le.Code != wire.LoginErrInvalidPassword {
		t.Fatalf("error code = 0x%02x, want 0x%02x", le.Code, wire.LoginErrInvalidPassword)
	}
}

// TestLoginUnknownUserFailsAtChallenge covers the server's real behavior for an
// unknown screen name: it answers the CHALLENGE with a login-response error
// carrying only TLV 0x08 — no screen name TLV. Parsing must not require one.
func TestLoginUnknownUserFailsAtChallenge(t *testing.T) {
	client, fs := newFakeServer(t)

	done := make(chan error, 1)
	go func() {
		_, err := loginOn(client, Credentials{ScreenName: "nobody", Password: testPassword})
		done <- err
	}()

	fs.hello()
	fs.expectSignon()
	fs.expectSNAC(wire.BUCP, wire.BUCPChallengeRequest)

	resp := wire.SNAC_0x17_0x03_BUCPLoginResponse{}
	resp.Append(wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword))
	fs.send(wire.BUCP, wire.BUCPLoginResponse, resp)

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
func TestReadSNACSkipsKeepAlive(t *testing.T) {
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
