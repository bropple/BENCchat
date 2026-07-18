package oscar

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// Live tests talk to a real OSCAR server and are opt-in, so the default
// `go test ./...` stays hermetic and offline:
//
//	BENCCHAT_LIVE_SERVER=oscar.example.com:5190 go test ./internal/oscar/ -run Live -v
//
// The address is read from the environment rather than hardcoded, matching the
// rule that the server is configuration, not a constant (CLAUDE.md).
func liveAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("BENCCHAT_LIVE_SERVER")
	if addr == "" {
		t.Skip("set BENCCHAT_LIVE_SERVER=host:port to run live server tests")
	}
	return addr
}

// TestLiveServerHello checks our framing against the real thing: the server
// must greet us with a FLAP signon frame carrying version 1. This is the
// cheapest possible end-to-end proof that the transport reads real bytes
// correctly, with no account required.
func TestLiveServerHello(t *testing.T) {
	addr := liveAddr(t)

	conn, err := Dial(context.Background(), addr, 0)
	if err != nil {
		t.Fatalf("Dial(%s): %v", addr, err)
	}
	defer conn.Close()

	sf, err := conn.ReadSignonFrame()
	if err != nil {
		t.Fatalf("ReadSignonFrame: %v", err)
	}
	if sf.FLAPVersion != 1 {
		t.Fatalf("server FLAP version = %d, want 1", sf.FLAPVersion)
	}
	t.Logf("server hello OK: FLAP version %d, %d TLVs", sf.FLAPVersion, len(sf.TLVList))
}

// TestLiveUnknownUserRejected drives the real BUCP handshake far enough to prove
// the framing, the empty-TLV BUCP branch selection, and error decoding all work
// against the live server — without needing an account. An unknown screen name
// is rejected at the challenge stage with error 0x01.
//
// If this ever returns success, the server is running with DISABLE_AUTH=true,
// which auto-creates accounts on login.
func TestLiveUnknownUserRejected(t *testing.T) {
	addr := liveAddr(t)

	_, err := Login(context.Background(), addr, Credentials{
		ScreenName: "benchat-probe-nonexistent",
		Password:   "not-a-real-password",
	})
	if err == nil {
		t.Fatal("unknown screen name unexpectedly signed on (is DISABLE_AUTH=true?)")
	}

	var le *LoginError
	if !errors.As(err, &le) {
		t.Fatalf("got %v (%T), want a *LoginError from the server", err, err)
	}
	if le.Code != wire.LoginErrInvalidUsernameOrPassword {
		t.Errorf("error code = 0x%02x, want 0x%02x", le.Code, wire.LoginErrInvalidUsernameOrPassword)
	}
	t.Logf("live server rejected unknown user as expected: %v", le)
}

// TestLiveSignOn is the full end-to-end check and needs real credentials:
//
//	BENCCHAT_LIVE_SERVER=oscar.example.com:5190 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/oscar/ -run TestLiveSignOn -v
func TestLiveSignOn(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD to run the full sign-on test")
	}

	res, err := Login(context.Background(), addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(res.Cookie) != 256 {
		t.Errorf("cookie length = %d, want 256", len(res.Cookie))
	}
	if res.BOSAddress == "" {
		t.Error("empty BOS address")
	}
	t.Logf("signed on as %q; BOS=%s, cookie=%dB", res.ScreenName, res.BOSAddress, len(res.Cookie))
}

// TestLiveRateParams proves our RateParamsReply wire layout matches what the
// real server sends: SignOn decodes the reply and builds the rate limiter, so a
// populated limiter with a sane ICBM mapping is end-to-end confirmation that the
// 30-byte (version-1, no V2Params tail) class layout and the greedy rate-group
// slice decode correctly against reality. Needs the same credentials as
// TestLiveSignOn.
func TestLiveRateParams(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.conn.Close()

	if session.rateLimiter == nil {
		t.Fatal("rate limiter is nil — the server's RateParamsReply failed to decode (wire layout mismatch)")
	}
	if len(session.rateLimiter.classes) == 0 {
		t.Fatal("rate limiter has no classes")
	}
	// The server governs outbound IMs; that mapping must be present for pacing to
	// protect the class that matters most for a chat client.
	if _, ok := session.rateLimiter.snacs[snacKey(wire.ICBM, wire.ICBMChannelMsgToHost)]; !ok {
		t.Error("no rate class mapped for outbound ICBM — messages would go unpaced")
	}
	t.Logf("rate limiter built: %d classes, %d SNAC mappings",
		len(session.rateLimiter.classes), len(session.rateLimiter.snacs))
}

// TestLiveAddBuddy exercises buddy-list editing against the real server: it
// removes alice (tolerating "not on list"), then adds alice back, and confirms the
// server accepts the insert (FeedbagStatus success) and the reloaded list shows
// the buddy. This is the real proof that our insert/update byte encoding is
// correct — unit tests can't catch a server-rejected item.
func TestLiveAddBuddy(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}
	const target = "alice"

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.Close()

	// Record the server's feedbag acks from the read loop.
	var mu sync.Mutex
	var statuses []uint16
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		if frame.FoodGroup == wire.Feedbag && frame.SubGroup == wire.FeedbagStatus {
			var st wire.SNAC_0x13_0x0E_FeedbagStatus
			if wire.UnmarshalBE(&st, bytes.NewReader(body)) == nil {
				mu.Lock()
				statuses = append(statuses, st.Results...)
				mu.Unlock()
			}
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = session.Run(runCtx) }()

	// Start from a known state: remove alice if present (ignore "not on list").
	if _, err := session.RemoveBuddy(target); err != nil {
		t.Logf("remove (pre-clean, expected if absent): %v", err)
	}
	time.Sleep(1 * time.Second)

	mu.Lock()
	statuses = nil
	mu.Unlock()

	list, err := session.AddBuddy(target, "")
	if err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	// The local list must show alice.
	found := false
	for _, b := range list.Buddies {
		if b.ScreenName == target {
			found = true
		}
	}
	if !found {
		t.Errorf("alice not in returned buddy list: %+v", list.Buddies)
	}

	// The server must have acknowledged the insert without an error code.
	mu.Lock()
	defer mu.Unlock()
	if len(statuses) == 0 {
		t.Fatal("no FeedbagStatus received from server after AddBuddy")
	}
	for _, code := range statuses {
		if code != wire.FeedbagStatusSuccess && code != wire.FeedbagStatusAuthRequired {
			t.Errorf("server rejected the buddy edit with code 0x%04x", code)
		}
	}
	t.Logf("server acknowledged buddy add; status codes: %v", statuses)
}

// TestLiveSetAway confirms the server accepts a Locate SetInfo away message: a
// malformed one draws a LocateErr or a disconnect, so a clean 3-second window
// after setting (and clearing) away is the proof.
func TestLiveSetAway(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.Close()

	var mu sync.Mutex
	var locateErr bool
	session.Handler = func(frame wire.SNACFrame, _ []byte) {
		if frame.FoodGroup == wire.Locate && frame.SubGroup == wire.LocateErr {
			mu.Lock()
			locateErr = true
			mu.Unlock()
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- session.Run(runCtx) }()

	if err := session.SetAway("Testing BENCchat away status."); err != nil {
		t.Fatalf("SetAway: %v", err)
	}
	time.Sleep(2 * time.Second)
	if err := session.SetAway(""); err != nil {
		t.Fatalf("clear away: %v", err)
	}
	time.Sleep(1 * time.Second)

	mu.Lock()
	if locateErr {
		t.Error("server returned a Locate error for the away message")
	}
	mu.Unlock()

	select {
	case err := <-runErr:
		t.Fatalf("session dropped during away test: %v", err)
	default:
		t.Log("away set and cleared; session stayed up")
	}
}

// TestLiveAwayMessageFetch verifies the Locate UserInfoQuery/Reply round trip
// against the real server: it asks for alice's away message and confirms the
// reply decodes. If alice is away, the text is non-empty; either way a clean
// decode proves the wire path.
func TestLiveAwayMessageFetch(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}
	const target = "alice"

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.Close()

	got := make(chan LocateReply, 1)
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		if frame.FoodGroup == wire.Locate && frame.SubGroup == wire.LocateUserInfoReply {
			if lr, err := DecodeLocateReply(body); err == nil {
				select {
				case got <- lr:
				default:
				}
			}
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = session.Run(runCtx) }()

	if err := session.RequestAwayMessage(target); err != nil {
		t.Fatalf("RequestAwayMessage: %v", err)
	}

	select {
	case lr := <-got:
		t.Logf("locate reply for %q: away=%q profile=%q", lr.ScreenName, lr.Away, lr.Profile)
	case <-time.After(5 * time.Second):
		t.Fatal("no LocateUserInfoReply received within 5s (is alice offline?)")
	}
}

// TestLiveBlockUnblock verifies the block/unblock feedbag encoding (deny +
// pdinfo items) against the real server, then cleans up after itself.
func TestLiveBlockUnblock(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}
	const target = "alice"

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.Close()

	var mu sync.Mutex
	var statuses []uint16
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		if frame.FoodGroup == wire.Feedbag && frame.SubGroup == wire.FeedbagStatus {
			var st wire.SNAC_0x13_0x0E_FeedbagStatus
			if wire.UnmarshalBE(&st, bytes.NewReader(body)) == nil {
				mu.Lock()
				statuses = append(statuses, st.Results...)
				mu.Unlock()
			}
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = session.Run(runCtx) }()

	// Clean slate: unblock first if already blocked (ignore "not blocked").
	if _, err := session.UnblockBuddy(target); err != nil {
		t.Logf("pre-clean unblock (expected if not blocked): %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	mu.Lock()
	statuses = nil
	mu.Unlock()

	list, err := session.BlockBuddy(target)
	if err != nil {
		t.Fatalf("BlockBuddy: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	blocked := false
	for _, b := range list.Blocked {
		if b == target {
			blocked = true
		}
	}
	if !blocked {
		t.Errorf("%q not in blocked list after block: %v", target, list.Blocked)
	}

	mu.Lock()
	if len(statuses) == 0 {
		t.Fatal("no FeedbagStatus after block")
	}
	for _, code := range statuses {
		if code != wire.FeedbagStatusSuccess && code != wire.FeedbagStatusAuthRequired {
			t.Errorf("server rejected block edit: 0x%04x", code)
		}
	}
	mu.Unlock()
	t.Logf("block accepted by server; cleaning up")

	// Clean up so we don't leave alice blocked.
	if _, err := session.UnblockBuddy(target); err != nil {
		t.Errorf("cleanup unblock: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
}

// TestLiveSession is the full end-to-end proof: BUCP auth, BOS reconnect with
// the cookie, the OSERVICE handshake, the feedbag load, and ClientOnline. It
// then holds the session open briefly to see whatever the server pushes.
//
// Needs the same credentials as TestLiveSignOn.
func TestLiveSession(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD to run the full session test")
	}

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn (BOS handshake): %v", err)
	}
	defer session.Close()

	t.Logf("BOS session up as %q", session.ScreenName())
	t.Logf("server advertised %d foodgroups: %v", len(session.FoodGroups()), session.FoodGroups())

	list := session.BuddyList()
	t.Logf("buddy list: %d buddies across %d groups %v", len(list.Buddies), len(list.Groups), list.Groups)
	for _, b := range list.Buddies {
		t.Logf("  buddy %q (group %q, alias %q)", b.ScreenName, b.Group, b.Alias)
	}

	// Watch the wire for a moment: ClientOnline should draw buddy arrivals for
	// anyone already signed on, plus the stats-interval SNAC.
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		switch {
		case frame.FoodGroup == wire.Buddy && frame.SubGroup == wire.BuddyArrived:
			if info, err := DecodeUserInfo(body); err == nil {
				t.Logf("  <- buddy arrived: %q (away=%v, idle=%dm)", info.ScreenName, info.Away, info.IdleMinutes)
			}
		default:
			t.Logf("  <- SNAC(0x%04x,0x%04x) %d bytes", frame.FoodGroup, frame.SubGroup, len(body))
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(runCtx) }()

	select {
	case err := <-done:
		// The server dropping us here means the handshake was wrong somewhere.
		t.Fatalf("session ended early: %v", err)
	case <-runCtx.Done():
		t.Log("session stayed up for the full watch window")
	}
}
