package oscar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
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

// liveTransport builds the transport for live tests. BENCoscar terminates TLS
// itself and a real deployment runs no plaintext OSCAR port at all, so a live
// test against one has to speak TLS:
//
//	BENCCHAT_LIVE_TLS=1          verify the certificate normally
//	BENCCHAT_LIVE_TLS=insecure   skip verification, for a self-signed dev server
//
// Unset means plaintext, which still works against a server started without a
// certificate configured.
func liveTransport(t *testing.T) Transport {
	t.Helper()
	switch os.Getenv("BENCCHAT_LIVE_TLS") {
	case "":
		return Transport{}
	case "insecure":
		return Transport{TLS: true, InsecureSkipVerify: true}
	default:
		return Transport{TLS: true}
	}
}

// TestLiveServerHello checks our framing against the real thing: the server
// must greet us with a FLAP signon frame carrying version 1. This is the
// cheapest possible end-to-end proof that the transport reads real bytes
// correctly, with no account required.
func TestLiveServerHello(t *testing.T) {
	addr := liveAddr(t)

	// Dial through the configured transport. Dialling plaintext into a TLS
	// listener does NOT fail at connect — TLS defers its handshake to the first
	// read — so the connection comes up fine and then the read below blocks
	// forever. That is how this test used to hang for the full package timeout
	// rather than failing.
	conn, err := liveTransport(t).dial(context.Background(), addr, 0)
	if err != nil {
		t.Fatalf("Dial(%s): %v", addr, err)
	}
	defer conn.Close()

	// A deadline so a transport mismatch reports itself instead of hanging.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

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

	res, err := Login(context.Background(), addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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

	// A wrong password must be refused. Without this the test would pass against
	// a server with authentication disabled, which is exactly the configuration
	// where a broken credential path looks healthy.
	if _, err := Login(context.Background(), addr,
		Credentials{ScreenName: sn, Password: pw + "-wrong"}, liveTransport(t)); err == nil {
		t.Error("a wrong password was accepted")
	} else {
		var le *LoginError
		if !errors.As(err, &le) {
			t.Errorf("wrong password gave %v (%T), want *LoginError", err, err)
		} else {
			t.Logf("wrong password correctly refused: %v (code 0x%02x)", le, le.Code)
		}
	}
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
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

// TestLiveKeyDirectory exercises the BENCO device key directory (foodgroup
// 0xBE00) against a real BENCoscar. It proves BENCchat's wire encoding
// interoperates with the server's, which is the part most likely to be subtly
// wrong — a mismatched length prefix shows up as a confusing disconnect, not an
// error.
//
// Needs two accounts. The second exists to be OFFLINE while its keys are
// fetched, which is the case the profile-marker scheme could not handle:
//
//	BENCCHAT_LIVE_SERVER=host:port BENCCHAT_LIVE_TLS=insecure \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	BENCCHAT_LIVE_PEER=... BENCCHAT_LIVE_PEER_PASSWORD=... \
//	go test ./internal/oscar/ -run TestLiveKeyDirectory -v
func TestLiveKeyDirectory(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	peer, peerPw := os.Getenv("BENCCHAT_LIVE_PEER"), os.Getenv("BENCCHAT_LIVE_PEER_PASSWORD")
	if sn == "" || pw == "" || peer == "" || peerPw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME/PASSWORD and BENCCHAT_LIVE_PEER/PEER_PASSWORD")
	}
	ctx := context.Background()

	key := func(b byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b
		}
		return k
	}

	// signOn brings up a BOS session and collects key directory replies.
	signOn := func(user, pass string) (*Session, chan wire.SNACFrame, chan []byte) {
		res, err := Login(ctx, addr, Credentials{ScreenName: user, Password: pass}, liveTransport(t))
		if err != nil {
			t.Fatalf("Login(%s): %v", user, err)
		}
		s, err := SignOn(ctx, res)
		if err != nil {
			t.Fatalf("SignOn(%s): %v", user, err)
		}
		frames, bodies := make(chan wire.SNACFrame, 16), make(chan []byte, 16)
		s.Handler = func(f wire.SNACFrame, b []byte) {
			if f.FoodGroup == wire.BENCOKeyDir {
				frames <- f
				bodies <- append([]byte(nil), b...)
			}
		}
		go func() { _ = s.Run(ctx) }()
		return s, frames, bodies
	}

	await := func(frames chan wire.SNACFrame, bodies chan []byte, want uint16) []byte {
		t.Helper()
		for {
			select {
			case f := <-frames:
				b := <-bodies
				if f.SubGroup == want {
					return b
				}
				if f.SubGroup == wire.BENCOKeyDirErr {
					t.Fatalf("server returned a key directory error while awaiting subgroup 0x%04x", want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out awaiting key directory subgroup 0x%04x", want)
			}
		}
	}

	alice, aFrames, aBodies := signOn(sn, pw)
	defer alice.Close()

	if !alice.SupportsKeyDir() {
		t.Fatalf("server does not advertise the key directory; foodgroups=%v", alice.FoodGroups())
	}
	t.Log("server advertises the key directory (0xBE00)")

	// The peer publishes, then disconnects, so its keys are fetched while offline.
	bob, bFrames, bBodies := signOn(peer, peerPw)
	if _, err := bob.PublishDeviceKeys([]wire.BENCODevice{{BoxKey: key(3)}}); err != nil {
		t.Fatalf("peer publish: %v", err)
	}
	await(bFrames, bBodies, wire.BENCOKeyDirPublishReply)
	_ = bob.Close()
	t.Logf("%s published one device, then signed off", peer)

	if _, err := alice.PublishDeviceKeys([]wire.BENCODevice{
		{BoxKey: key(1), SignKey: key(0xA1)},
		{BoxKey: key(2)},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	pub, err := DecodeKeyDirPublishReply(await(aFrames, aBodies, wire.BENCOKeyDirPublishReply))
	if err != nil {
		t.Fatalf("decode publish reply: %v", err)
	}
	if pub.Accepted != 2 || len(pub.Refused) != 0 {
		t.Fatalf("publish: accepted=%d refused=%d, want 2 and 0", pub.Accepted, len(pub.Refused))
	}

	// Our OWN devices. The Locate self-lookup took a branch where a session
	// always exists, so this was impossible before.
	if _, err := alice.QueryDeviceKeys(sn); err != nil {
		t.Fatalf("self query: %v", err)
	}
	self, err := DecodeKeyDirQueryReply(await(aFrames, aBodies, wire.BENCOKeyDirQueryReply))
	if err != nil {
		t.Fatalf("decode self query: %v", err)
	}
	if len(self.Devices) != 2 {
		t.Fatalf("self query returned %d devices, want 2", len(self.Devices))
	}
	if len(self.Devices[0].SignKey) != 32 {
		t.Error("signing key did not survive the round trip")
	}
	t.Logf("read back %d of our own devices", len(self.Devices))

	// The offline peer.
	if _, err := alice.QueryDeviceKeys(peer); err != nil {
		t.Fatalf("peer query: %v", err)
	}
	got, err := DecodeKeyDirQueryReply(await(aFrames, aBodies, wire.BENCOKeyDirQueryReply))
	if err != nil {
		t.Fatalf("decode peer query: %v", err)
	}
	if len(got.Devices) != 1 {
		t.Fatalf("offline peer query returned %d devices, want 1", len(got.Devices))
	}
	t.Logf("fetched %d device(s) for OFFLINE %s", len(got.Devices), peer)

	// Revoke, then try to republish it. The refusal is what makes removal stick.
	if _, err := alice.RevokeDeviceKey(key(1)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rev, err := DecodeKeyDirRevokeReply(await(aFrames, aBodies, wire.BENCOKeyDirRevokeReply))
	if err != nil {
		t.Fatalf("decode revoke reply: %v", err)
	}
	if rev.Revoked != 1 {
		t.Fatalf("revoke reported %d, want 1", rev.Revoked)
	}

	if _, err := alice.PublishDeviceKeys([]wire.BENCODevice{
		{BoxKey: key(1), SignKey: key(0xA1)},
		{BoxKey: key(2)},
	}); err != nil {
		t.Fatalf("republish: %v", err)
	}
	again, err := DecodeKeyDirPublishReply(await(aFrames, aBodies, wire.BENCOKeyDirPublishReply))
	if err != nil {
		t.Fatalf("decode republish reply: %v", err)
	}
	if len(again.Refused) != 1 {
		t.Fatalf("republishing a revoked key was accepted (refused=%d); removal is not durable",
			len(again.Refused))
	}
	t.Logf("republishing the revoked device was refused, as it must be")

	// The exit from the dead end. Before Restore existed a tombstone was
	// permanent: the device republished on every sign-on, was refused, and the
	// client told the user to approve it from another machine — which could not
	// help, because nothing could lift the revocation. The only escape was
	// wiping both machines.
	if _, err := alice.RestoreDeviceKey(key(1)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	res, err := DecodeKeyDirRestoreReply(await(aFrames, aBodies, wire.BENCOKeyDirRestoreReply))
	if err != nil {
		t.Fatalf("decode restore reply: %v", err)
	}
	if res.Restored != 1 {
		t.Fatalf("restore reported %d, want 1", res.Restored)
	}

	if _, err := alice.PublishDeviceKeys([]wire.BENCODevice{
		{BoxKey: key(1), SignKey: key(0xA1)},
		{BoxKey: key(2)},
	}); err != nil {
		t.Fatalf("publish after restore: %v", err)
	}
	back, err := DecodeKeyDirPublishReply(await(aFrames, aBodies, wire.BENCOKeyDirPublishReply))
	if err != nil {
		t.Fatalf("decode publish reply: %v", err)
	}
	if len(back.Refused) != 0 {
		t.Fatalf("a restored device was still refused (%d), so removal is still irreversible",
			len(back.Refused))
	}
	if back.Accepted != 2 {
		t.Fatalf("accepted=%d after restore, want 2", back.Accepted)
	}
	t.Logf("restored device published again — removal is reversible")
}

// TestLiveKeyDirIsAccountScoped answers the question left open when the profile
// key path was removed: does a SECOND device on the same account see what the
// first one published?
//
// This used to be answered for profiles, and the answer was no — a self-directed
// Locate reply came from the asking instance, so device 2 could not see device 1
// (see TestLiveSelfLookupIsInstanceScoped, now skipped). wire/keydir.go
// describes the directory as account-scoped storage instead, but nothing had
// verified that against a real server, and multi-device is built on it being
// true.
//
// The two devices are sequential, not simultaneous, so this holds whether or not
// the server permits concurrent sessions for one account.
//
//	BENCCHAT_LIVE_SERVER=host:port BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/oscar/ -run TestLiveKeyDirIsAccountScoped -v
func TestLiveKeyDirIsAccountScoped(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}
	ctx := context.Background()

	deviceKey := func(b byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b
		}
		return k
	}

	// signOn brings up one "device": a fresh BOS session on the same account.
	signOn := func(label string) (*Session, chan wire.SNACFrame, chan []byte) {
		res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
		if err != nil {
			t.Fatalf("Login(%s): %v", label, err)
		}
		s, err := SignOn(ctx, res)
		if err != nil {
			t.Fatalf("SignOn(%s): %v", label, err)
		}
		frames, bodies := make(chan wire.SNACFrame, 16), make(chan []byte, 16)
		s.Handler = func(f wire.SNACFrame, b []byte) {
			if f.FoodGroup == wire.BENCOKeyDir {
				frames <- f
				bodies <- append([]byte(nil), b...)
			}
		}
		go func() { _ = s.Run(ctx) }()
		return s, frames, bodies
	}

	await := func(frames chan wire.SNACFrame, bodies chan []byte, want uint16) []byte {
		t.Helper()
		for {
			select {
			case f := <-frames:
				b := <-bodies
				if f.SubGroup == want {
					return b
				}
				if f.SubGroup == wire.BENCOKeyDirErr {
					t.Fatalf("server returned a key directory error awaiting subgroup 0x%04x", want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out awaiting key directory subgroup 0x%04x", want)
			}
		}
	}

	// Device one publishes and signs off.
	one, oneFrames, oneBodies := signOn("device one")
	if !one.SupportsKeyDir() {
		_ = one.Close()
		t.Fatalf("server does not advertise the key directory; foodgroups=%v", one.FoodGroups())
	}
	if _, err := one.PublishDeviceKeys([]wire.BENCODevice{
		{BoxKey: deviceKey(0x11), SignKey: deviceKey(0xB1)},
	}); err != nil {
		t.Fatalf("device one publish: %v", err)
	}
	pub, err := DecodeKeyDirPublishReply(await(oneFrames, oneBodies, wire.BENCOKeyDirPublishReply))
	if err != nil {
		t.Fatalf("decode device one publish reply: %v", err)
	}
	if pub.Accepted != 1 {
		t.Fatalf("device one publish: accepted=%d, want 1", pub.Accepted)
	}
	_ = one.Close()
	t.Log("device one published its key and signed off")

	// Device two: a different session on the same account, querying its own
	// screen name. It deliberately does NOT publish first — publication is a full
	// replace, so publishing before reading would destroy exactly what we are
	// checking for, which is also why the app reads before it writes.
	two, twoFrames, twoBodies := signOn("device two")
	defer two.Close()

	if _, err := two.QueryDeviceKeys(sn); err != nil {
		t.Fatalf("device two self query: %v", err)
	}
	got, err := DecodeKeyDirQueryReply(await(twoFrames, twoBodies, wire.BENCOKeyDirQueryReply))
	if err != nil {
		t.Fatalf("decode device two self query: %v", err)
	}

	var found *wire.BENCODevice
	for i := range got.Devices {
		if bytes.Equal(got.Devices[i].BoxKey, deviceKey(0x11)) {
			found = &got.Devices[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("device two saw %d device(s) but not the one device one published: "+
			"the directory is instance-scoped, not account-scoped, and multi-device "+
			"cannot work on top of it", len(got.Devices))
	}
	if !bytes.Equal(found.SignKey, deviceKey(0xB1)) {
		t.Errorf("signing key did not survive: got %x", found.SignKey)
	}
	t.Logf("device two read back device one's key — the directory is account-scoped")

	// Leave the account as we found it.
	if _, err := two.RevokeDeviceKey(deviceKey(0x11)); err != nil {
		t.Logf("cleanup: revoke failed: %v", err)
		return
	}
	await(twoFrames, twoBodies, wire.BENCOKeyDirRevokeReply)
	if _, err := two.RestoreDeviceKey(deviceKey(0x11)); err == nil {
		await(twoFrames, twoBodies, wire.BENCOKeyDirRestoreReply)
	}
	t.Log("cleanup: test key revoked and its tombstone lifted")
}

// TestLiveICBMSizeCeiling measures how large a message body this server will
// actually carry.
//
// This gates whether post-quantum hybrid key wrapping can ride in the ordinary
// IM body. ML-KEM-768 adds ~1088 bytes of ciphertext per recipient device, so a
// five-device account needs roughly 8 KB after base64 — trivial by any modern
// standard, but the limit here is a policy number inherited from the 1990s, not
// a bandwidth constraint. FLAP itself allows 65529 bytes (wire.FLAPMaxPayload),
// and MaxIncomingICBMLen is a uint16, so the protocol has ample headroom; the
// question is entirely what BENCoscar enforces.
//
// Reports two numbers: what the server advertises, and what it demonstrably
// accepts. They are not required to agree, and the second one is the real one.
//
//	BENCCHAT_LIVE_SERVER=host:port BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/oscar/ -run TestLiveICBMSizeCeiling -v
func TestLiveICBMSizeCeiling(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME and BENCCHAT_LIVE_PASSWORD")
	}
	ctx := context.Background()

	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	s, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer s.Close()

	params := make(chan wire.SNAC_0x04_0x05_ICBMParameterReply, 1)
	echoes := make(chan string, 8)
	icbmErrs := make(chan uint16, 8)

	s.Handler = func(f wire.SNACFrame, b []byte) {
		if f.FoodGroup != wire.ICBM {
			return
		}
		switch f.SubGroup {
		case wire.ICBMParameterReply:
			var p wire.SNAC_0x04_0x05_ICBMParameterReply
			if err := wire.UnmarshalBE(&p, bytes.NewReader(b)); err == nil {
				select {
				case params <- p:
				default:
				}
			}
		case wire.ICBMChannelMsgToClient:
			if msg, ok, derr := DecodeIncomingMessage(b); ok && derr == nil {
				select {
				case echoes <- msg.Text:
				default:
				}
			}
		case wire.ICBMErr:
			// The error SNAC body is a bare uint16 code; there is no struct for
			// it because the client never decodes one.
			if len(b) >= 2 {
				select {
				case icbmErrs <- binary.BigEndian.Uint16(b[:2]):
				default:
				}
			}
		}
	}
	go func() { _ = s.Run(ctx) }()

	// What the server claims.
	if err := s.Send(wire.ICBM, wire.ICBMParameterQuery, nil); err != nil {
		t.Fatalf("ICBMParameterQuery: %v", err)
	}
	var advertised int
	select {
	case p := <-params:
		advertised = int(p.MaxIncomingICBMLen)
		t.Logf("server advertises MaxIncomingICBMLen=%d, MaxSlots=%d, MinInterICBMInterval=%d",
			p.MaxIncomingICBMLen, p.MaxSlots, p.MinInterICBMInterval)
	case <-time.After(10 * time.Second):
		t.Log("server did not answer ICBMParameterQuery; relying on the empirical probe alone")
	}

	// What the server does. A self-addressed message is relayed back to this
	// same session, so delivery can be confirmed without a second account.
	probe := func(n int) bool {
		t.Helper()
		for {
			select {
			case <-echoes:
			case <-icbmErrs:
			default:
				goto drained
			}
		}
	drained:
		body := strings.Repeat("A", n)
		if _, err := s.SendMessage(sn, body, false); err != nil {
			t.Logf("  %6d bytes: send failed locally: %v", n, err)
			return false
		}
		select {
		case got := <-echoes:
			ok := len(got) == n
			if !ok {
				t.Logf("  %6d bytes: echoed back TRUNCATED at %d", n, len(got))
			}
			return ok
		case code := <-icbmErrs:
			t.Logf("  %6d bytes: server returned ICBM error 0x%04x", n, code)
			return false
		case <-time.After(15 * time.Second):
			t.Logf("  %6d bytes: no echo within 15s (treating as refused)", n)
			return false
		}
	}

	// Binary search between a size known to work and one that does not. Kept to
	// a handful of probes: both stunnel and the server rate-limit, and a long
	// sweep would measure throttling rather than the ceiling.
	lo := 1024
	if !probe(lo) {
		t.Fatalf("a %d-byte message did not survive; something other than size is wrong", lo)
	}
	hi := 65000
	if probe(hi) {
		t.Logf("RESULT: %d bytes accepted — at or above the practical FLAP ceiling", hi)
		t.Logf("post-quantum hybrid wrapping (~8 KB for five devices) fits with room to spare")
		return
	}
	for hi-lo > 512 {
		mid := lo + (hi-lo)/2
		if probe(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}

	t.Logf("RESULT: largest message that survived intact: %d bytes (refused at %d)", lo, hi)
	if advertised > 0 && (lo < advertised-1024 || lo > advertised+1024) {
		t.Logf("NOTE: that disagrees with the advertised %d — the advertised value is not the binding constraint",
			advertised)
	}
	switch {
	case lo >= 8192:
		t.Logf("post-quantum hybrid wrapping (~8 KB for five devices) fits as-is")
	case lo >= 2048:
		t.Logf("hybrid wrapping does NOT fit at five devices; raising the server limit "+
			"or moving the envelope off the IM body would be required (have %d, need ~8192)", lo)
	default:
		t.Logf("only %d bytes — even modest multi-device envelopes are tight", lo)
	}
}
