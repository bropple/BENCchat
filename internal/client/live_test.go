package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// Live tests talk to a real OSCAR server and are opt-in:
//
//	BENCCHAT_LIVE_SERVER=oscar.example.com:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLive -v
func liveCreds(t *testing.T) (addr, sn, pw string) {
	t.Helper()
	addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	sn = os.Getenv("BENCCHAT_LIVE_SCREENNAME")
	pw = os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_SERVER/SCREENNAME/PASSWORD to run live tests")
	}
	return addr, sn, pw
}

// liveTransport mirrors the helper in internal/oscar so these tests can reach a
// TLS-only deployment. Without it every test here dialed plaintext, which
// against a stunnel port connects and then hangs waiting for a FLAP hello that
// never arrives — an i/o timeout that looks nothing like "wrong transport".
//
//	BENCCHAT_LIVE_TLS=1          verify the certificate normally
//	BENCCHAT_LIVE_TLS=insecure   skip verification, for a self-signed dev server
//
// Two rate limiters sit in front of a live run: stunnel's (30/min per IP, burst
// 40) and the server's own sign-on limiter. The whole suite does not fit in one
// window. The server's limiter says so plainly; stunnel's does not — it drops
// the connection, which surfaces as an i/o timeout during the FLAP hello and
// looks exactly like a framing bug. Run in batches before concluding otherwise.
func liveTransport(t *testing.T) []oscar.Transport {
	t.Helper()
	switch os.Getenv("BENCCHAT_LIVE_TLS") {
	case "1", "true", "yes":
		return []oscar.Transport{{TLS: true}}
	case "insecure":
		return []oscar.Transport{{TLS: true, InsecureSkipVerify: true}}
	default:
		return nil
	}
}

// publishSelfDevices puts this driver's keys in the directory, as a signed v2
// manifest, and installs the verifier without which the same client would learn
// nothing back.
//
// Both halves are needed and it is easy to notice only the first: with no
// verifier installed, every inbound manifest is dropped and RefreshPeerKeys
// quietly learns nothing, so a driver would sit in a polling loop that can never
// succeed and report it as the peer not being ready.
//
// # Where the identity key comes from
//
// Publishing requires the account's identity key, and under transient custody
// (proposal §5) that means the recovery key, every time — there is no cached
// copy for a test to reuse and inventing one would be inventing the property the
// design exists to provide. So:
//
//	BENCCHAT_LIVE_RECOVERY_KEY set     use the account's real identity
//	no backup on the server            bootstrap one, and log the recovery key
//	backup present, no key supplied    skip
//
// The last case skips rather than generating a fresh identity, because doing
// that would REPLACE the account's identity: every contact would see the safety
// number change and every other device would be cut off. A test driver must not
// be able to do that as a side effect of running.
func publishSelfDevices(t *testing.T, c *Client, devices ...e2ee.Device) {
	t.Helper()
	installLiveVerifier(t, c)

	if !c.SupportsKeyDir() {
		t.Skip("this server has no key directory, so device keys cannot be published")
	}
	backup, ok := c.GetIdentityBackup()
	if !ok {
		t.Fatal("could not reach the key directory to look for an identity backup")
	}

	var kp e2ee.IdentityKey
	switch {
	case os.Getenv("BENCCHAT_LIVE_RECOVERY_KEY") != "":
		if !backup.Present {
			t.Fatal("BENCCHAT_LIVE_RECOVERY_KEY is set but this account has no identity backup")
		}
		rk, err := e2ee.ParseRecoveryKey(os.Getenv("BENCCHAT_LIVE_RECOVERY_KEY"))
		if err != nil {
			t.Fatalf("BENCCHAT_LIVE_RECOVERY_KEY: %v", err)
		}
		params, err := e2ee.DecodeBackupParams(backup.Params)
		if err != nil {
			t.Fatalf("decode backup params: %v", err)
		}
		kp, err = e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
			Params: params, Salt: backup.Salt, Blob: backup.Blob,
		}, rk)
		if err != nil {
			t.Fatalf("open identity backup: %v", err)
		}

	case !backup.Present:
		// A fresh test account: bootstrap it properly, in §12's order — the
		// recovery key is generated and reported before anything is uploaded.
		rk, err := e2ee.GenerateRecoveryKey()
		if err != nil {
			t.Fatalf("GenerateRecoveryKey: %v", err)
		}
		kp, err = e2ee.GenerateIdentityKey()
		if err != nil {
			t.Fatalf("GenerateIdentityKey: %v", err)
		}
		t.Logf("bootstrapped an identity for this account. RECOVERY KEY: %s", rk)
		sealed, err := e2ee.SealIdentityBackup(kp, rk)
		if err != nil {
			t.Fatalf("SealIdentityBackup: %v", err)
		}
		stored, ok := c.PutIdentityBackup(wire.BENCOKDFArgon2id,
			sealed.Params.Encode(), sealed.Salt, sealed.Blob)
		if !ok || !stored {
			t.Fatalf("PutIdentityBackup: stored=%v ok=%v", stored, ok)
		}

	default:
		t.Skip("this account has an identity backup; set BENCCHAT_LIVE_RECOVERY_KEY to " +
			"publish under it (generating a new identity would cut off every other device)")
	}
	defer kp.Zero()

	// The counter has to beat what the server holds, so read it rather than
	// assuming. A refusal carries the value to beat, which is the retry below.
	counter := liveManifestCounter(t, c) + 1
	for attempt := 0; attempt < 2; attempt++ {
		manifest := liveBuildManifest(t, c, kp.Public, counter, devices)
		sig, err := e2ee.SignManifest(kp, manifest)
		if err != nil {
			t.Fatalf("SignManifest: %v", err)
		}
		outcome, serverCounter, ok := c.PublishManifest(manifest, wire.BENCOAlgEd25519, sig)
		if !ok {
			t.Fatal("the key directory did not answer a publish")
		}
		if outcome == PublishIdentityPinned {
			t.Fatal("this account is bound to a different identity key; the test account's " +
				"key directory needs clearing (DELETE /user/{screenname}/keydir) before it can publish")
		}
		if outcome == PublishStored {
			t.Logf("published %d device(s) at counter %d", len(devices), counter)
			return
		}
		counter = serverCounter + 1
	}
	t.Fatal("the key directory refused our manifest twice")
}

// liveManifestCounter reads the counter the server currently holds for us, or 0.
func liveManifestCounter(t *testing.T, c *Client) uint64 {
	t.Helper()
	sm, ok := c.QueryManifest(c.store.Self().ScreenName)
	if !ok {
		t.Fatal("could not read our own manifest from the directory")
	}
	if !sm.Present {
		return 0
	}
	m, err := wire.DecodeManifest(sm.Manifest)
	if err != nil {
		t.Fatalf("decode our own manifest: %v", err)
	}
	return m.Counter
}

func liveBuildManifest(t *testing.T, c *Client, identity ed25519.PublicKey, counter uint64, devices []e2ee.Device) []byte {
	t.Helper()
	m := wire.BENCOManifest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: c.store.Self().ScreenName,
		Counter:    counter,
		IssuedAt:   uint64(time.Now().UTC().Unix()),
		Identity:   wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: identity},
	}
	for _, d := range devices {
		dev := wire.BENCODeviceV2{Box: wire.BENCOKey{Alg: wire.BENCOAlgX25519, Key: d.Box[:]}}
		if len(d.Sign) == ed25519.PublicKeySize {
			dev.Sign = wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: d.Sign}
		}
		m.Devices = append(m.Devices, dev)
	}
	b, err := wire.EncodeManifest(m)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	return b
}

// installLiveVerifier gives a driver the same trust rules the app layer applies:
// check the signature over the bytes as received, pin the identity on first
// sight, and refuse a counter at or below the highest already seen from it.
//
// The pin is in memory only, which is the one difference from the real thing —
// a driver is one session, so there is nothing for it to remember across runs.
func installLiveVerifier(t *testing.T, c *Client) {
	t.Helper()
	var mu sync.Mutex
	type pin struct {
		identity string
		counter  uint64
	}
	pins := map[string]pin{}

	c.SetManifestVerifier(func(sm SignedManifest) ([]e2ee.Device, bool) {
		if !sm.Present || sm.SigAlg != wire.BENCOAlgEd25519 {
			return nil, false
		}
		m, err := wire.DecodeManifest(sm.Manifest)
		if err != nil {
			t.Logf("verifier: undecodable manifest for %s: %v", sm.ScreenName, err)
			return nil, false
		}
		if m.Identity.Alg != wire.BENCOAlgEd25519 || len(m.Identity.Key) != wire.BENCOEd25519KeyLen {
			return nil, false
		}
		if err := e2ee.VerifyManifest(m.Identity.Key, sm.Manifest, sm.Signature); err != nil {
			t.Logf("verifier: bad signature for %s: %v", sm.ScreenName, err)
			return nil, false
		}
		if !strings.EqualFold(m.ScreenName, sm.ScreenName) || m.Counter == 0 {
			return nil, false
		}

		key := strings.ToLower(strings.ReplaceAll(sm.ScreenName, " ", ""))
		identity := e2ee.EncodeIdentityPublic(m.Identity.Key)
		mu.Lock()
		have := pins[key]
		// Strictly below, where the app layer refuses at-or-below: a driver
		// verifies the same reply more than once in a run, and without a digest
		// to recognise the repeat by, at-or-below would reject the manifest it
		// had just accepted. The app layer keeps a digest and can be stricter.
		if have.identity == identity && m.Counter < have.counter {
			mu.Unlock()
			t.Logf("verifier: refusing a stale manifest for %s (%d <= %d)",
				sm.ScreenName, m.Counter, have.counter)
			return nil, false
		}
		pins[key] = pin{identity: identity, counter: m.Counter}
		mu.Unlock()

		out := make([]e2ee.Device, 0, len(m.Devices))
		for _, d := range m.Devices {
			if d.Box.Alg != wire.BENCOAlgX25519 || len(d.Box.Key) != wire.BENCOX25519KeyLen {
				continue
			}
			var b [32]byte
			copy(b[:], d.Box.Key)
			dev := e2ee.Device{Box: b}
			if d.Sign.Alg == wire.BENCOAlgEd25519 && len(d.Sign.Key) == wire.BENCOEd25519KeyLen {
				dev.Sign = ed25519.PublicKey(d.Sign.Key)
			}
			out = append(out, dev)
		}
		return out, true
	})
}

// TestLiveChatRoom exercises the entire multi-connection chat-room path against
// the real server, solo: sign on, join/create a room (which runs the BOS →
// ChatNav → Chat cookie-redirect dance), confirm the server put us in the room's
// roster, send a message, and leave. Receiving from a *second* user is the only
// part this can't cover alone.
// liveRoster signs the roster that rides along with a live invite. The receiving
// client verifies it, so an unsigned one would leave the newcomer with no idea
// who else is in the room.
func liveRoster(t *testing.T, c *Client, room string, members ...string) string {
	t.Helper()
	body, err := c.SignRosterBody(e2ee.Roster{
		Room: room, Epoch: 1, Members: members, Owner: members[0], Author: members[0],
	})
	if err != nil {
		t.Fatalf("signing a live roster: %v", err)
	}
	return body
}

func TestLiveChatRoom(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	store := state.NewStore()
	c := New(store, nil)

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	const roomName = "bencchat-livetest"
	if err := c.JoinRoom(roomName); err != nil {
		t.Fatalf("JoinRoom(%q): %v — the multi-connection chat dance failed", roomName, err)
	}

	// The server pushes the roster right after we go online on the Chat
	// connection; give it a moment to land, then confirm we joined.
	var room state.Room
	for i := 0; i < 20; i++ {
		rooms := store.Rooms()
		if len(rooms) > 0 && len(rooms[0].Participants) > 0 {
			room = rooms[0]
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if room.Cookie == "" {
		t.Fatal("joined no room / no participants pushed — chat connection never populated")
	}
	t.Logf("joined room %q (cookie %q) with participants %v", room.Name, room.Cookie, room.Participants)

	// We should see ourselves in the roster.
	var sawSelf bool
	for _, p := range room.Participants {
		if state.NormalizeScreenName(p) == state.NormalizeScreenName(sn) {
			sawSelf = true
		}
	}
	if !sawSelf {
		t.Errorf("own screen name %q not in participants %v", sn, room.Participants)
	}

	// Send a message; the server accepting it (no error) proves the Chat
	// connection is live and our message encoding is valid.
	if err := c.SendRoomMessage(room.Cookie, "hello from the BENCchat live test"); err != nil {
		t.Fatalf("SendRoomMessage: %v", err)
	}
	t.Log("message sent to the room OK")

	// Leaving should tear the room down.
	c.LeaveRoom(room.Cookie)
	time.Sleep(300 * time.Millisecond)
	if _, ok := store.Room(room.Cookie); ok {
		t.Log("note: room still present shortly after leave (async teardown)")
	}
}

// TestLiveChatRoomListen is the second-client side of a two-party chat-room
// test. It signs bob (or whoever) in, joins the room named by
// BENCCHAT_LIVE_ROOM, sends a greeting, then logs every roster change and
// message it receives for BENCCHAT_LIVE_LISTEN_SECS seconds (default 90) before
// leaving. Run this while a human drives the GUI in the same room:
//
//	BENCCHAT_LIVE_ROOM=bencchat-livetest BENCCHAT_LIVE_LISTEN_SECS=120 \
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveChatRoomListen -v -timeout 300s
func TestLiveChatRoomListen(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	roomName := os.Getenv("BENCCHAT_LIVE_ROOM")
	if roomName == "" {
		t.Skip("set BENCCHAT_LIVE_ROOM to run the interactive listener")
	}
	secs := 90
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if n, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(n.Seconds())
		}
	}

	store := state.NewStore()
	c := New(store, nil)

	// Log everything that happens in a room.
	unsub := store.Subscribe(func(e state.Event) {
		switch e.Kind {
		case state.EventRoomMessage:
			if e.Message != nil {
				t.Logf("[recv] <%s> %s", e.Message.From, e.Message.Text)
			}
		case state.EventRoomChanged:
			if e.Room != nil {
				t.Logf("[room] %q roster: %v", e.Room.Name, e.Room.Participants)
			}
		}
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.JoinRoom(roomName); err != nil {
		t.Fatalf("JoinRoom(%q): %v", roomName, err)
	}
	rooms := store.Rooms()
	if len(rooms) == 0 {
		t.Fatal("joined no room")
	}
	cookie := rooms[0].Cookie
	t.Logf("in room %q as %q — listening %ds; type in the GUI now", roomName, sn, secs)

	_ = c.SendRoomMessage(cookie, "bob is here (live test) — say something!")
	time.Sleep(time.Duration(secs) * time.Second)
	_ = c.SendRoomMessage(cookie, "bob signing off, thanks!")
	c.LeaveRoom(cookie)
}

// TestLiveFeedbagPropagation proves a feedbag change made on one session shows
// up on ANOTHER session of the same account without reconnecting — the server
// relays it and the client now applies the relay. Two clients sign in as the
// same account; one blocks a target, the other should see it appear in its
// blocked list within a few seconds, and see it disappear on unblock.
//
//	BENCCHAT_LIVE_SERVER=aim.benco.lol:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=cmaximus BENCCHAT_LIVE_PASSWORD=... \
//	BENCCHAT_LIVE_BLOCK_TARGET=someuser \
//	go test ./internal/client/ -run TestLiveFeedbagPropagation -v -timeout 90s
func TestLiveFeedbagPropagation(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	target := os.Getenv("BENCCHAT_LIVE_BLOCK_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_BLOCK_TARGET to a screen name to block/unblock")
	}
	ctx := context.Background()

	// Two independent clients, same account = two server-side instances.
	a := New(state.NewStore(), nil)
	if err := a.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn A: %v", err)
	}
	defer func() { _ = a.SignOff() }()

	b := New(state.NewStore(), nil)
	if err := b.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn B: %v", err)
	}
	defer func() { _ = b.SignOff() }()

	blockedOnB := func() bool {
		for _, n := range b.BlockedUsers() {
			if state.NormalizeScreenName(n) == state.NormalizeScreenName(target) {
				return true
			}
		}
		return false
	}
	waitFor := func(want bool) bool {
		for i := 0; i < 20; i++ { // up to ~5s
			if blockedOnB() == want {
				return true
			}
			time.Sleep(250 * time.Millisecond)
		}
		return blockedOnB() == want
	}

	// Clean start: make sure the target isn't already blocked, and let it settle.
	_ = a.UnblockBuddy(target)
	time.Sleep(500 * time.Millisecond)

	if err := a.BlockBuddy(target); err != nil {
		t.Fatalf("A.BlockBuddy: %v", err)
	}
	if !waitFor(true) {
		t.Errorf("block made on A did not propagate to B (B blocked=%v)", b.BlockedUsers())
	} else {
		t.Logf("RESULT: block propagated A→B live")
	}

	if err := a.UnblockBuddy(target); err != nil {
		t.Fatalf("A.UnblockBuddy: %v", err)
	}
	if !waitFor(false) {
		t.Errorf("unblock made on A did not propagate to B (B blocked=%v)", b.BlockedUsers())
	} else {
		t.Logf("RESULT: unblock propagated A→B live")
	}
}

// TestLiveDMEcho brings bob online and echoes back every 1:1 message it
// receives, so a human driving the GUI can test direct messages both ways. Run:
//
//	BENCCHAT_LIVE_DM=1 BENCCHAT_LIVE_LISTEN_SECS=180 \
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveDMEcho -v -timeout 400s
func TestLiveDMEcho(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	if os.Getenv("BENCCHAT_LIVE_DM") == "" {
		t.Skip("set BENCCHAT_LIVE_DM=1 to run the interactive DM echo driver")
	}
	secs := 180
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	store := state.NewStore()
	c := New(store, nil)

	unsub := store.Subscribe(func(e state.Event) {
		if e.Kind != state.EventMessage || e.Message == nil || e.Message.Outgoing {
			return
		}
		m := *e.Message
		t.Logf("[DM recv] <%s> %s", m.From, m.Text)
		// Reply from a goroutine — the read loop delivered this event and must
		// not block on the send's rate pacing.
		go func() {
			if err := c.SendMessage(m.From, "bob got: "+m.Text); err != nil {
				t.Logf("reply to %s failed: %v", m.From, err)
			}
		}()
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	t.Logf("bob online as %q — message it from the GUI ('+ New IM' → %q); echoing for %ds", sn, sn, secs)
	time.Sleep(time.Duration(secs) * time.Second)
}

// TestLiveDirectorySearch runs an ODir name search against the real server. It
// confirms the request/reply decode works end to end; whether it returns matches
// depends on whether any accounts have directory info set.
func TestLiveDirectorySearch(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	store := state.NewStore()
	c := New(store, nil)

	var got []state.DirEntry
	var ok bool
	done := make(chan struct{}, 1)
	unsub := store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventDirectoryResult {
			got, ok = e.Directory, e.DirectoryOK
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.SearchDirectory("Test", ""); err != nil {
		t.Fatalf("SearchDirectory: %v", err)
	}
	select {
	case <-done:
		t.Logf("directory reply decoded: ok=%v, %d matches", ok, len(got))
	case <-time.After(10 * time.Second):
		t.Fatal("no directory reply within 10s — decode or routing failed")
	}
}

// TestLiveWarnDriver brings bob online, opens a 1:1 conversation with the
// human tester, echoes anything they send, and logs every warning notification
// it receives — so an anonymous vs. named warn can be told apart from the GUI
// side. Run:
//
//	BENCCHAT_LIVE_TARGET=alice BENCCHAT_LIVE_LISTEN_SECS=600 \
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveWarnDriver -v -timeout 700s
func TestLiveWarnDriver(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to DM")
	}
	secs := 600
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	store := state.NewStore()
	c := New(store, nil)

	unsub := store.Subscribe(func(e state.Event) {
		switch e.Kind {
		case state.EventMessage:
			if e.Message == nil || e.Message.Outgoing {
				return
			}
			m := *e.Message
			t.Logf("[DM recv] <%s> %s", m.From, m.Text)
			go func() {
				if err := c.SendMessage(m.From, "bob got: "+m.Text); err != nil {
					t.Logf("reply to %s failed: %v", m.From, err)
				}
			}()
		case state.EventNotice:
			// Warn notifications land here; the text names the warner or says
			// "anonymous", which is exactly what we're testing.
			t.Logf("[NOTICE %s] %s", e.NoticeLevel, e.Notice)
		case state.EventSelfChanged:
			t.Logf("[self] warning level now %d (tenths of a percent)", store.Self().WarningLevel)
		}
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	// Give the server a beat to finish pushing our roster/rights before the
	// first outbound IM, so it isn't sent into a half-ready session.
	time.Sleep(2 * time.Second)
	if err := c.SendMessage(target, "hey! bob here, reporting for duty. warn away — I'll log what comes back."); err != nil {
		t.Fatalf("opening DM to %s failed: %v", target, err)
	}
	t.Logf("bob online as %q; DMed %q. Listening %ds.", sn, target, secs)
	time.Sleep(time.Duration(secs) * time.Second)
}

// TestLiveE2EEDriver is the counterpart to the GUI for verifying end-to-end
// encryption between two real accounts. It brings the peer online WITH a
// keypair (persisted in the OS keyring, so the safety number is stable across
// runs), publishes the public key in its profile, requests the target's profile
// to learn theirs, prints the safety number both sides should agree on, and
// echoes messages while logging whether each arrived encrypted. Run:
//
//	BENCCHAT_LIVE_E2EE=1 BENCCHAT_LIVE_TARGET=alice BENCCHAT_LIVE_LISTEN_SECS=600 \
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveE2EEDriver -v -timeout 700s
func TestLiveE2EEDriver(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	if os.Getenv("BENCCHAT_LIVE_E2EE") == "" {
		t.Skip("set BENCCHAT_LIVE_E2EE=1 to run the E2EE driver")
	}
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to DM")
	}
	secs := 600
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	// Reuse the keyring-held key if this account already has one, exactly as the
	// app does — a fresh key every run would change the safety number and make
	// "did it match?" meaningless.
	var kp e2ee.KeyPair
	if priv, err := secret.RetrievePrivateKey(sn); err == nil && priv != "" {
		if pk, derr := e2ee.DecodeKey(priv); derr == nil {
			kp, err = e2ee.KeyPairFromPrivate(pk)
			if err != nil {
				t.Fatalf("loading stored key: %v", err)
			}
			t.Logf("reusing the stored E2EE key for %q", sn)
		}
	}
	if kp.Public == ([32]byte{}) {
		var err error
		if kp, err = e2ee.GenerateKeyPair(); err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if err := secret.StorePrivateKey(sn, e2ee.EncodeKey(kp.Private)); err != nil {
			t.Logf("warning: could not persist the key (%v) — the safety number will change next run", err)
		}
		t.Logf("generated a new E2EE key for %q", sn)
	}

	store := state.NewStore()
	c := New(store, nil)
	c.SetE2EEKeyPair(kp, true)
	c.SetE2EEOn(true)

	unsub := store.Subscribe(func(e state.Event) {
		if e.Kind != state.EventMessage || e.Message == nil || e.Message.Outgoing {
			return
		}
		m := *e.Message
		lock := "PLAINTEXT"
		if m.Encrypted {
			lock = "ENCRYPTED"
		}
		t.Logf("[DM recv %s] <%s> %s", lock, m.From, m.Text)
		go func() {
			if err := c.SendMessage(m.From, "bob got: "+m.Text); err != nil {
				t.Logf("reply to %s failed: %v", m.From, err)
			}
		}()
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	// Publish our key so the other side can discover it, then ask for theirs.
	if err := c.SetProfile("bob, BENCO coworker."); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	publishSelfDevices(t, c, e2ee.Device{Box: kp.Public})
	t.Logf("our public key: %s", e2ee.EncodeKey(kp.Public))
	// Re-request on a slow loop for a minute rather than polling once: the human
	// on the other end may still be turning encryption on, which is what
	// publishes their keys.
	var peer [][32]byte
	var havePeer bool
	for i := 0; i < 20; i++ {
		c.RefreshPeerKeys(target)
		for j := 0; j < 12; j++ {
			if peer, havePeer = c.PeerKeys(target); havePeer {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if havePeer {
			break
		}
	}
	if !havePeer {
		t.Logf("no E2EE key published by %q yet — is encryption enabled on that side?", target)
	} else {
		t.Logf("learned %q's key(s): %s", target, e2ee.EncodeKeys(peer))
		t.Logf("CanEncryptTo(%q) = %v", target, c.CanEncryptTo(target))
	}

	if err := c.SendMessage(target, "bob here — this message should show a lock if E2EE is working."); err != nil {
		t.Fatalf("opening DM to %s failed: %v", target, err)
	}
	t.Logf("online as %q; echoing for %ds", sn, secs)
	time.Sleep(time.Duration(secs) * time.Second)
}

// TestLiveCapabilities confirms the server accepts BENCchat's capability
// advertisement AND relays it back verbatim. Both halves matter:
// open-oscar-server validates the blob length (dropping the connection on a
// malformed one) and filters a few known UUIDs, so a local round-trip is no
// evidence a custom UUID survives the server. Run:
//
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveCapabilities -v
func TestLiveCapabilities(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	store := state.NewStore()
	c := New(store, nil)

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v — a malformed capabilities blob drops the connection here", err)
	}
	defer func() { _ = c.SignOff() }()

	// Look ourselves up: the reply carries whatever the server stored for us,
	// which is the only way to see what actually survived.
	got := make(chan []oscar.Capability, 1)
	c.setLocateCapsProbe(func(screenName string, caps []oscar.Capability) {
		if state.NormalizeScreenName(screenName) == state.NormalizeScreenName(sn) {
			select {
			case got <- caps:
			default:
			}
		}
	})
	c.RequestUserInfo(sn)

	select {
	case caps := <-got:
		t.Logf("server returned %d capabilities: %v", len(caps), caps)
		if !oscar.HasCapability(caps, oscar.CapBENCchat) {
			t.Errorf("BENCchat capability %s did not survive the server", oscar.CapBENCchat)
		}
		if !oscar.HasCapability(caps, oscar.CapSecureIM) {
			t.Errorf("SECURE_IM capability %s did not survive the server", oscar.CapSecureIM)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no locate reply within 15s — could not confirm capability relay")
	}
}

// TestLiveSelfLookupIsInstanceScoped recorded the server behaviour that used to
// decide how multi-device had to work.
//
// open-oscar-server answers a self-directed UserInfoQuery from the asking
// INSTANCE's profile, not the account's (foodgroup/locate.go: "if looking up own
// profile, return this instance's profile for consistency"). While device keys
// lived in the profile, that meant a second machine could not discover the
// first's key by looking the account up, which is why linking needed an explicit
// step.
//
// Keys now live in the server's key directory, which is account-scoped storage
// and answers a query for our own screen name (see wire/keydir.go). The
// constraint this test pinned down therefore no longer governs anything, and the
// API it probed — FetchOwnPublishedKeys — is gone.
//
// Left skipped rather than deleted because the question it replaces is still
// worth answering against a live server: does the directory show device 2 the
// key device 1 published? Rewriting it that way needs a run against the real
// deployment to confirm the expected answer, so it is not guessed at here.
func TestLiveSelfLookupIsInstanceScoped(t *testing.T) {
	t.Skip("obsolete: device keys moved from the Locate profile to the key directory; " +
		"needs rewriting as a directory self-query, verified against a live server")
}

// TestLiveSelfMessageRelay asks whether the server relays an instant message
// addressed to your OWN account to your other signed-on sessions.
//
// BENCchat no longer uses this for anything: device linking is cross-signing
// against the key directory, and the announce/share/deny message channel this
// question was asked for is gone. Kept because the server property is real,
// undocumented upstream, and cheap to re-confirm before anything else is built
// on it. Run:
//
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveSelfMessageRelay -v -timeout 120s
func TestLiveSelfMessageRelay(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	type session struct {
		c        *Client
		store    *state.Store
		received chan state.Message
	}
	signOn := func(label string) *session {
		store := state.NewStore()
		c := New(store, nil)
		s := &session{c: c, store: store, received: make(chan state.Message, 8)}
		store.Subscribe(func(e state.Event) {
			if e.Kind == state.EventMessage && e.Message != nil && !e.Message.Outgoing {
				select {
				case s.received <- *e.Message:
				default:
				}
			}
		})
		if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
			t.Fatalf("%s SignOn: %v", label, err)
		}
		return s
	}

	deviceA := signOn("device A")
	defer func() { _ = deviceA.c.SignOff() }()
	deviceB := signOn("device B")
	defer func() { _ = deviceB.c.SignOff() }()
	time.Sleep(time.Second) // let both sessions settle

	const probe = "BENCCHAT-DEVICE-LINK-PROBE"
	if err := deviceA.c.SendMessage(sn, probe); err != nil {
		t.Fatalf("sending to our own screen name was rejected outright: %v", err)
	}
	t.Log("the server accepted a self-addressed message")

	select {
	case m := <-deviceB.received:
		if m.Text == probe {
			t.Logf("SELF-LINK WORKS: device B received %q from %q", m.Text, m.From)
		} else {
			t.Logf("device B received something else: %q", m.Text)
		}
	case <-time.After(10 * time.Second):
		t.Log("SELF-LINK NOT AVAILABLE: device B never received the message — " +
			"self-addressed IMs are not relayed to other sessions, so device linking must be manual")
	}

	// Did it echo back to the sender's own session too? That would be noise a
	// real implementation has to filter.
	select {
	case m := <-deviceA.received:
		t.Logf("note: the sending device also received its own message (%q) — an "+
			"implementation must ignore its own announcements", m.Text)
	case <-time.After(2 * time.Second):
		t.Log("the sending device did not receive its own message")
	}
}

// TestLiveTLSSignOn signs on to the real server through a local TLS proxy —
// the same shape stunnel gives us, before stunnel exists on the VM.
//
// This is the test that proves the whole transport path, not just the dial:
// login, the BOS reconnect, and the fact that the session reports itself
// secure. The BOS address comes from the server and would otherwise be dialed
// in the clear. Run:
//
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveTLSSignOn -v -timeout 120s
func TestLiveTLSSignOn(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	// A throwaway certificate for the proxy.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Terminate TLS and forward to the real (plaintext) OSCAR server.
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, client) }()
				_, _ = io.Copy(client, upstream)
			}()
		}
	}()

	proxyAddr := ln.Addr().String()
	t.Logf("TLS proxy on %s forwarding to %s", proxyAddr, addr)

	store := state.NewStore()
	c := New(store, nil)
	// PinAddress because the server advertises its own hostname for the BOS
	// reconnect, which doesn't route to a proxy running on loopback.
	tr := oscar.Transport{TLS: true, InsecureSkipVerify: true, PinAddress: true}
	if err := c.SignOn(context.Background(), proxyAddr, oscar.Credentials{ScreenName: sn, Password: pw}, tr); err != nil {
		t.Fatalf("TLS sign-on failed: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if !c.Secure() {
		t.Error("signed on over TLS but the session does not report itself secure")
	}
	if store.Self().ScreenName == "" {
		t.Error("signed on but no screen name was recorded")
	}
	t.Logf("signed on as %q over TLS — login and BOS reconnect both encrypted", store.Self().ScreenName)

	// Prove the session is usable, not merely connected.
	if err := c.SetProfile("tls test"); err != nil {
		t.Errorf("a request over the TLS session failed: %v", err)
	}
}

// TestLiveTLSVerifiedSignOn signs on to the real deployment over TLS with
// certificate verification ENABLED — no proxy, no skip-verify.
//
// This is the one that proves the production path: a genuine certificate the
// client validates against the system trust store, which is the difference
// between encryption and encryption-that-means-something. Run:
//
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveTLSVerifiedSignOn -v -timeout 60s
func TestLiveTLSVerifiedSignOn(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_TLS_SERVER/SCREENNAME/PASSWORD to run the verified TLS test")
	}

	store := state.NewStore()
	c := New(store, nil)

	// Verification ON. If the certificate is self-signed, expired, or issued for
	// another name, this must fail rather than connect.
	tr := oscar.Transport{TLS: true}
	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw}, tr); err != nil {
		t.Fatalf("verified TLS sign-on failed: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if !c.Secure() {
		t.Error("connected but the session does not report itself secure")
	}
	t.Logf("signed on as %q over verified TLS", store.Self().ScreenName)

	// The BOS reconnect is the leg that would silently drop to plaintext if the
	// transport weren't carried forward; a working request proves it didn't.
	if err := c.SetProfile("tls verified"); err != nil {
		t.Errorf("request over the TLS session failed: %v", err)
	}

	// And chat, which opens yet another connection to a server-supplied address.
	if err := c.JoinRoom("bencchat-tlstest"); err != nil {
		t.Errorf("joining a room over TLS failed (chat connection did not inherit TLS?): %v", err)
	} else {
		rooms := store.Rooms()
		if len(rooms) > 0 {
			t.Logf("chat connection also came up over TLS (room %q)", rooms[0].Name)
			c.LeaveRoom(rooms[0].Cookie)
		}
	}
}

// TestLiveEncryptedRoom is the test the whole group-E2EE design hinges on.
//
// open-oscar-server does not relay chat text verbatim: it runs an HTML
// tokenizer over the message, takes the first text token, and regex-matches
// "^//roll" to implement dice commands — replacing the message outright when it
// hits. A ciphertext mangled that way would be destroyed in flight, and no
// amount of unit testing would reveal it.
//
// It uses the reflection flag so one account can see its own message as it came
// back off the server. (Two sessions of the same account cannot both sit in one
// room, so the two-client version of this needs a second real account.) Run:
//
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveEncryptedRoom -v -timeout 180s
func TestLiveEncryptedRoom(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	if addr == "" {
		addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	}
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set BENCCHAT_LIVE_TLS_SERVER (or _SERVER)/SCREENNAME/PASSWORD")
	}
	useTLS := os.Getenv("BENCCHAT_LIVE_TLS_SERVER") != ""

	store := state.NewStore()
	c := New(store, nil)
	inbound := make(chan state.Message, 16)
	store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventRoomMessage && e.Message != nil && !e.Message.Outgoing {
			select {
			case inbound <- *e.Message:
			default:
			}
		}
	})

	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw},
		oscar.Transport{TLS: useTLS}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.JoinRoom("bencchat-e2ee-test"); err != nil {
		t.Fatalf("JoinRoom: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	rooms := store.Rooms()
	if len(rooms) == 0 {
		t.Fatal("joined no room")
	}
	cookie := rooms[0].Cookie
	defer c.LeaveRoom(cookie)

	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatal(err)
	}
	c.SetRoomKey(cookie, key)

	// Chosen to poke the server's text handling: ordinary, a literal dice
	// command, and markup with a script tag.
	for _, msg := range []string{
		"ordinary encrypted room message 🔒",
		"//roll 2d6",
		`<b>markup</b> & "quotes" <script>alert(1)</script>`,
	} {
		if err := c.sendRoomMessageReflected(cookie, msg); err != nil {
			t.Fatalf("send %q: %v", msg, err)
		}
		select {
		case got := <-inbound:
			if !got.Encrypted {
				t.Errorf("reflected %q came back unencrypted — the envelope did not survive relay (got %q)", msg, got.Text)
				continue
			}
			if got.Text != msg {
				t.Errorf("round-trip mismatch:\n  sent: %q\n  got:  %q", msg, got.Text)
			} else {
				t.Logf("survived the server intact: %q", msg)
			}
		case <-time.After(15 * time.Second):
			t.Errorf("reflected message %q never came back — the server may have swallowed it", msg)
		}
	}

	// A plaintext message in the same room must still work, and must NOT be
	// mistaken for an encrypted one.
	c.ForgetRoomKeys(cookie)
	if err := c.sendRoomMessageReflected(cookie, "plain text in the same room"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-inbound:
		if got.Encrypted {
			t.Error("a plaintext room message was flagged encrypted")
		}
		t.Logf("plaintext round-trip: %q", got.Text)
	case <-time.After(15 * time.Second):
		t.Error("plaintext message never came back")
	}
}

// TestLiveRoomDriver is the bob side of a two-person encrypted-room test.
//
// It brings bob online with an E2EE keypair, waits for alice to invite it to
// an encrypted room, joins, and then reports for every room message whether it
// decrypted — which is the thing a human at the GUI cannot see from their own
// side. Run:
//
//	BENCCHAT_LIVE_ROOM_DRIVER=1 BENCCHAT_LIVE_LISTEN_SECS=900 \
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=bob BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveRoomDriver -v -timeout 1000s
func TestLiveRoomDriver(t *testing.T) {
	if os.Getenv("BENCCHAT_LIVE_ROOM_DRIVER") == "" {
		t.Skip("set BENCCHAT_LIVE_ROOM_DRIVER=1 to run the encrypted-room driver")
	}
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	useTLS := addr != ""
	if addr == "" {
		addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	}
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set server/screenname/password")
	}
	secs := 900
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewStore()
	c := New(store, nil)
	c.SetE2EEKeyPair(kp, true)
	c.SetE2EEOn(true)

	// Report every room message and whether it decrypted.
	store.Subscribe(func(e state.Event) {
		switch e.Kind {
		case state.EventRoomMessage:
			if e.Message == nil || e.Message.Outgoing {
				return
			}
			lock := "PLAINTEXT"
			if e.Message.Encrypted {
				lock = "DECRYPTED"
			}
			t.Logf("[room %s] <%s> %s", lock, e.Message.From, e.Message.Text)
		case state.EventMessage:
			if e.Message != nil && !e.Message.Outgoing {
				t.Logf("[DM] <%s> %s", e.Message.From, e.Message.Text)
			}
		}
	})

	// Accept any room invitation and join.
	c.SetRoomInviteHandler(func(from string, inv e2ee.RoomInvite) {
		t.Logf("[invite] %s shared the key for room %q", from, inv.Room)
		go func() {
			if err := c.JoinRoom(inv.Room); err != nil {
				t.Logf("joining %q failed: %v", inv.Room, err)
				return
			}
			// Find the cookie the join produced and install the key.
			for i := 0; i < 20; i++ {
				for _, r := range store.Rooms() {
					if strings.EqualFold(r.Name, inv.Room) && r.Joined {
						c.SetRoomKey(r.Cookie, inv.Key)
						t.Logf("[invite] joined %q and installed the key — messages should now decrypt", inv.Room)
						_ = c.SendRoomMessage(r.Cookie, "bob is here and can read this room 🔒")
						return
					}
				}
				time.Sleep(200 * time.Millisecond)
			}
			t.Logf("joined %q but never saw the room appear", inv.Room)
		}()
	})

	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw},
		oscar.Transport{TLS: useTLS}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.SetProfile("bob, BENCO coworker."); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	publishSelfDevices(t, c, e2ee.Device{Box: kp.Public})
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to talk to")
	}
	c.RefreshPeerKeys(target)
	time.Sleep(2 * time.Second)
	if err := c.SendMessage(target, "bob online with a fresh key — invite me to an encrypted room when ready."); err != nil {
		t.Logf("opening DM failed: %v", err)
	}

	t.Logf("online as %q, TLS=%v. Waiting %ds for a room invitation.", sn, useTLS, secs)
	time.Sleep(time.Duration(secs) * time.Second)
}

// TestLiveChatRosterCaps pins down a server behaviour the room UI depends on.
//
// A chat room's participant roster carries NO client capabilities, even though
// the server builds it from Session.TLVUserInfo() and that ought to union them
// across a user's connections. Capabilities are set on the BOS connection and
// simply do not reach the room roster.
//
// This matters because concluding "no capabilities means no encryption support"
// from that roster marks EVERY participant as unable to read — which produced a
// UI listing the same person as both able and unable to read the room. The
// reader/non-reader split is therefore sourced from BOS-side capability data
// instead. If this test starts failing because capabilities DO appear, the
// roster becomes a usable source again. Run:
//
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveChatRosterCaps -v -timeout 90s
func TestLiveChatRosterCaps(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	useTLS := addr != ""
	if addr == "" {
		addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	}
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set server/screenname/password")
	}

	store := state.NewStore()
	c := New(store, nil)

	// Intercept the raw roster SNAC before anything interprets it.
	seen := make(chan []oscar.ChatUser, 4)
	c.chatProbe = func(users []oscar.ChatUser) {
		select {
		case seen <- users:
		default:
		}
	}

	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw},
		oscar.Transport{TLS: useTLS}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	const roomName = "bencchat-capstest"
	if err := c.JoinRoom(roomName); err != nil {
		t.Fatalf("JoinRoom: %v", err)
	}
	defer func() {
		for _, r := range store.Rooms() {
			c.LeaveRoom(r.Cookie)
		}
	}()

	select {
	case users := <-seen:
		if len(users) == 0 {
			t.Fatal("roster arrived empty")
		}
		for _, u := range users {
			t.Logf("participant %q advertises %d capability/ies in the chat roster", u.ScreenName, len(u.Capabilities))
			for _, cap := range u.Capabilities {
				t.Logf("    %s", cap)
			}
			if len(u.Capabilities) > 0 {
				t.Logf("NOTE: the chat roster now carries capabilities. It could be used " +
					"directly for the room reader/non-reader split again.")
			}
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no chat roster arrived")
	}
}

// TestLiveSignedRoomMessage puts a signed room message through the real server
// and confirms the signature survives relay.
//
// The server rewrites chat text (HTML tokenizer, "//roll" interception), and a
// signature is far less forgiving of a single altered byte than the ciphertext
// is — so this is worth checking against the live server rather than assuming.
// Run:
//
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveSignedRoomMessage -v -timeout 120s
func TestLiveSignedRoomMessage(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	useTLS := addr != ""
	if addr == "" {
		addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	}
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set server/screenname/password")
	}

	store := state.NewStore()
	c := New(store, nil)
	inbound := make(chan state.Message, 8)
	store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventRoomMessage && e.Message != nil && !e.Message.Outgoing {
			select {
			case inbound <- *e.Message:
			default:
			}
		}
	})

	signer, err := e2ee.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	c.SetSigningKey(signer, true)

	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw},
		oscar.Transport{TLS: useTLS}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.JoinRoom("bencchat-signtest"); err != nil {
		t.Fatalf("JoinRoom: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	rooms := store.Rooms()
	if len(rooms) == 0 {
		t.Fatal("joined no room")
	}
	cookie := rooms[0].Cookie
	defer c.LeaveRoom(cookie)

	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatal(err)
	}
	c.SetRoomKey(cookie, key)
	// We are the sender, so verifying our own reflected message means teaching
	// the client that this signing key belongs to us.
	c.learnPeerSigningKeys(sn, []ed25519.PublicKey{signer.Public})

	const msg = "signed message through the real server 🔒"
	if err := c.sendRoomMessageReflected(cookie, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-inbound:
		if got.Text != msg {
			t.Fatalf("round-trip mismatch:\n  sent: %q\n  got:  %q", msg, got.Text)
		}
		if !got.Encrypted {
			t.Error("message came back unencrypted")
		}
		if got.Forged {
			t.Error("a genuine signature was reported as forged after relay — the server altered the payload")
		}
		if !got.SenderVerified {
			t.Error("the signature did not verify after passing through the server")
		} else {
			t.Log("signature survived the server and verified")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no reflected message arrived")
	}
}

// TestLiveRoomHost is the reverse of the earlier room driver: bob CREATES
// an encrypted room, invites the human, and hosts it.
//
// It publishes a signed device manifest naming both this device's encryption
// key and its signing key, so the invitee's client can both encrypt to it and
// verify its room messages. Run:
//
//	BENCCHAT_LIVE_ROOM_HOST=1 BENCCHAT_LIVE_TARGET=alice BENCCHAT_LIVE_LISTEN_SECS=1200 \
//	BENCCHAT_LIVE_TLS_SERVER=oscar.example.com:5191 \
//	BENCCHAT_LIVE_SCREENNAME=bob BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveRoomHost -v -timeout 1400s
func TestLiveRoomHost(t *testing.T) {
	if os.Getenv("BENCCHAT_LIVE_ROOM_HOST") == "" {
		t.Skip("set BENCCHAT_LIVE_ROOM_HOST=1 to host an encrypted room")
	}
	addr := os.Getenv("BENCCHAT_LIVE_TLS_SERVER")
	useTLS := addr != ""
	if addr == "" {
		addr = os.Getenv("BENCCHAT_LIVE_SERVER")
	}
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	if addr == "" || sn == "" || pw == "" {
		t.Skip("set server/screenname/password")
	}
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to talk to")
	}
	roomName := os.Getenv("BENCCHAT_LIVE_ROOM")
	if roomName == "" {
		roomName = "BENCO Signed Room"
	}
	secs := 1200
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	boxKP, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signKP, err := e2ee.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	store := state.NewStore()
	c := New(store, nil)
	c.SetE2EEKeyPair(boxKP, true)
	c.SetE2EEOn(true)
	c.SetSigningKey(signKP, true)

	store.Subscribe(func(e state.Event) {
		switch e.Kind {
		case state.EventRoomMessage:
			if e.Message == nil || e.Message.Outgoing {
				return
			}
			status := "PLAINTEXT"
			switch {
			case e.Message.Forged:
				status = "FORGED"
			case e.Message.Encrypted && e.Message.SenderVerified:
				status = "DECRYPTED+VERIFIED"
			case e.Message.Encrypted:
				status = "DECRYPTED (unverified)"
			}
			t.Logf("[room %s] <%s> %s", status, e.Message.From, e.Message.Text)
		case state.EventRoomChanged:
			if e.Room != nil {
				t.Logf("[room roster] %v", e.Room.Participants)
			}
		case state.EventMessage:
			if e.Message != nil && !e.Message.Outgoing {
				t.Logf("[DM] <%s> %s", e.Message.From, e.Message.Text)
			}
		}
	})

	// Serve catch-up: when the invitee rejoins, they ask what they missed, and
	// we forward the sealed originals so they can verify each one themselves.
	var hostCookie atomic.Value
	c.SetCatchupHandler(func(from string, isRequest bool, req e2ee.CatchupRequest, _ e2ee.CatchupResponse) {
		if !isRequest {
			return
		}
		ck, _ := hostCookie.Load().(string)
		if ck == "" {
			return
		}
		msgs := c.RoomHistorySince(ck, req.Since)
		t.Logf("[catch-up] %s asked what they missed in %q since %v — serving %d message(s)",
			from, req.Room, req.Since.Format(time.Kitchen), len(msgs))
		if len(msgs) == 0 {
			return
		}
		if err := c.SendCatchup(from, e2ee.CatchupResponse{Room: req.Room, Messages: msgs}); err != nil {
			t.Logf("[catch-up] could not serve %s: %v", from, err)
		}
	})

	if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw},
		oscar.Transport{TLS: useTLS}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	// Publish BOTH keys so the invitee can encrypt to us and verify our
	// signatures.
	if err := c.SetProfile("bob, BENCO coworker."); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	publishSelfDevices(t, c, e2ee.Device{Box: boxKP.Public, Sign: signKP.Public})
	t.Logf("published signing key, signer id %s", e2ee.SignerID(signKP.Public))

	// Learn the target's encryption key — the invitation travels as an
	// encrypted 1:1 message, so we cannot invite them without it.
	var haveTheirs bool
	for i := 0; i < 20 && !haveTheirs; i++ {
		c.RefreshPeerKeys(target)
		for j := 0; j < 10; j++ {
			if _, ok := c.PeerKeys(target); ok {
				haveTheirs = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if !haveTheirs {
		t.Fatalf("could not learn %q's encryption key — is E2EE on for them?", target)
	}
	t.Logf("learned %q's encryption key; can encrypt: %v", target, c.CanEncryptTo(target))

	if err := c.JoinRoom(roomName); err != nil {
		t.Fatalf("creating room %q: %v", roomName, err)
	}
	time.Sleep(1500 * time.Millisecond)
	var cookie string
	for _, r := range store.Rooms() {
		if strings.EqualFold(r.Name, roomName) && r.Joined {
			cookie = r.Cookie
		}
	}
	if cookie == "" {
		t.Fatalf("created %q but could not identify it", roomName)
	}
	defer c.LeaveRoom(cookie)

	roomKey, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatal(err)
	}
	c.SetRoomKey(cookie, roomKey)
	hostCookie.Store(cookie)
	t.Logf("created encrypted room %q (key id %s)", roomName, roomKey.ID())

	if err := c.InviteToRoom(target, roomName, c.ChainBundleFor(cookie), liveRoster(t, c, roomName, sn, target)); err != nil {
		t.Fatalf("inviting %q: %v", target, err)
	}
	t.Logf("invited %q — they should be prompted to join", target)

	_ = c.SendRoomMessage(cookie, "bob here — this room is encrypted and this message is signed. 🔒")

	// Say something periodically so there is traffic to look at, and so the
	// signature status is visible on the other side.
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	tick := 0
	invitedWhileAway := false
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Second)
		tick++
		if len(store.Rooms()) == 0 {
			continue
		}
		_ = c.SendRoomMessage(cookie, fmt.Sprintf("signed heartbeat #%d from bob", tick))

		// If the invitee has left, keep talking (so there is history to recover)
		// and re-invite them so they can come back and ask for it.
		present := false
		if room, ok := store.Room(cookie); ok {
			for _, p := range room.Participants {
				if strings.EqualFold(p, target) {
					present = true
				}
			}
		}
		switch {
		case !present && !invitedWhileAway && tick >= 3:
			if err := c.InviteToRoom(target, roomName, c.ChainBundleFor(cookie), liveRoster(t, c, roomName, sn, target)); err != nil {
				t.Logf("re-invite failed: %v", err)
			} else {
				invitedWhileAway = true
				t.Logf("re-invited %q after %d messages while they were away", target, tick)
			}
		case present:
			invitedWhileAway = false
		}
	}
}

// TestLiveDeviceWatch signs on, opens a DM, then watches the target's
// published device set and reports every change the way the app would classify
// it. This is the peer's-eye view of someone adding a machine: the safety
// number moves, and the question is whether the previously-known keys survived
// (a new device) or were replaced (a substitution). Run:
//
//	BENCCHAT_LIVE_SERVER=... BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	BENCCHAT_LIVE_TARGET=... BENCCHAT_LIVE_WATCH=1 \
//	go test ./internal/client/ -run TestLiveDeviceWatch -v -timeout 30m
func TestLiveDeviceWatch(t *testing.T) {
	addr, sn, pw := liveCreds(t)
	if os.Getenv("BENCCHAT_LIVE_WATCH") == "" {
		t.Skip("set BENCCHAT_LIVE_WATCH=1 to run the device watcher")
	}
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to watch")
	}
	secs := 900
	if v := os.Getenv("BENCCHAT_LIVE_LISTEN_SECS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			secs = int(d.Seconds())
		}
	}

	// Reuse the keyring key exactly as the app does. A fresh key each run would
	// move the safety number on its own and make the observation meaningless.
	var kp e2ee.KeyPair
	if priv, err := secret.RetrievePrivateKey(sn); err == nil && priv != "" {
		if pk, derr := e2ee.DecodeKey(priv); derr == nil {
			if kp, err = e2ee.KeyPairFromPrivate(pk); err != nil {
				t.Fatalf("loading stored key: %v", err)
			}
			t.Logf("reusing the stored E2EE key for %q", sn)
		}
	}
	if kp.Public == ([32]byte{}) {
		var err error
		if kp, err = e2ee.GenerateKeyPair(); err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if err := secret.StorePrivateKey(sn, e2ee.EncodeKey(kp.Private)); err != nil {
			t.Logf("warning: could not persist the key (%v)", err)
		}
		t.Logf("generated a new E2EE key for %q", sn)
	}

	store := state.NewStore()
	c := New(store, nil)
	c.SetE2EEKeyPair(kp, true)
	c.SetE2EEOn(true)

	unsub := store.Subscribe(func(e state.Event) {
		if e.Kind != state.EventMessage || e.Message == nil || e.Message.Outgoing {
			return
		}
		lock := "PLAINTEXT"
		if e.Message.Encrypted {
			lock = "ENCRYPTED"
		}
		t.Logf("[DM recv %s] <%s> %s", lock, e.Message.From, e.Message.Text)
	})
	defer unsub()

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	if err := c.SetProfile("cmaximus, BENCO coworker."); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	publishSelfDevices(t, c, e2ee.Device{Box: kp.Public})

	// Learn the target's keys BEFORE the opening DM. SendMessage falls back to
	// plaintext for a peer whose keys we don't hold yet, so sending first sends
	// the first message in the clear — which is exactly what happened the first
	// time this driver ran.
	for i := 0; i < 20; i++ {
		c.RefreshPeerKeys(target)
		if keys, ok := c.PeerKeys(target); ok && len(keys) > 0 {
			t.Logf("learned %d key(s) for %q before sending", len(keys), target)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !c.CanEncryptTo(target) {
		t.Logf("WARNING: still cannot encrypt to %q — the opening DM will be plaintext", target)
	}

	if err := c.SendMessage(target,
		"cmaximus here. Watching your device list — add a device whenever you're ready."); err != nil {
		t.Fatalf("opening DM to %s failed: %v", target, err)
	}
	t.Logf("online as %q, watching %q for %ds", sn, target, secs)

	// Poll the directory: a re-query is the only way to observe the target
	// adding or removing a device while we watch.
	var last [][32]byte
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		c.RefreshPeerKeys(target)
		time.Sleep(3 * time.Second)

		keys, ok := c.PeerKeys(target)
		if !ok || len(keys) == 0 {
			continue
		}
		if e2ee.EncodeKeys(keys) == e2ee.EncodeKeys(last) {
			continue
		}

		if last == nil {
			t.Logf("BASELINE: %q publishes %d device key(s)", target, len(keys))
		} else {
			// The same classification VerificationInfo applies: every old key
			// still present means an addition, anything missing is a swap.
			verdict := "changed (a key we relied on is GONE — substitution)"
			if e2ee.KeysOnlyAdded(last, keys) {
				verdict = "device-added (all previously-known keys still present)"
			}
			t.Logf("CHANGE: %d -> %d device key(s); classified as %s",
				len(last), len(keys), verdict)
		}
		t.Logf("  keys: %s", e2ee.EncodeKeys(keys))
		last = keys
	}
	t.Logf("watch window ended")
}

// TestLiveCrossSigning is the end-to-end proof that key directory v2 works
// against a real BENCoscar: bootstrap an identity, publish a manifest signed by
// it, read it back, and verify the signature over the bytes AS RETURNED.
//
// Everything else that exercises publishSelfDevices is an interactive driver
// needing a human on the other end, so before this there was no automated check
// that the whole chain -- identity, signing, wire encoding, server storage,
// retrieval, verification -- survives contact with the server.
//
// The signature check is the point. A server that re-encoded the manifest rather
// than storing the bytes it was given would return something that decodes
// perfectly and verifies as forged, and nothing short of this would notice.
//
//	BENCCHAT_LIVE_SERVER=host:port BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
//	[BENCCHAT_LIVE_RECOVERY_KEY=...] \
//	go test ./internal/client/ -run TestLiveCrossSigning -v
func TestLiveCrossSigning(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	c, _ := newTestClient(t)
	if err := c.SignOn(context.Background(), addr,
		oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// Bootstraps an identity if the account has none, or opens the existing
	// backup with BENCCHAT_LIVE_RECOVERY_KEY. Either way it publishes a signed
	// manifest naming this device.
	publishSelfDevices(t, c, e2ee.Device{Box: kp.Public})

	// Read it back the way a peer would.
	sm, ok := c.QueryManifest(sn)
	if !ok {
		t.Fatal("could not query our own manifest back")
	}
	if !sm.Present {
		t.Fatal("the server reports no manifest immediately after we published one")
	}
	if len(sm.Manifest) == 0 || len(sm.Signature) == 0 {
		t.Fatalf("manifest=%d bytes signature=%d bytes, want both non-empty",
			len(sm.Manifest), len(sm.Signature))
	}

	// Decode ONLY to reach the identity key the manifest vouches for. The
	// signature must then be checked over sm.Manifest exactly as received --
	// never over a re-encoding of the decoded struct.
	m, err := wire.DecodeManifest(sm.Manifest)
	if err != nil {
		t.Fatalf("decode the manifest the server returned: %v", err)
	}
	if m.Identity.Alg != wire.BENCOAlgEd25519 {
		t.Fatalf("identity alg = %d, want Ed25519", m.Identity.Alg)
	}
	if err := e2ee.VerifyManifest(m.Identity.Key, sm.Manifest, sm.Signature); err != nil {
		t.Fatalf("the manifest the SERVER returned does not verify: %v\n"+
			"This is what a server re-encoding the bytes it stored would look like.", err)
	}

	if !strings.EqualFold(m.ScreenName, sn) {
		t.Errorf("manifest is signed for %q, want %q", m.ScreenName, sn)
	}
	if m.Counter == 0 {
		t.Error("counter is 0, which is reserved so that 'no manifest' stays distinguishable")
	}

	var found bool
	for _, d := range m.Devices {
		if bytes.Equal(d.Box.Key, kp.Public[:]) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the manifest names %d device(s), none of them the one we just published",
			len(m.Devices))
	}

	t.Logf("verified: counter=%d, %d device(s), signed by identity %s",
		m.Counter, len(m.Devices), e2ee.EncodeIdentityPublic(m.Identity.Key)[:16]+"...")

	// Tampering must be caught. One byte, in the body rather than the header.
	bad := append([]byte(nil), sm.Manifest...)
	bad[len(bad)-1] ^= 0x01
	if err := e2ee.VerifyManifest(m.Identity.Key, bad, sm.Signature); err == nil {
		t.Error("a manifest with a flipped byte still verified")
	}
}

func liveCredsObj(sn, pw string) oscar.Credentials {
	return oscar.Credentials{ScreenName: sn, Password: pw}
}
