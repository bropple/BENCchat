package client

import (
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
)

// Live tests talk to a real OSCAR server and are opt-in:
//
//	BENCCHAT_LIVE_SERVER=oscar.example.com:5190 \
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

// TestLiveChatRoom exercises the entire multi-connection chat-room path against
// the real server, solo: sign on, join/create a room (which runs the BOS →
// ChatNav → Chat cookie-redirect dance), confirm the server put us in the room's
// roster, send a message, and leave. Receiving from a *second* user is the only
// part this can't cover alone.
func TestLiveChatRoom(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	store := state.NewStore()
	c := New(store, nil)

	ctx := context.Background()
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()

	// Publish our key so the other side can discover it, then ask for theirs.
	if err := c.SetProfile("bob, BENCO coworker.\n" + e2ee.ProfileMarker(kp.Public)); err != nil {
		t.Fatalf("SetProfile (publishing our key): %v", err)
	}
	t.Logf("our public key: %s", e2ee.EncodeKey(kp.Public))
	// The peer's key arrives on the profile reply. Re-request on a slow loop for
	// a minute rather than polling once: the human on the other end may still be
	// turning encryption on, which is what republishes their profile.
	var peer [][32]byte
	var havePeer bool
	for i := 0; i < 20; i++ {
		c.RequestUserInfo(target)
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
		t.Logf("no E2EE key found in %q's profile yet — is encryption enabled on that side?", target)
	} else {
		t.Logf("learned %q's key(s): %s", target, e2ee.EncodeKeys(peer))
		t.Logf("SAFETY NUMBER (both sides must match):\n\t%s", e2ee.SafetyNumberSet([][32]byte{kp.Public}, peer))
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
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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

// TestLiveSelfLookupIsInstanceScoped pins down the server behaviour that
// decides how multi-device has to work.
//
// open-oscar-server answers a self-directed UserInfoQuery from the asking
// INSTANCE's profile, not the account's (foodgroup/locate.go: "if looking up
// own profile, return this instance's profile for consistency"). A second
// machine therefore cannot discover the first machine's published key by
// looking the account up — even with both signed on at once.
//
// That rules out automatic device-set merging and is why linking a device needs
// an explicit step. If this test ever starts failing because a second session's
// keys DO show up, the automatic merge becomes possible and this constraint can
// be revisited. Run:
//
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveSelfLookupIsInstanceScoped -v -timeout 120s
func TestLiveSelfLookupIsInstanceScoped(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	signOn := func(label string) *Client {
		store := state.NewStore()
		c := New(store, nil)
		if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
			t.Fatalf("%s SignOn: %v", label, err)
		}
		return c
	}

	laptopKey, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	laptop := signOn("device 1")
	defer func() { _ = laptop.SignOff() }()
	if err := laptop.SetProfile("device test\n" + e2ee.ProfileMarkerFor([][32]byte{laptopKey.Public})); err != nil {
		t.Fatalf("device 1 SetProfile: %v", err)
	}
	got, has, ok := laptop.FetchOwnPublishedKeys(8 * time.Second)
	if !ok || !has || len(got) != 1 {
		t.Fatalf("device 1 cannot see its own published key (ok=%v has=%v n=%d)", ok, has, len(got))
	}
	t.Log("device 1 sees its own key, as expected")

	// Second session on the same account, first still connected.
	phone := signOn("device 2")
	defer func() { _ = phone.SignOff() }()
	got, has, _ = phone.FetchOwnPublishedKeys(8 * time.Second)
	if has && len(got) > 0 {
		t.Errorf("device 2 CAN see device 1's key (%d found) — self-lookup is no longer "+
			"instance-scoped, so automatic device merging is now possible", len(got))
	} else {
		t.Log("device 2 sees nothing: self-lookup is instance-scoped, so a device " +
			"cannot discover its siblings. Linking must be explicit.")
	}

	if err := laptop.SetProfile("device test"); err != nil {
		t.Logf("cleanup SetProfile: %v", err)
	}
}

// TestLiveSelfMessageRelay asks whether the server relays an instant message
// addressed to your OWN account to your other signed-on sessions.
//
// If it does, devices can link themselves: a new machine announces its public
// key over the account's own message channel and an existing machine merges it,
// with no codes to copy by hand. If it doesn't, linking has to be manual. Run:
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
		if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
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

// TestLiveDeviceLinkHandshake runs the whole linking flow between two live
// sessions on one account: device B announces itself, device A (standing in for
// the user clicking Approve) merges and shares back the full list, and B ends up
// knowing both devices. Finally a peer-style send to the merged set is checked
// to be readable on both machines — the actual point of the exercise. Run:
//
//	BENCCHAT_LIVE_SERVER=... SCREENNAME=... PASSWORD=... \
//	go test ./internal/client/ -run TestLiveDeviceLinkHandshake -v -timeout 120s
func TestLiveDeviceLinkHandshake(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	type device struct {
		c    *Client
		key  e2ee.KeyPair
		msgs chan struct {
			kind string
			keys [][32]byte
		}
	}
	signOn := func(label string) *device {
		kp, err := e2ee.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		store := state.NewStore()
		c := New(store, nil)
		c.SetE2EEKeyPair(kp, true)
		c.SetE2EEOn(true)
		d := &device{c: c, key: kp, msgs: make(chan struct {
			kind string
			keys [][32]byte
		}, 8)}
		c.SetDeviceMessageHandler(func(kind string, keys [][32]byte) {
			select {
			case d.msgs <- struct {
				kind string
				keys [][32]byte
			}{kind, keys}:
			default:
			}
		})
		if err := c.SignOn(context.Background(), addr, oscar.Credentials{ScreenName: sn, Password: pw}); err != nil {
			t.Fatalf("%s SignOn: %v", label, err)
		}
		return d
	}

	deviceA := signOn("device A (existing)")
	defer func() { _ = deviceA.c.SignOff() }()
	deviceB := signOn("device B (new)")
	defer func() { _ = deviceB.c.SignOff() }()
	time.Sleep(time.Second)

	// B announces itself, as it would on sign-on.
	if err := deviceB.c.SendDeviceMessage(e2ee.DeviceAnnounce, [][32]byte{deviceB.key.Public}); err != nil {
		t.Fatalf("device B announce: %v", err)
	}

	// A should hear it. (It also reaches B's own session; that echo is ignored
	// by the app layer, and here we simply read A's copy.)
	var announced [][32]byte
	deadline := time.After(15 * time.Second)
	for announced == nil {
		select {
		case m := <-deviceA.msgs:
			if m.kind == e2ee.DeviceAnnounce && len(m.keys) == 1 && m.keys[0] == deviceB.key.Public {
				announced = m.keys
			}
		case <-deadline:
			t.Fatal("device A never received device B's announcement")
		}
	}
	t.Logf("device A received the announcement, fingerprint %s", e2ee.Fingerprint(announced[0]))

	// The user approves on A: A shares the full device list back.
	full := [][32]byte{deviceA.key.Public, deviceB.key.Public}
	if err := deviceA.c.SendDeviceMessage(e2ee.DeviceShare, full); err != nil {
		t.Fatalf("device A share: %v", err)
	}

	var shared [][32]byte
	deadline = time.After(15 * time.Second)
	for shared == nil {
		select {
		case m := <-deviceB.msgs:
			if m.kind == e2ee.DeviceShare && len(m.keys) == 2 {
				shared = m.keys
			}
		case <-deadline:
			t.Fatal("device B never received the shared device list")
		}
	}
	var sawA, sawB bool
	for _, k := range shared {
		sawA = sawA || k == deviceA.key.Public
		sawB = sawB || k == deviceB.key.Public
	}
	if !sawA || !sawB {
		t.Fatalf("shared list is incomplete (A=%v B=%v)", sawA, sawB)
	}
	t.Log("device B learned the full device list — linking completed with no codes typed")

	// The payoff: a message encrypted to the linked set is readable on both.
	peer, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2ee.SealFor("readable on every linked device", shared, peer.Private)
	if err != nil {
		t.Fatal(err)
	}
	for name, kp := range map[string]e2ee.KeyPair{"device A": deviceA.key, "device B": deviceB.key} {
		got, oerr := e2ee.OpenAny(env, peer.Public, kp.Private)
		if oerr != nil || got != "readable on every linked device" {
			t.Errorf("%s could not read the message: %q %v", name, got, oerr)
		}
	}
	t.Log("both linked devices decrypt the same message")
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

	if err := c.SetProfile("bob, BENCO coworker.\n" + e2ee.ProfileMarkerFor([][32]byte{kp.Public})); err != nil {
		t.Fatalf("publishing our key failed: %v", err)
	}
	target := os.Getenv("BENCCHAT_LIVE_TARGET")
	if target == "" {
		t.Skip("set BENCCHAT_LIVE_TARGET to the screen name to talk to")
	}
	c.RequestUserInfo(target)
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
// It publishes a v3 profile marker (encryption key plus signing key) so the
// invitee's client can both encrypt to it and verify its room messages. Run:
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
	marker := e2ee.ProfileMarkerForDevices([]e2ee.Device{{Box: boxKP.Public, Sign: signKP.Public}})
	if err := c.SetProfile("bob, BENCO coworker.\n" + marker); err != nil {
		t.Fatalf("publishing our keys failed: %v", err)
	}
	t.Logf("published signing key, signer id %s", e2ee.SignerID(signKP.Public))

	// Learn the target's encryption key — the invitation travels as an
	// encrypted 1:1 message, so we cannot invite them without it.
	var haveTheirs bool
	for i := 0; i < 20 && !haveTheirs; i++ {
		c.RequestUserInfo(target)
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

	if err := c.InviteToRoom(target, roomName, roomKey); err != nil {
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
			if err := c.InviteToRoom(target, roomName, roomKey); err != nil {
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
