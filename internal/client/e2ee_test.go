package client

import (
	"bytes"
	"strings"
	"testing"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// newE2EEClient builds a server-less Client with a fresh E2EE keypair and
// outbound encryption on, standing in for one side of a conversation. It
// returns the client and its public key.
func newE2EEClient(t *testing.T) (*Client, [32]byte) {
	t.Helper()
	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	c, _ := newTestClient(t)
	c.SetE2EEKeyPair(kp, true)
	c.SetE2EEOn(true)
	return c, kp.Public
}

// TestClientEncryptDecryptRoundTrip walks the two-party flow: alice seals a
// message for bob using the parameters sealFor hands back, and bob's
// decodeIncoming recovers the plaintext and flags it encrypted.
func TestClientEncryptDecryptRoundTrip(t *testing.T) {
	alice, alicePub := newE2EEClient(t)
	bob, bobPub := newE2EEClient(t)

	alice.learnPeerKeys("bob", [][32]byte{bobPub})
	bob.learnPeerKeys("alice", [][32]byte{alicePub})

	peerPub, ourPriv, ok := alice.sealFor("bob")
	if !ok {
		t.Fatal("sealFor(bob) said plaintext, want encrypt")
	}
	env, err := e2ee.SealFor("hi bob 🔒", peerPub, ourPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !e2ee.IsEnvelope(env) {
		t.Fatal("sealed output is not recognized as an envelope")
	}

	text, encrypted, _ := bob.decodeIncoming("alice", env)
	if !encrypted {
		t.Error("decodeIncoming did not flag the message encrypted")
	}
	if text != "hi bob 🔒" {
		t.Errorf("decrypted text = %q, want %q", text, "hi bob 🔒")
	}
}

// TestClientPlaintextFallback: with the peer's key unknown, sealFor declines and
// a plaintext body decodes unchanged.
func TestClientPlaintextFallback(t *testing.T) {
	alice, _ := newE2EEClient(t)

	if _, _, ok := alice.sealFor("stranger"); ok {
		t.Error("sealFor(stranger) said encrypt, want plaintext (no key known)")
	}
	text, encrypted, _ := alice.decodeIncoming("stranger", "plain hello")
	if encrypted {
		t.Error("plaintext body was flagged encrypted")
	}
	if text != "plain hello" {
		t.Errorf("text = %q, want %q", text, "plain hello")
	}
}

// TestClientEncryptOffSendsPlaintext: with E2EE toggled off, sealFor declines
// even when the peer's key is known.
func TestClientEncryptOffSendsPlaintext(t *testing.T) {
	alice, _ := newE2EEClient(t)
	_, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})
	alice.SetE2EEOn(false)

	if _, _, ok := alice.sealFor("bob"); ok {
		t.Error("sealFor said encrypt with E2EE off, want plaintext")
	}
	if alice.CanEncryptTo("bob") {
		t.Error("CanEncryptTo true with E2EE off")
	}
}

// TestClientUnknownSenderKeyPlaceholder: an encrypted envelope from a sender
// whose key we don't hold yields the placeholder, not the ciphertext, and is
// not flagged as successfully decrypted.
func TestClientUnknownSenderKeyPlaceholder(t *testing.T) {
	bob, _ := newE2EEClient(t)
	sender, senderPub := newE2EEClient(t)
	sender.learnPeerKeys("bob", [][32]byte{mustPub(t, bob)})
	// bob does NOT learn sender's key.

	peerPub, ourPriv, ok := sender.sealFor("bob")
	if !ok {
		t.Fatal("sender.sealFor(bob) declined")
	}
	_ = senderPub
	env, err := e2ee.SealFor("secret", peerPub, ourPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	text, encrypted, _ := bob.decodeIncoming("sender", env)
	if encrypted {
		t.Error("placeholder path should not report encrypted=true")
	}
	if text == "secret" {
		t.Error("plaintext leaked without the sender's key")
	}
}

// mustPub returns a client's public key by round-tripping through a learned
// keypair; it exists so tests can wire keys without exporting internals.
func mustPub(t *testing.T, c *Client) [32]byte {
	t.Helper()
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.e2eeKP.Public
}

// TestLateKeyRecoversMessage covers the ordering that actually happens on a
// live server: a peer's encrypted message can arrive before their profile
// (and so their key) has been fetched. The message must be held as ciphertext
// and recovered once the key lands — not stranded behind a placeholder, which
// loses it permanently.
func TestLateKeyRecoversMessage(t *testing.T) {
	alice, alicePub := newE2EEClient(t)
	bob, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})

	peerPub, ourPriv, ok := alice.sealFor("bob")
	if !ok {
		t.Fatal("sealFor(bob) said plaintext, want encrypt")
	}
	env, err := e2ee.SealFor("secret before the key", peerPub, ourPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Bob does not know alice's key yet.
	text, encrypted, cipher := bob.decodeIncoming("alice", env)
	if encrypted {
		t.Error("message decrypted without the sender's key")
	}
	if cipher != env {
		t.Fatal("ciphertext was discarded — the message can never be recovered")
	}
	if text == "secret before the key" {
		t.Error("plaintext leaked into the placeholder")
	}
	bob.store.AddMessage(state.Message{
		From: "alice", To: "bob", Text: text, Encrypted: encrypted, Cipher: cipher,
	})

	// Alice's profile arrives; learning her key must recover the message.
	bob.learnPeerKeys("alice", [][32]byte{alicePub})

	convo, found := bob.store.Conversation("alice")
	if !found || len(convo.Messages) != 1 {
		t.Fatalf("conversation with alice = %+v, found=%v", convo, found)
	}
	got := convo.Messages[0]
	if got.Text != "secret before the key" {
		t.Errorf("after learning the key, text = %q, want the decrypted message", got.Text)
	}
	if !got.Encrypted {
		t.Error("recovered message is not flagged encrypted")
	}
	if got.Cipher != "" {
		t.Error("ciphertext retained after a successful decrypt")
	}
}

// locateReplyBody builds a LocateUserInfoReply carrying a profile.
func locateReplyBody(t *testing.T, screenName, profile string) []byte {
	t.Helper()
	reply := wire.SNAC_0x02_0x06_LocateUserInfoReply{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: screenName},
	}
	reply.LocateInfo.Append(wire.NewTLVBE(wire.LocateTLVSigMime, []byte(wire.ProfileMIME)))
	reply.LocateInfo.Append(wire.NewTLVBE(wire.LocateTLVSigData, []byte(profile)))
	var buf bytes.Buffer
	if err := wire.MarshalBE(reply, &buf); err != nil {
		t.Fatalf("marshal locate reply: %v", err)
	}
	return buf.Bytes()
}

// TestSelfProfileIsNotTreatedAsAPeer is the guard on multi-device detection.
//
// Fetching our own profile to see what key this account advertises means a
// locate reply arrives bearing OUR screen name. If that were handled like any
// peer's it would file a trust entry against our own account and — once a
// second device published a different key — warn us that our own key had
// changed, which is both alarming and meaningless.
func TestSelfProfileIsNotTreatedAsAPeer(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")

	var warned []string
	c.SetPeerKeyHandler(func(screenName string, _, _ [][32]byte) {
		warned = append(warned, screenName)
	})

	other, err := e2ee.GenerateKeyPair() // as if another device published
	if err != nil {
		t.Fatal(err)
	}
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
		locateReplyBody(t, "alice", "hi\n"+e2ee.ProfileMarker(other.Public)),
	)

	if len(warned) != 0 {
		t.Errorf("our own profile was handled as a peer key change for %v", warned)
	}
	if _, ok := c.PeerKeys("alice"); ok {
		t.Error("our own account was cached as a peer key")
	}
}

// TestSelfProfileReachesTheDeviceCheck: the same reply must still be delivered
// to a waiting FetchOwnPublishedKey, or multi-device detection sees nothing.
func TestSelfProfileReachesTheDeviceCheck(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")

	other, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan ownKeyReply, 1)
	c.e2eeMu.Lock()
	c.ownKeyWait = got
	c.e2eeMu.Unlock()

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
		locateReplyBody(t, "alice", "hi\n"+e2ee.ProfileMarker(other.Public)),
	)

	select {
	case r := <-got:
		if !r.has || len(r.keys) != 1 || r.keys[0] != other.Public {
			t.Errorf("delivered keys = %v (has=%v), want the other device's key", r.keys, r.has)
		}
	default:
		t.Fatal("the self reply never reached the device check")
	}
}

// TestPeerProfileStillLearnsKey guards the other direction: the self-routing
// must not swallow ordinary peers.
func TestPeerProfileStillLearnsKey(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.ReplaceBuddyList([]state.Buddy{{ScreenName: "bob", Key: "bob", Group: "BENCO"}}, []string{"BENCO"})

	peer, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
		locateReplyBody(t, "bob", "hello\n"+e2ee.ProfileMarker(peer.Public)),
	)

	gotKeys, ok := c.PeerKeys("bob")
	if !ok || len(gotKeys) != 1 || gotKeys[0] != peer.Public {
		t.Fatal("a peer's published key was not learned")
	}
	if b, _ := store.Buddy("bob"); strings.Contains(b.Profile, "BENCO-E2EE") {
		t.Error("the key marker leaked into the displayed profile text")
	}
}

// TestMultiDevicePeerGetsEveryDeviceEncrypted: when a peer publishes several
// device keys, a single send must be readable on all of them. This is the
// behaviour that makes a second machine usable rather than a source of
// undecryptable messages.
func TestMultiDevicePeerGetsEveryDeviceEncrypted(t *testing.T) {
	sender, senderPub := newE2EEClient(t)

	// Bob on two machines: two independent keypairs, one account.
	bobLaptop, laptopPub := newE2EEClient(t)
	bobPhone, phonePub := newE2EEClient(t)
	sender.learnPeerKeys("bob", [][32]byte{laptopPub, phonePub})

	peerKeys, ourPriv, ok := sender.sealFor("bob")
	if !ok {
		t.Fatal("sealFor declined for a multi-device peer")
	}
	if len(peerKeys) != 2 {
		t.Fatalf("sealFor returned %d recipient keys, want 2", len(peerKeys))
	}
	env, err := e2ee.SealFor("readable on both", peerKeys, ourPriv)
	if err != nil {
		t.Fatal(err)
	}

	for name, dev := range map[string]*Client{"laptop": bobLaptop, "phone": bobPhone} {
		dev.learnPeerKeys("sender", [][32]byte{senderPub})
		text, encrypted, _ := dev.decodeIncoming("sender", env)
		if !encrypted {
			t.Errorf("%s failed to decrypt a message addressed to it", name)
		}
		if text != "readable on both" {
			t.Errorf("%s decrypted %q, want the original", name, text)
		}
	}
}

// TestMultiDeviceSenderIsIdentified: NaCl box authenticates against a specific
// sender key, so a peer sending from any of THEIR machines must still decrypt —
// the receiver has to try each candidate sender key.
func TestMultiDeviceSenderIsIdentified(t *testing.T) {
	recipient, recipPub := newE2EEClient(t)
	senderA, senderAPub := newE2EEClient(t)
	senderB, senderBPub := newE2EEClient(t)

	// The recipient knows the sender's account has two machines.
	recipient.learnPeerKeys("sender", [][32]byte{senderAPub, senderBPub})

	for name, s := range map[string]*Client{"machine A": senderA, "machine B": senderB} {
		s.learnPeerKeys("recipient", [][32]byte{recipPub})
		keys, priv, ok := s.sealFor("recipient")
		if !ok {
			t.Fatalf("%s could not seal", name)
		}
		env, err := e2ee.SealFor("from "+name, keys, priv)
		if err != nil {
			t.Fatal(err)
		}
		text, encrypted, _ := recipient.decodeIncoming("sender", env)
		if !encrypted || text != "from "+name {
			t.Errorf("message from %s decoded as %q (encrypted=%v)", name, text, encrypted)
		}
	}
}

// TestMultiDeviceProfileMergePreservesOthers: parsing a peer's v2 marker must
// yield every device, not just the first — the regression that would silently
// reduce multi-device back to single-device.
func TestMultiDeviceProfileMergePreservesOthers(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.ReplaceBuddyList([]state.Buddy{{ScreenName: "bob", Key: "bob", Group: "BENCO"}}, []string{"BENCO"})

	one, _ := e2ee.GenerateKeyPair()
	two, _ := e2ee.GenerateKeyPair()
	marker := e2ee.ProfileMarkerFor([][32]byte{one.Public, two.Public})

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
		locateReplyBody(t, "bob", "bio\n"+marker),
	)

	got, ok := c.PeerKeys("bob")
	if !ok || len(got) != 2 {
		t.Fatalf("learned %d device keys for bob, want 2", len(got))
	}
	if b, _ := store.Buddy("bob"); strings.Contains(b.Profile, "BENCO-E2EE") {
		t.Error("the v2 marker leaked into the displayed profile")
	}
}
