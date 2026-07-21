package client

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

// keyDirQueryReplyBody builds a key directory query reply carrying a manifest
// that names the given device keys.
//
// The signature is a placeholder: these tests are about how a verified device
// set is routed, not about verification, so they pair this with
// useTestManifestVerifier below.
func keyDirQueryReplyBody(t *testing.T, screenName string, keys ...[32]byte) []byte {
	t.Helper()
	m := wire.BENCOManifest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: screenName,
		Counter:    1,
		IssuedAt:   1_700_000_000,
		Identity:   wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: bytes.Repeat([]byte{0x99}, 32)},
	}
	for _, k := range keys {
		key := k
		m.Devices = append(m.Devices, wire.BENCODeviceV2{
			Box:  wire.BENCOKey{Alg: wire.BENCOAlgX25519, Key: key[:]},
			Sign: wire.BENCOKey{Alg: wire.BENCOAlgEd25519},
		})
	}
	manifest, err := wire.EncodeManifest(m)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	reply := wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
		ScreenName: screenName,
		Present:    1,
		Manifest:   manifest,
		SigAlg:     wire.BENCOAlgEd25519,
		Signature:  bytes.Repeat([]byte{0xAB}, 64),
	}
	var buf bytes.Buffer
	if err := wire.MarshalBE(reply, &buf); err != nil {
		t.Fatalf("marshal key directory reply: %v", err)
	}
	return buf.Bytes()
}

// useTestManifestVerifier installs a verifier that accepts any manifest.
//
// Real verification lives in internal/e2ee; the client package only carries the
// bytes to it. Stubbing it here keeps these tests on the question they are
// actually asking — whether a manifest's devices end up filed against the right
// account — rather than dragging signing into every one of them.
func useTestManifestVerifier(t *testing.T, c *Client) {
	t.Helper()
	c.SetManifestVerifier(func(sm SignedManifest) ([]e2ee.Device, bool) {
		m, err := wire.DecodeManifest(sm.Manifest)
		if err != nil {
			t.Errorf("test verifier could not decode a manifest: %v", err)
			return nil, false
		}
		var out []e2ee.Device
		for _, d := range m.Devices {
			if len(d.Box.Key) != 32 {
				continue
			}
			var box [32]byte
			copy(box[:], d.Box.Key)
			out = append(out, e2ee.Device{Box: box})
		}
		return out, true
	})
}

// TestSelfKeysAreNotTreatedAsAPeer is the guard on multi-device detection.
//
// Asking the directory what this account publishes means a reply arrives bearing
// OUR screen name. If that were handled like any peer's it would file a trust
// entry against our own account and — once a second device published a different
// key — warn us that our own key had changed, which is both alarming and
// meaningless.
func TestSelfKeysAreNotTreatedAsAPeer(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	useTestManifestVerifier(t, c)

	var warned []string
	c.SetPeerKeyHandler(func(screenName string, _, _ [][32]byte) {
		warned = append(warned, screenName)
	})

	other, err := e2ee.GenerateKeyPair() // as if another device published
	if err != nil {
		t.Fatal(err)
	}
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.BENCOKeyDir, SubGroup: wire.BENCOKeyDirQueryReply},
		keyDirQueryReplyBody(t, "alice", other.Public),
	)

	if len(warned) != 0 {
		t.Errorf("our own device set was handled as a peer key change for %v", warned)
	}
	if _, ok := c.PeerKeys("alice"); ok {
		t.Error("our own account was cached as a peer key")
	}
}

// TestPeerKeysAreLearnedFromTheDirectory guards the other direction: the
// self-routing must not swallow ordinary peers.
func TestPeerKeysAreLearnedFromTheDirectory(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.ReplaceBuddyList([]state.Buddy{{ScreenName: "bob", Key: "bob", Group: "BENCO"}}, []string{"BENCO"})
	useTestManifestVerifier(t, c)

	peer, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.BENCOKeyDir, SubGroup: wire.BENCOKeyDirQueryReply},
		keyDirQueryReplyBody(t, "bob", peer.Public),
	)

	gotKeys, ok := c.PeerKeys("bob")
	if !ok || len(gotKeys) != 1 || gotKeys[0] != peer.Public {
		t.Fatal("a peer's published key was not learned")
	}
}

// TestLegacyProfileMarkerIsNotDisplayed: keys no longer live in profiles, but an
// account that has not signed on since the change still carries a marker in its
// bio, and it must not render as profile text.
func TestLegacyProfileMarkerIsNotDisplayed(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.ReplaceBuddyList([]state.Buddy{{ScreenName: "bob", Key: "bob", Group: "BENCO"}}, []string{"BENCO"})

	peer, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	legacy := "hello\n<!--BENCO-E2EE:v1:" + e2ee.EncodeKey(peer.Public) + "-->"
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
		locateReplyBody(t, "bob", legacy),
	)

	b, _ := store.Buddy("bob")
	if strings.Contains(b.Profile, "BENCO-E2EE") {
		t.Errorf("the key marker leaked into the displayed profile text: %q", b.Profile)
	}
	if !strings.Contains(b.Profile, "hello") {
		t.Errorf("stripping ate the profile text: %q", b.Profile)
	}
	// And a profile must never be a source of keys any more.
	if _, ok := c.PeerKeys("bob"); ok {
		t.Error("a key was learned from a profile marker")
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

// TestMultiDeviceDirectoryReplyPreservesOthers: a directory reply listing
// several devices must yield every one of them, not just the first — the
// regression that would silently reduce multi-device back to single-device.
func TestMultiDeviceDirectoryReplyPreservesOthers(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.ReplaceBuddyList([]state.Buddy{{ScreenName: "bob", Key: "bob", Group: "BENCO"}}, []string{"BENCO"})
	useTestManifestVerifier(t, c)

	one, _ := e2ee.GenerateKeyPair()
	two, _ := e2ee.GenerateKeyPair()

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.BENCOKeyDir, SubGroup: wire.BENCOKeyDirQueryReply},
		keyDirQueryReplyBody(t, "bob", one.Public, two.Public),
	)

	got, ok := c.PeerKeys("bob")
	if !ok || len(got) != 2 {
		t.Fatalf("learned %d device keys for bob, want 2", len(got))
	}
}

// TestSealOutboundNeverSendsPlaintextToAnEncryptedPeer pins the invariant behind
// the 1:1 fail-closed rule: once we hold a peer's keys, what goes on the wire is
// an envelope or nothing. It must never be the raw text, because the UI is
// showing a lock for that conversation at the same moment.
func TestSealOutboundNeverSendsPlaintextToAnEncryptedPeer(t *testing.T) {
	alice, _ := newE2EEClient(t)
	_, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})

	wire, encrypted, err := alice.sealOutbound("bob", "secret")
	if err != nil {
		t.Fatalf("sealOutbound: %v", err)
	}
	if !encrypted {
		t.Error("a peer with known keys was not marked encrypted")
	}
	if wire == "secret" {
		t.Fatal("plaintext went on the wire for a peer we hold keys for")
	}
	if !e2ee.IsEnvelopeAny(wire) {
		t.Errorf("wire body is neither plaintext nor an envelope: %q", wire)
	}
}

// A peer we hold no keys for is the ordinary non-BENCchat case: plaintext, no
// error, no lock. This is the branch the fail-closed change must NOT break.
func TestSealOutboundSendsPlaintextToAStranger(t *testing.T) {
	alice, _ := newE2EEClient(t)

	wire, encrypted, err := alice.sealOutbound("stranger", "hello")
	if err != nil {
		t.Fatalf("sealOutbound to a stranger errored: %v", err)
	}
	if encrypted {
		t.Error("a peer with no known keys was marked encrypted")
	}
	if wire != "hello" {
		t.Errorf("wire = %q, want the plaintext unchanged", wire)
	}
}

// With E2EE switched off, a peer whose keys we happen to know is still
// plaintext — the toggle wins over key possession.
func TestSealOutboundHonoursTheE2EEToggle(t *testing.T) {
	alice, _ := newE2EEClient(t)
	_, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})
	alice.SetE2EEOn(false)

	wire, encrypted, err := alice.sealOutbound("bob", "hello")
	if err != nil {
		t.Fatalf("sealOutbound with E2EE off errored: %v", err)
	}
	if encrypted || wire != "hello" {
		t.Errorf("E2EE off still encrypted: encrypted=%v wire=%q", encrypted, wire)
	}
}

// TestReplayedMessageKeepsItsOriginalTime is K8's main defence.
//
// The server chooses when to deliver, so a timestamp it controls says nothing. A
// message redelivered weeks later must render with the time its sender sealed
// into it, which is the tell — a month-old "yes, go ahead" that displays as a
// month old is not much of an attack.
func TestReplayedMessageKeepsItsOriginalTime(t *testing.T) {
	alice, alicePub := newE2EEClient(t)
	bob, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})
	bob.learnPeerKeys("alice", [][32]byte{alicePub})

	peerPub, ourPriv, _ := alice.sealFor("bob")
	env, err := e2ee.SealFor("yes, go ahead", peerPub, ourPriv)
	if err != nil {
		t.Fatalf("SealFor: %v", err)
	}

	text, encrypted, _, sentAt := bob.decodeIncomingStamped("alice", env)
	if !encrypted || text != "yes, go ahead" {
		t.Fatalf("decode = %q encrypted=%v", text, encrypted)
	}
	if sentAt.IsZero() {
		t.Fatal("no send time, so a replay would render as something said just now")
	}
	if d := time.Since(sentAt); d < 0 || d > time.Minute {
		t.Errorf("send time is %v old, want ~now", d)
	}
	// The stamp is sealed, so a server holding the envelope cannot move it.
	if e2ee.PlausibleSendTime(sentAt.Add(48*time.Hour), time.Now()) {
		t.Error("a send time far in the future was accepted")
	}
}

// TestDuplicateMessageIsDropped: the same sealed envelope arriving twice is the
// server handing us a copy it kept, not something said twice.
func TestDuplicateMessageIsDropped(t *testing.T) {
	alice, alicePub := newE2EEClient(t)
	bob, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})
	bob.learnPeerKeys("alice", [][32]byte{alicePub})

	peerPub, ourPriv, _ := alice.sealFor("bob")
	env, _ := e2ee.SealFor("transfer approved", peerPub, ourPriv)

	if text, encrypted, _, _ := bob.decodeIncomingStamped("alice", env); !encrypted || text == "" {
		t.Fatalf("first delivery was not accepted: %q encrypted=%v", text, encrypted)
	}
	text, encrypted, cipher, _ := bob.decodeIncomingStamped("alice", env)
	if text != "" || encrypted || cipher != "" {
		t.Errorf("a replayed message was accepted a second time: %q", text)
	}

	// A genuinely different message from the same sender still gets through —
	// the check is on identity, not on content.
	again, _ := e2ee.SealFor("transfer approved", peerPub, ourPriv)
	if text, encrypted, _, _ := bob.decodeIncomingStamped("alice", again); !encrypted || text != "transfer approved" {
		t.Errorf("an identical-text message was mistaken for a replay: %q", text)
	}
}
