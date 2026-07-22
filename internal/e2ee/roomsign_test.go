package e2ee

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustSigner(t *testing.T) SigningKeyPair {
	t.Helper()
	kp, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// TestSignedRoomRoundTrip: a signed message opens and verifies as its sender.
func TestSignedRoomRoundTrip(t *testing.T) {
	key := mustRoomKey(t)
	alice := mustSigner(t)

	env, err := SealRoomSigned("project-room", "the meeting is at four", key, alice)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(env, "meeting") {
		t.Fatal("plaintext leaked into the envelope")
	}

	got, err := OpenRoomSigned("project-room", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if err != nil {
		t.Fatalf("OpenRoomSigned: %v", err)
	}
	if got.Text != "the meeting is at four" {
		t.Errorf("text = %q", got.Text)
	}
	if !got.Signed || !got.Verified {
		t.Errorf("signed=%v verified=%v, want both true", got.Signed, got.Verified)
	}
	if got.SignerID != SignerID(alice.Public) {
		t.Errorf("signer ID = %q, want alice's", got.SignerID)
	}
}

// TestForgeryIsDetected is the whole point: a member holding the group key
// tries to publish a message as someone else. They can seal it — the key is
// shared — but they cannot sign as anyone but themselves.
func TestForgeryIsDetected(t *testing.T) {
	key := mustRoomKey(t)
	alice := mustSigner(t)
	mallory := mustSigner(t) // a member of the room, so she has the group key

	// Mallory seals a message and signs it with her own key, hoping it passes
	// as Alice's.
	env, err := SealRoomSigned("project-room", "transfer the money", key, mallory)
	if err != nil {
		t.Fatal(err)
	}

	// The recipient checks it against ALICE's published keys, because the chat
	// message claimed to come from Alice.
	_, err = OpenRoomSigned("project-room", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if !errors.Is(err, ErrForgedSignature) {
		t.Fatalf("forged message was accepted (err=%v) — attribution is worthless", err)
	}
}

// TestCrossRoomReplayIsDetected: a genuine message from one room must not be
// replayable into another, which is why the room name is signed.
func TestCrossRoomReplayIsDetected(t *testing.T) {
	key := mustRoomKey(t) // same key in both rooms, e.g. a member of each
	alice := mustSigner(t)

	env, err := SealRoomSigned("private-room", "I quit", key, alice)
	if err != nil {
		t.Fatal(err)
	}
	// Replayed into a different room where the attacker is also a member.
	_, err = OpenRoomSigned("public-room", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if !errors.Is(err, ErrForgedSignature) {
		t.Fatalf("a message was replayed into another room undetected (err=%v)", err)
	}
}

// TestTamperedTextFailsVerification: altering the text must break the
// signature even though the forger can re-seal with the group key.
func TestTamperedTextFailsVerification(t *testing.T) {
	key := mustRoomKey(t)
	alice := mustSigner(t)
	env, _ := SealRoomSigned("r", "pay alice 10", key, alice)

	// Open it, tamper, re-seal with the SAME signature bytes.
	opened, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key}, []ed25519.PublicKey{alice.Public})
	if err != nil || !opened.Verified {
		t.Fatal("setup failed")
	}
	forged, err := signPayload("r", "pay mallory 1000", mustSigner(t)) // different signer
	if err != nil {
		t.Fatalf("signPayload: %v", err)
	}
	tampered, err := sealRoomPayload(forged, key, roomEnvelopePrefixV2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoomSigned("r", tampered, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public}); !errors.Is(err, ErrForgedSignature) {
		t.Errorf("tampered message accepted (err=%v)", err)
	}
}

// TestUnknownSignerIsNotForgery: not having fetched someone's keys yet is a
// routine timing gap, and must not be reported as an attack.
func TestUnknownSignerIsNotForgery(t *testing.T) {
	key := mustRoomKey(t)
	alice := mustSigner(t)
	env, _ := SealRoomSigned("r", "hello", key, alice)

	got, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key}, nil)
	if err != nil {
		t.Fatalf("an unknown signer produced an error: %v", err)
	}
	if got.Text != "hello" {
		t.Errorf("text = %q", got.Text)
	}
	if !got.Signed {
		t.Error("message should be flagged as carrying a signature")
	}
	if got.Verified {
		t.Error("message must NOT be reported verified when we hold no keys for the sender")
	}
}

// TestUnsignedMessageStillOpens: an older BENCchat sends unsigned messages;
// they remain readable, just not attributable.
func TestUnsignedMessageStillOpens(t *testing.T) {
	key := mustRoomKey(t)
	env, err := SealRoom("legacy message", key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key}, nil)
	if err != nil {
		t.Fatalf("unsigned message failed to open: %v", err)
	}
	if got.Text != "legacy message" {
		t.Errorf("text = %q", got.Text)
	}
	if got.Signed || got.Verified {
		t.Error("an unsigned message must not claim to be signed or verified")
	}
}

// TestMultiDeviceSenderVerifies: a sender with several machines signs with
// whichever one they're on, and any of their published keys should verify it.
func TestMultiDeviceSenderVerifies(t *testing.T) {
	key := mustRoomKey(t)
	laptop, phone := mustSigner(t), mustSigner(t)
	published := []ed25519.PublicKey{laptop.Public, phone.Public}

	for name, signer := range map[string]SigningKeyPair{"laptop": laptop, "phone": phone} {
		env, _ := SealRoomSigned("r", "from "+name, key, signer)
		got, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key}, published)
		if err != nil || !got.Verified {
			t.Errorf("%s message did not verify: %v", name, err)
		}
	}
}

// TestSigningKeySeedRoundTrip: the seed is what we store in the keyring, and it
// must rebuild exactly the same key or every past signature becomes unverifiable.
func TestSigningKeySeedRoundTrip(t *testing.T) {
	kp := mustSigner(t)
	seed, err := DecodeSigningSeed(EncodeSigningSeed(kp))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := SigningKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if SignerID(restored.Public) != SignerID(kp.Public) {
		t.Fatal("restored signing key has a different identity")
	}
	env, _ := SealRoomSigned("r", "signed before restart", mustRoomKey(t), kp)
	_ = env
	if !restored.Public.Equal(kp.Public) {
		t.Error("restored public key differs")
	}
}

// TestDeviceKeySplit covers pulling the two kinds of key back out of a device
// set: the encryption path wants box keys, the room-signing path wants signing
// keys, and a device set may legitimately mix devices that publish a signing key
// with ones that don't.
func TestDeviceKeySplit(t *testing.T) {
	box1, box2, box3 := mustKey(t), mustKey(t), mustKey(t)
	sign1, sign2 := mustSigner(t), mustSigner(t)

	devices := []Device{
		{Box: box1.Public, Sign: sign1.Public},
		{Box: box2.Public, Sign: sign2.Public},
		// A device from a client that never generated a signing key: its room
		// messages are readable but not attributable.
		{Box: box3.Public},
	}

	if got := BoxKeysOf(devices); len(got) != 3 {
		t.Errorf("BoxKeysOf returned %d keys, want 3", len(got))
	}
	signing := SigningKeysOf(devices)
	if len(signing) != 2 {
		t.Fatalf("SigningKeysOf returned %d keys, want 2", len(signing))
	}
	for _, want := range []ed25519.PublicKey{sign1.Public, sign2.Public} {
		var found bool
		for _, got := range signing {
			if got.Equal(want) {
				found = true
			}
		}
		if !found {
			t.Error("a published signing key was dropped")
		}
	}

	// Duplicate devices must not produce duplicate envelope slots.
	if got := BoxKeysOf(append(devices, Device{Box: box1.Public})); len(got) != 3 {
		t.Errorf("BoxKeysOf did not dedupe: %d keys, want 3", len(got))
	}
}

// TestRoomMessageCarriesSignedStamp: a room message must say when it was sent,
// or the server can redeliver last month's and have it read as current.
func TestRoomMessageCarriesSignedStamp(t *testing.T) {
	alice := mustSigner(t)
	key := mustRoomKey(t)

	before := time.Now().Add(-time.Second)
	env, err := SealRoomSigned("r", "ship it", key, alice)
	if err != nil {
		t.Fatalf("SealRoomSigned: %v", err)
	}
	got, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if err != nil {
		t.Fatalf("OpenRoomSigned: %v", err)
	}
	if !got.Verified {
		t.Fatal("a freshly signed message did not verify")
	}
	if got.SentAt.Before(before) || got.SentAt.After(time.Now().Add(time.Second)) {
		t.Errorf("sent-at = %v, not close to now", got.SentAt)
	}
	if got.ID == ([16]byte{}) {
		t.Error("no message ID, so duplicates are undetectable")
	}
}

// TestRoomStampIsCoveredBySignature is the whole point of R6.
//
// A timestamp the sender does not sign is one anybody downstream can rewrite —
// and rewriting it is exactly the attack, since a replay is only convincing if
// it looks recent. Moving a single byte of the stamp must break the signature.
func TestRoomStampIsCoveredBySignature(t *testing.T) {
	alice := mustSigner(t)
	key := mustRoomKey(t)

	payload, err := signPayload("r", "ship it", alice)
	if err != nil {
		t.Fatalf("signPayload: %v", err)
	}
	// [1] version, [8] signer id, [64] signature, then the stamp.
	const stampAt = 1 + signerIDLen + ed25519.SignatureSize
	if len(payload) < stampAt+stampLen {
		t.Fatalf("payload is %d bytes, too short to carry a stamp", len(payload))
	}

	// Wind the claimed send time forward, as a server replaying it would.
	tampered := append([]byte(nil), payload...)
	tampered[stampAt] ^= 0xFF

	env, err := sealRoomPayload(tampered, key, roomEnvelopePrefixV2)
	if err != nil {
		t.Fatalf("sealRoomPayload: %v", err)
	}
	_, err = OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if !errors.Is(err, ErrForgedSignature) {
		t.Errorf("a rewritten send time was accepted (err=%v)", err)
	}

	// Same for the message ID, which is what makes a duplicate detectable.
	tampered = append([]byte(nil), payload...)
	tampered[stampAt+8] ^= 0xFF
	env, _ = sealRoomPayload(tampered, key, roomEnvelopePrefixV2)
	if _, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public}); !errors.Is(err, ErrForgedSignature) {
		t.Errorf("a rewritten message ID was accepted (err=%v)", err)
	}
}

// TestAttestationRoundTrips: the client half of device attestation must agree
// with the server's, byte for byte, or every session fails to prove itself.
func TestAttestationRoundTrips(t *testing.T) {
	kp := mustSigner(t)
	nonce := []byte("a-32-byte-nonce-for-attestation!")

	sig := SignAttestation("alice", nonce, kp.Private)
	if !VerifyAttestation("alice", nonce, kp.Public, sig) {
		t.Fatal("a freshly made attestation did not verify")
	}
}

// TestAttestationBindsAccountAndNonce: a signature must not be liftable onto
// another account, or replayable from an earlier session into a later one.
func TestAttestationBindsAccountAndNonce(t *testing.T) {
	kp := mustSigner(t)
	nonce := []byte("a-32-byte-nonce-for-attestation!")
	sig := SignAttestation("alice", nonce, kp.Private)

	if VerifyAttestation("mallory", nonce, kp.Public, sig) {
		t.Error("an attestation for alice verified for mallory")
	}
	if VerifyAttestation("alice", []byte("a-different-32-byte-nonce-here!!"), kp.Public, sig) {
		t.Error("an attestation over one nonce verified against another")
	}
}

// TestAttestationIsNotARoomSignature: the two contexts must not collide, or a
// room message could be replayed as proof of device possession.
func TestAttestationIsNotARoomSignature(t *testing.T) {
	kp := mustSigner(t)
	nonce := []byte("a-32-byte-nonce-for-attestation!")

	roomSig := ed25519.Sign(kp.Private, signingContext("alice", string(nonce)))
	if VerifyAttestation("alice", nonce, kp.Public, roomSig) {
		t.Error("a room-message signature was accepted as a device attestation")
	}
}

// TestAttestationUsesNormalizedNames pins a MIXED-CASE vector.
//
// The server verifies against its normalized screen name — lowercased, spaces
// stripped — so a client signing the display form fails on every account whose
// user typed a capital or a space. Every existing test used "alice", where the
// display and normalized forms are identical, so the whole suite was structurally
// blind to it.
func TestAttestationUsesNormalizedNames(t *testing.T) {
	kp := mustSigner(t)
	nonce := []byte("a-32-byte-nonce-for-attestation!")

	// What the client must sign, and what the server will check.
	sig := SignAttestation("rtriy", nonce, kp.Private)

	if !VerifyAttestation("rtriy", nonce, kp.Public, sig) {
		t.Fatal("the normalized form did not verify")
	}
	// The display form must NOT verify — if it did, the two would be
	// interchangeable and the bug would be invisible again.
	if VerifyAttestation("R Triy", nonce, kp.Public, sig) {
		t.Error("display and normalized forms verify interchangeably; " +
			"this test cannot catch the bug it exists for")
	}
}

// TestAttestationContextBytesArePinned fixes the exact wire bytes.
//
// The server builds this independently. If the two drift, the symptom is
// "nobody can sign in", which is a long way from "somebody changed a constant" —
// so both sides pin the same vector. The server's lives in
// TestAttestContextsMatchAcrossImplementations.
func TestAttestationContextBytesArePinned(t *testing.T) {
	got := attestContext("alice", []byte{1, 2, 3})
	want := []byte("BENCO-ATTEST-v1\x00\x00\x00\x00\x05alice\x00\x00\x00\x03\x01\x02\x03")
	if string(got) != string(want) {
		t.Errorf("attest context = %q, want %q", got, want)
	}
}

// TestNoContextCanSpellAnother is the general form of the bug that got through
// twice, and it is written to fail on the SHAPE rather than on one example.
//
// The first fix tagged only the attestation context. That did not separate
// anything: the room context began with a variable-length attacker-chosen field,
// so a room NAMED "BENCO-ATTEST-v1" carrying `screenName || 0x00 || nonce`
// produced byte-identical output. The collision moved rather than closed.
//
// This asserts the property directly: no choice of room name and message can
// produce the bytes of an attestation, and no choice of screen name and nonce
// can produce the bytes of a room signature.
func TestNoContextCanSpellAnother(t *testing.T) {
	nonce := []byte("a-32-byte-nonce-for-attestation!")

	// The exact attack that defeated the first fix.
	spelled := signingContextV2(attestDomain, make([]byte, stampLen), "alice\x00"+string(nonce))
	if string(spelled) == string(attestContext("alice", nonce)) {
		t.Error("a room named after the attest domain still spells an attestation")
	}

	// And the reverse.
	back := attestContext(roomSigDomain, []byte("anything"))
	if string(back) == string(signingContextV2(roomSigDomain, make([]byte, stampLen), "anything")) {
		t.Error("an attestation for a screen name equal to the room domain spells a room signature")
	}

	// Every context must begin with its own tag, which is what makes the above
	// impossible rather than merely unlikely.
	for name, ctx := range map[string][]byte{
		"attest": attestContext("alice", nonce),
		"roomv2": signingContextV2("room", make([]byte, stampLen), "hello"),
	} {
		want := map[string]string{"attest": attestDomain, "roomv2": roomSigDomain}[name]
		if string(ctx[:len(want)]) != want {
			t.Errorf("%s context does not begin with its domain tag", name)
		}
	}
}

// TestContextFieldsAreUnambiguous: a NUL separator only separates if it cannot
// occur in what it separates, and nothing ever stopped a room name or a message
// containing one. Length prefixes remove the question.
func TestContextFieldsAreUnambiguous(t *testing.T) {
	stamp := make([]byte, stampLen)
	a := signingContextV2("a\x00b", stamp, "c")
	b := signingContextV2("a", stamp, "b\x00c")
	if string(a) == string(b) {
		t.Error("a NUL in a room name shifts the field boundary; length prefixes are missing")
	}

	nonce := []byte("a-32-byte-nonce-for-attestation!")
	if string(attestContext("a\x00b", nonce)) == string(attestContext("a", append([]byte("b\x00"), nonce...))) {
		t.Error("a NUL in a screen name shifts the attestation field boundary")
	}
}

// TestV1SignedPayloadsAreNoLongerVerified: the v1 context had no tag and no
// length prefixes, which made it the path by which a signature obtained
// elsewhere could be rebuilt as a room message. Nothing produces v1; accepting
// it kept the weakest construction reachable.
func TestV1SignedPayloadsAreNoLongerVerified(t *testing.T) {
	alice := mustSigner(t)
	key := mustRoomKey(t)

	sig := ed25519.Sign(alice.Private, signingContext("r", "hello from v1"))
	id, _ := hex.DecodeString(SignerID(alice.Public))
	payload := []byte{signedPayloadV1}
	payload = append(payload, id...)
	payload = append(payload, sig...)
	payload = append(payload, "hello from v1"...)

	env, err := sealRoomPayload(payload, key, roomEnvelopePrefixV2)
	if err != nil {
		t.Fatalf("sealRoomPayload: %v", err)
	}
	got, err := OpenRoomSigned("r", env, map[string]RoomKey{key.ID(): key},
		[]ed25519.PublicKey{alice.Public})
	if err != nil {
		t.Fatalf("a v1 payload should still OPEN, just not be attributed: %v", err)
	}
	if got.Verified || got.Signed {
		t.Error("a v1 signed payload was still attributed to its signer")
	}
	if got.Text != "hello from v1" {
		t.Errorf("v1 text was lost: %q", got.Text)
	}
}
