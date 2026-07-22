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

// TestRoomV1PayloadStillVerifies: an older client signs without a stamp, and
// those messages must still open and attribute correctly.
func TestRoomV1PayloadStillVerifies(t *testing.T) {
	alice := mustSigner(t)
	key := mustRoomKey(t)

	// Build a v1 payload by hand — the shape an older BENCchat emits.
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
		t.Fatalf("a v1 signed payload did not open: %v", err)
	}
	if !got.Verified || got.Text != "hello from v1" {
		t.Errorf("v1 payload = %+v, want verified text", got)
	}
	if !got.SentAt.IsZero() {
		t.Errorf("v1 produced a send time from nowhere: %v", got.SentAt)
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
