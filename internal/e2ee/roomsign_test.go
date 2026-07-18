package e2ee

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
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
	forged := signPayload("r", "pay mallory 1000", mustSigner(t)) // different signer
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

// TestDeviceMarkerV3RoundTrip covers publishing encryption and signing keys
// together, and reading older markers.
func TestDeviceMarkerV3RoundTrip(t *testing.T) {
	box1, box2 := mustKey(t), mustKey(t)
	sign1, sign2 := mustSigner(t), mustSigner(t)

	marker := ProfileMarkerForDevices([]Device{
		{Box: box1.Public, Sign: sign1.Public},
		{Box: box2.Public, Sign: sign2.Public},
	})
	if !strings.Contains(marker, "v3:") {
		t.Fatalf("marker = %q, want the v3 form", marker)
	}

	devices, ok := ExtractDevices("bio\n" + marker)
	if !ok || len(devices) != 2 {
		t.Fatalf("extracted %d devices (ok=%v), want 2", len(devices), ok)
	}
	if len(SigningKeysOf(devices)) != 2 {
		t.Error("signing keys did not survive publication")
	}
	if len(BoxKeysOf(devices)) != 2 {
		t.Error("encryption keys did not survive publication")
	}
	// ExtractKeys must still work against a v3 marker, since the encryption
	// path uses it.
	keys, ok := ExtractKeys("bio\n" + marker)
	if !ok || len(keys) != 2 {
		t.Errorf("ExtractKeys on a v3 marker returned %d keys (ok=%v)", len(keys), ok)
	}
	if strings.Contains(StripMarkerAll("bio\n"+marker), "BENCO-E2EE") {
		t.Error("the v3 marker was shown as profile text")
	}

	// A peer on an older marker yields devices with no signing key.
	old, ok := ExtractDevices("bio\n" + ProfileMarkerFor([][32]byte{box1.Public}))
	if !ok || len(old) != 1 || len(old[0].Sign) != 0 {
		t.Errorf("older marker parsed wrongly: %+v (ok=%v)", old, ok)
	}
}
