package e2ee

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestIdentityKeyRoundTripsThroughSeed(t *testing.T) {
	kp, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	seed, err := kp.seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := IdentityKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if !got.Public.Equal(kp.Public) {
		t.Fatal("public key did not survive the seed round trip")
	}
}

func TestIdentityKeyZeroMakesItUnusable(t *testing.T) {
	kp, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	priv := kp.Private // same backing array; Zero must scrub it in place
	kp.Zero()

	if !kp.Zeroed() {
		t.Fatal("Zeroed() false after Zero()")
	}
	for i, b := range priv {
		if b != 0 {
			t.Fatalf("private key byte %d survived Zero()", i)
		}
	}
	if _, err := SignManifest(kp, []byte("anything")); !errors.Is(err, ErrIdentityKeyZeroed) {
		t.Fatalf("SignManifest after Zero() = %v, want ErrIdentityKeyZeroed", err)
	}
	if _, err := kp.seed(); !errors.Is(err, ErrIdentityKeyZeroed) {
		t.Fatalf("seed() after Zero() = %v, want ErrIdentityKeyZeroed", err)
	}
	kp.Zero() // must be safe twice, since callers defer it AND call it
}

func TestEncodeDecodeIdentityPublic(t *testing.T) {
	kp, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := DecodeIdentityPublic(EncodeIdentityPublic(kp.Public))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Equal(kp.Public) {
		t.Fatal("identity public key did not round trip")
	}
	if _, err := DecodeIdentityPublic("not base64!!"); err == nil {
		t.Fatal("decoded garbage as an identity key")
	}
	if _, err := DecodeIdentityPublic("AAAA"); err == nil {
		t.Fatal("accepted a short identity key")
	}
}

// The signature must cover the exact bytes handed in. This is the property the
// proposal calls the single most important implementation note (§3), so it is
// tested at the byte level rather than via any encoder.
func TestManifestSignatureCoversExactBytes(t *testing.T) {
	kp, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer kp.Zero()

	manifest := []byte("\x00\x02benuser\x00\x00\x00\x00\x00\x00\x00\x01 devices go here")
	sig, err := SignManifest(kp, manifest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyManifest(kp.Public, manifest, sig); err != nil {
		t.Fatalf("verify of the signed bytes failed: %v", err)
	}

	// Flip one bit in every position in turn: all must fail.
	for i := range manifest {
		altered := make([]byte, len(manifest))
		copy(altered, manifest)
		altered[i] ^= 0x01
		if err := VerifyManifest(kp.Public, altered, sig); !errors.Is(err, ErrBadManifestSignature) {
			t.Fatalf("byte %d altered but verification returned %v", i, err)
		}
	}

	// And a single altered signature byte.
	for i := range sig {
		altered := make([]byte, len(sig))
		copy(altered, sig)
		altered[i] ^= 0x01
		if err := VerifyManifest(kp.Public, manifest, altered); !errors.Is(err, ErrBadManifestSignature) {
			t.Fatalf("signature byte %d altered but verification returned %v", i, err)
		}
	}
}

func TestManifestSignatureRejectsWrongIdentity(t *testing.T) {
	mine, _ := GenerateIdentityKey()
	theirs, _ := GenerateIdentityKey()
	defer mine.Zero()
	defer theirs.Zero()

	manifest := []byte("a manifest")
	sig, err := SignManifest(mine, manifest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyManifest(theirs.Public, manifest, sig); !errors.Is(err, ErrBadManifestSignature) {
		t.Fatalf("verified under the wrong identity: %v", err)
	}
}

func TestManifestSignatureRejectsMalformedInput(t *testing.T) {
	kp, _ := GenerateIdentityKey()
	defer kp.Zero()

	if _, err := SignManifest(kp, nil); err == nil {
		t.Fatal("signed an empty manifest")
	}
	sig, _ := SignManifest(kp, []byte("m"))
	if err := VerifyManifest(kp.Public, []byte("m"), sig[:10]); err == nil {
		t.Fatal("accepted a truncated signature")
	}
	if err := VerifyManifest(ed25519.PublicKey("short"), []byte("m"), sig); err == nil {
		t.Fatal("accepted a short public key")
	}
	if err := VerifyManifest(kp.Public, nil, sig); err == nil {
		t.Fatal("accepted an empty manifest")
	}
}

// The whole reason the identity key exists: the safety number stops moving when
// a device is added. Both properties are asserted together because the number
// being order-independent is what makes it comparable at all, and being stable
// is what makes it worth comparing.
func TestIdentitySafetyNumberIsOrderIndependentAndDeviceStable(t *testing.T) {
	alice, _ := GenerateIdentityKey()
	bob, _ := GenerateIdentityKey()
	defer alice.Zero()
	defer bob.Zero()

	fromAlice := IdentitySafetyNumber(alice.Public, bob.Public)
	fromBob := IdentitySafetyNumber(bob.Public, alice.Public)
	if fromAlice == "" {
		t.Fatal("empty safety number for two valid identities")
	}
	if fromAlice != fromBob {
		t.Fatalf("safety number depends on argument order: %q vs %q", fromAlice, fromBob)
	}

	emojiA := IdentitySafetyEmoji(alice.Public, bob.Public)
	emojiB := IdentitySafetyEmoji(bob.Public, alice.Public)
	if len(emojiA) != safetyEmojiCount {
		t.Fatalf("got %d emoji, want %d", len(emojiA), safetyEmojiCount)
	}
	for i := range emojiA {
		if emojiA[i] != emojiB[i] {
			t.Fatalf("emoji %d depends on argument order", i)
		}
	}

	// Adding devices under the same identities must not move either rendering.
	// This is exactly what SafetyNumberSet cannot promise, and the reason for
	// the whole cross-signing design.
	for i := 0; i < 3; i++ {
		if _, err := GenerateKeyPair(); err != nil { // stand-in for a new device
			t.Fatalf("device keypair: %v", err)
		}
	}
	if got := IdentitySafetyNumber(alice.Public, bob.Public); got != fromAlice {
		t.Fatalf("safety number moved after adding devices: %q -> %q", fromAlice, got)
	}

	// And it MUST move when an identity is replaced — the one event §6 says is
	// worth interrupting a human for.
	carol, _ := GenerateIdentityKey()
	defer carol.Zero()
	if got := IdentitySafetyNumber(alice.Public, carol.Public); got == fromAlice {
		t.Fatal("safety number did not change when the peer identity changed")
	}
}

// Device-set safety numbers churn on device addition. Asserted here so the
// contrast is recorded, and so that a later pass that switches the app over has
// a test proving what it fixed.
func TestDeviceSetSafetyNumberChurnsWhereIdentityDoesNot(t *testing.T) {
	a, _ := GenerateKeyPair()
	b, _ := GenerateKeyPair()
	extra, _ := GenerateKeyPair()

	before := SafetyNumberSet([][32]byte{a.Public}, [][32]byte{b.Public})
	after := SafetyNumberSet([][32]byte{a.Public, extra.Public}, [][32]byte{b.Public})
	if before == after {
		t.Fatal("device-set safety number did not change on device addition; " +
			"if this now holds, the identity-based version has nothing to fix")
	}
}

func TestIdentitySafetyRenderingsRejectMissingKeys(t *testing.T) {
	kp, _ := GenerateIdentityKey()
	defer kp.Zero()

	if got := IdentitySafetyNumber(kp.Public, nil); got != "" {
		t.Fatalf("got %q for a missing peer identity, want empty", got)
	}
	if got := IdentitySafetyEmoji(nil, kp.Public); got != nil {
		t.Fatalf("got %v for a missing local identity, want nil", got)
	}
}

// The domain prefix exists so an identity digest can never coincide with a
// device-set digest over the same two 32-byte blobs. Without it a one-device
// account's number and an identity number would be the same string, and during
// the transition both are on screen.
func TestIdentityDigestIsDomainSeparatedFromDeviceSet(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2

	deviceDigest := safetyDigest([][32]byte{a}, [][32]byte{b})
	identityDigest := identitySafetyDigest(ed25519.PublicKey(a[:]), ed25519.PublicKey(b[:]))

	if deviceDigest == identityDigest {
		t.Fatal("identity digest collides with the device-set digest over the same keys")
	}
}
