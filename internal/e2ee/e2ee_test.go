package e2ee

import "testing"

func TestSealOpenRoundTrip(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	const msg = "meet me in the lobby 🔒 :-)"
	env, err := Seal(msg, bob.Public, alice.Private)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsEnvelope(env) {
		t.Fatal("sealed output is not recognized as an envelope")
	}
	// The plaintext must not appear in the envelope.
	if containsPlaintext(env, "lobby") {
		t.Fatal("plaintext leaked into the envelope")
	}

	got, err := Open(env, alice.Public, bob.Private)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != msg {
		t.Fatalf("round-trip = %q, want %q", got, msg)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	mallory, _ := GenerateKeyPair()

	env, _ := Seal("secret", bob.Public, alice.Private)

	// Wrong recipient key.
	if _, err := Open(env, alice.Public, mallory.Private); err == nil {
		t.Fatal("Open succeeded with the wrong recipient key")
	}
	// Wrong claimed sender key (impersonation attempt).
	if _, err := Open(env, mallory.Public, bob.Private); err == nil {
		t.Fatal("Open succeeded with the wrong sender key")
	}
}

func TestTamperedEnvelopeFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	env, _ := Seal("hello", bob.Public, alice.Private)

	// Flip a byte in the base64 body.
	b := []byte(env)
	b[len(b)-2] ^= 0x01
	if _, err := Open(string(b), alice.Public, bob.Private); err == nil {
		t.Fatal("Open accepted a tampered envelope")
	}
}

func TestKeyEncodeRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	enc := EncodeKey(kp.Public)
	got, err := DecodeKey(enc)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if got != kp.Public {
		t.Fatal("public key did not round-trip")
	}
	if _, err := DecodeKey("not-base64!!"); err == nil {
		t.Fatal("DecodeKey accepted junk")
	}
	// A base64 value of the wrong length must be rejected.
	if _, err := DecodeKey("aGVsbG8="); err == nil {
		t.Fatal("DecodeKey accepted a wrong-length key")
	}
}

// TestStripMarkerHidesLegacyV1: nothing publishes profile markers any more, but
// accounts that signed on under the old scheme still carry one in their bio and
// it must never render as profile text.
func TestStripMarkerHidesLegacyV1(t *testing.T) {
	kp, _ := GenerateKeyPair()
	bio := "R. Triy — BENCO roster mascot."
	profile := bio + "\n" + profileMarkerOpen + EncodeKey(kp.Public) + profileMarkerClose

	if stripped := StripMarker(profile); stripped != bio {
		t.Fatalf("StripMarker = %q, want %q", stripped, bio)
	}
	// A profile with no marker is returned unchanged.
	if StripMarker(bio) != bio {
		t.Fatal("StripMarker altered a marker-free profile")
	}
	// An unterminated marker must still not leak: better to lose the tail of a
	// corrupt profile than to show base64 to the user.
	if got := StripMarker(bio + "\n" + profileMarkerOpen + "truncated"); got != bio {
		t.Fatalf("unterminated marker survived stripping: %q", got)
	}
}

func TestSafetyNumberSymmetricAndStable(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Order-independent: both parties compute the same number regardless of which
	// key they treat as "self".
	if SafetyNumber(alice.Public, bob.Public) != SafetyNumber(bob.Public, alice.Public) {
		t.Fatal("SafetyNumber is not order-independent")
	}
	// Stable across calls.
	if SafetyNumber(alice.Public, bob.Public) != SafetyNumber(alice.Public, bob.Public) {
		t.Fatal("SafetyNumber is not stable")
	}

	// A different peer key yields a different number (MITM detection).
	mallory, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if SafetyNumber(alice.Public, bob.Public) == SafetyNumber(alice.Public, mallory.Public) {
		t.Fatal("SafetyNumber collided across different peer keys")
	}

	// Shape: six groups of five digits.
	sn := SafetyNumber(alice.Public, bob.Public)
	if got := len(sn); got != 6*5+5 { // 6 groups, 5 digits each, 5 separators
		t.Fatalf("SafetyNumber %q has length %d, want %d", sn, got, 6*5+5)
	}
}

func containsPlaintext(env, needle string) bool {
	for i := 0; i+len(needle) <= len(env); i++ {
		if env[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
