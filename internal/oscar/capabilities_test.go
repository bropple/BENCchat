package oscar

import "testing"

// TestCapabilityRoundTrip: a capabilities blob is a flat concatenation of
// 16-byte UUIDs, and must decode back to exactly what was advertised.
func TestCapabilityRoundTrip(t *testing.T) {
	want := []Capability{CapSecureIM, CapBENCchat}
	blob := make([]byte, 0, 32)
	for _, c := range want {
		blob = append(blob, c[:]...)
	}
	if len(blob)%16 != 0 {
		t.Fatalf("blob length %d is not a multiple of 16 — the server drops the connection on this", len(blob))
	}

	got := decodeCapabilities(blob)
	if len(got) != len(want) {
		t.Fatalf("decoded %d capabilities, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("capability %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestDecodeCapabilitiesTolerantOfJunk: a peer's malformed advertisement must
// not break decoding — a trailing partial UUID is dropped, not fatal.
func TestDecodeCapabilitiesTolerantOfJunk(t *testing.T) {
	blob := append(append([]byte{}, CapBENCchat[:]...), 0x01, 0x02, 0x03)
	got := decodeCapabilities(blob)
	if len(got) != 1 || got[0] != CapBENCchat {
		t.Fatalf("decoded %v, want just CapBENCchat", got)
	}
	if len(decodeCapabilities([]byte{0x01})) != 0 {
		t.Error("a sub-UUID blob should decode to nothing")
	}
	if len(decodeCapabilities(nil)) != 0 {
		t.Error("nil blob should decode to nothing")
	}
}

// TestHasCapability covers the lookup the UI's "can this peer encrypt?" check
// depends on.
func TestHasCapability(t *testing.T) {
	caps := []Capability{CapSecureIM}
	if !HasCapability(caps, CapSecureIM) {
		t.Error("HasCapability missed a capability that is present")
	}
	if HasCapability(caps, CapBENCchat) {
		t.Error("HasCapability reported one that is absent")
	}
	if HasCapability(nil, CapBENCchat) {
		t.Error("HasCapability on an empty list must be false")
	}
}

// TestBENCchatCapIsNotInAOLNamespace guards the UUID choice: AOL's capabilities
// all end in the 4C7F-11D1-8222-444553540000 suffix, and colliding with a real
// one would make BENCchat clients look like something else entirely.
func TestBENCchatCapIsNotInAOLNamespace(t *testing.T) {
	aolSuffix := CapSecureIM[4:]
	same := true
	for i, b := range CapBENCchat[4:] {
		if b != aolSuffix[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("CapBENCchat %s sits in AOL's capability namespace", CapBENCchat)
	}
}
