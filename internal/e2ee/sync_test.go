package e2ee

import (
	"strings"
	"testing"
)

// TestSentCopyRoundTrips: the fields a receiving device acts on must survive
// intact, including a message that contains the delimiters.
func TestSentCopyRoundTrips(t *testing.T) {
	in := SentCopy{
		Origin: "abc123",
		Peer:   "bob, jr",
		// A message that spells the framing back at it: NULs, colons, and the
		// prefix itself.
		Text:   "here's \x00 a colon: and \x1bBENCO-SYNC:v1: for good measure",
		SentAt: 1_700_000_000,
	}
	body, err := EncodeSentCopy(in)
	if err != nil {
		t.Fatalf("EncodeSentCopy: %v", err)
	}
	if !IsSentCopy(body) {
		t.Fatal("output not recognized as a sync copy")
	}
	got, err := DecodeSentCopy(body)
	if err != nil {
		t.Fatalf("DecodeSentCopy: %v", err)
	}
	if got != in {
		t.Errorf("round trip changed the copy:\n got %+v\nwant %+v", got, in)
	}
}

// TestSentCopyFieldsAreUnambiguous: three variable-length strings in a row, so
// one field's content must not be readable as another's boundary.
func TestSentCopyFieldsAreUnambiguous(t *testing.T) {
	a, _ := EncodeSentCopy(SentCopy{Origin: "x", Peer: "a\x00b", Text: "c"})
	b, _ := EncodeSentCopy(SentCopy{Origin: "x", Peer: "a", Text: "b\x00c"})
	if a == b {
		t.Error("a NUL shifted the field boundary; length prefixes are missing")
	}
}

// TestSentCopyIDIsStableAndDistinguishing: the ID is what stops a redelivered
// copy appearing in the conversation twice, so it must be identical for the same
// copy and different for a different one.
func TestSentCopyIDIsStableAndDistinguishing(t *testing.T) {
	base := SentCopy{Origin: "dev1", Peer: "bob", Text: "hello", SentAt: 42}
	if SentCopyID(base) != SentCopyID(base) {
		t.Fatal("the same copy produced two different IDs")
	}

	for name, edit := range map[string]func(SentCopy) SentCopy{
		"origin": func(c SentCopy) SentCopy { c.Origin = "dev2"; return c },
		"peer":   func(c SentCopy) SentCopy { c.Peer = "carol"; return c },
		"text":   func(c SentCopy) SentCopy { c.Text = "goodbye"; return c },
		"time":   func(c SentCopy) SentCopy { c.SentAt = 43; return c },
	} {
		if SentCopyID(edit(base)) == SentCopyID(base) {
			t.Errorf("changing the %s did not change the ID, so two messages would collide", name)
		}
	}

	// Field boundaries again, this time in the hash: "a"+"bc" must not hash the
	// same as "ab"+"c", or two genuinely different messages would be deduped
	// into one.
	x := SentCopy{Origin: "d", Peer: "a", Text: "bc"}
	y := SentCopy{Origin: "d", Peer: "ab", Text: "c"}
	if SentCopyID(x) == SentCopyID(y) {
		t.Error("the ID hash does not separate its fields")
	}
}

// TestSentCopyRefusesJunk: everything here arrives from the wire, even though it
// arrives sealed to our own keys.
func TestSentCopyRefusesJunk(t *testing.T) {
	for name, body := range map[string]string{
		"not a sync copy": "hello",
		"bad base64":      SyncPrefix + "!!!not-base64",
		"truncated":       SyncPrefix + "AAAA",
	} {
		if _, err := DecodeSentCopy(body); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	// A copy naming no peer has nowhere to go, and filing it under "" would put
	// it in a conversation with nobody.
	empty, _ := EncodeSentCopy(SentCopy{Origin: "d", Peer: "", Text: "orphan"})
	if _, err := DecodeSentCopy(empty); err == nil {
		t.Error("a copy naming no peer decoded")
	}
	// And an oversized one is refused at encode rather than sent.
	if _, err := EncodeSentCopy(SentCopy{Peer: "bob", Text: strings.Repeat("x", maxSyncText+1)}); err == nil {
		t.Error("an oversized sync copy was encoded instead of refused")
	}
}
