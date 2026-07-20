package e2ee

import "testing"

// The alphabet's size is a security parameter: each position consumes exactly
// six bits, so anything other than 64 entries silently changes both the entropy
// and the indexing.
func TestSafetyEmojiAlphabetIsExactlySixBits(t *testing.T) {
	if len(safetyEmojiAlphabet) != 64 {
		t.Fatalf("alphabet has %d entries, want exactly 64 (6 bits per position)", len(safetyEmojiAlphabet))
	}
	seenEmoji := map[string]bool{}
	seenName := map[string]bool{}
	for i, e := range safetyEmojiAlphabet {
		if e.Emoji == "" || e.Name == "" {
			t.Errorf("entry %d is incomplete: %+v", i, e)
		}
		if seenEmoji[e.Emoji] {
			t.Errorf("entry %d duplicates emoji %q — collisions halve the work to forge a match", i, e.Emoji)
		}
		if seenName[e.Name] {
			t.Errorf("entry %d duplicates name %q — the name is what gets read aloud", i, e.Name)
		}
		seenEmoji[e.Emoji], seenName[e.Name] = true, true
	}
}

// The emoji must render the SAME number as the digits. If they could disagree
// they would be two codes, and an attacker would target whichever one the user
// actually reads.
func TestSafetyEmojiTracksTheDigits(t *testing.T) {
	a, b := [][32]byte{{1}}, [][32]byte{{2}}

	if got := len(SafetyEmojiSet(a, b)); got != safetyEmojiCount {
		t.Fatalf("got %d emoji, want %d", got, safetyEmojiCount)
	}
	// Same inputs in the other order: both sides of a conversation must see the
	// same rendering, exactly as they do for the digits.
	if SafetyNumberSet(a, b) != SafetyNumberSet(b, a) {
		t.Fatal("digit rendering is order-dependent")
	}
	x, y := SafetyEmojiSet(a, b), SafetyEmojiSet(b, a)
	for i := range x {
		if x[i] != y[i] {
			t.Fatalf("emoji rendering is order-dependent at %d: %v vs %v", i, x[i], y[i])
		}
	}
	// A different key set must move it.
	if same(SafetyEmojiSet(a, b), SafetyEmojiSet(a, [][32]byte{{3}})) {
		t.Error("a different peer key set produced identical emoji")
	}
}

// Nothing to compare until both sides have keys — same contract the digits have.
func TestSafetyEmojiEmptyWithoutKeys(t *testing.T) {
	if SafetyEmojiSet(nil, [][32]byte{{1}}) != nil {
		t.Error("emoji returned with no keys of our own")
	}
	if SafetyEmojiSet([][32]byte{{1}}, nil) != nil {
		t.Error("emoji returned with no peer keys")
	}
}

// Every position must be reachable, or the effective alphabet is smaller than
// 64 and the rendering is weaker than it claims. A bad bit-window would show up
// as whole ranges of the alphabet never appearing.
func TestSafetyEmojiUsesTheWholeAlphabet(t *testing.T) {
	hit := map[string]bool{}
	for i := 0; i < 4000; i++ {
		var k [32]byte
		k[0], k[1] = byte(i), byte(i>>8)
		for _, e := range SafetyEmojiSet([][32]byte{{9}}, [][32]byte{k}) {
			hit[e.Name] = true
		}
	}
	if len(hit) != 64 {
		t.Errorf("only %d of 64 alphabet entries were ever produced", len(hit))
	}
}

func same(a, b []SafetyEmoji) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
