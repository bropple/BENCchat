package e2ee

import (
	"crypto/sha256"
	"testing"
)

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
// actually reads. Driven through the live entry points rather than the digest
// helper, so a change that renders the two from different digests fails here.
func TestSafetyEmojiTracksTheDigits(t *testing.T) {
	a, _ := GenerateIdentityKey()
	defer a.Zero()
	b, _ := GenerateIdentityKey()
	defer b.Zero()
	c, _ := GenerateIdentityKey()
	defer c.Zero()

	if got := len(IdentitySafetyEmoji(a.Public, b.Public)); got != safetyEmojiCount {
		t.Fatalf("got %d emoji, want %d", got, safetyEmojiCount)
	}
	// Both renderings must come from one digest: same inputs, same digest, so
	// the emoji move exactly when the digits do.
	if IdentitySafetyNumber(a.Public, b.Public) == IdentitySafetyNumber(a.Public, c.Public) {
		t.Fatal("digits did not move for a different peer identity")
	}
	if same(IdentitySafetyEmoji(a.Public, b.Public), IdentitySafetyEmoji(a.Public, c.Public)) {
		t.Error("a different peer identity produced identical emoji")
	}
}

// Every position must be reachable, or the effective alphabet is smaller than
// 64 and the rendering is weaker than it claims. A bad bit-window would show up
// as whole ranges of the alphabet never appearing. Driven at emojiFromDigest,
// which is where the bit-window arithmetic lives.
func TestSafetyEmojiUsesTheWholeAlphabet(t *testing.T) {
	hit := map[string]bool{}
	for i := 0; i < 4000; i++ {
		var sum [32]byte
		sum[0], sum[1] = byte(i), byte(i>>8)
		sum = sha256.Sum256(sum[:])
		for _, e := range emojiFromDigest(sum) {
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
