package e2ee

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestRecoveryKeyRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		key, err := GenerateRecoveryKey()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		words := strings.Split(key, "-")
		if len(words) != RecoveryKeyWords {
			t.Fatalf("generated %d words, want %d: %q", len(words), RecoveryKeyWords, key)
		}
		parsed, err := ParseRecoveryKey(key)
		if err != nil {
			t.Fatalf("parse of a generated key failed: %v (%q)", err, key)
		}
		if parsed != key {
			t.Fatalf("generated key is not in canonical form: %q -> %q", key, parsed)
		}
	}
}

// Everything a human might actually type must normalise to the same canonical
// string, because that string is what the KDF hashes — a key that is correct
// but typed with spaces must still open the backup.
func TestParseRecoveryKeyNormalisesInput(t *testing.T) {
	canonical, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	words := strings.Split(canonical, "-")

	variants := map[string]string{
		"spaces":            strings.Join(words, " "),
		"upper case":        strings.ToUpper(canonical),
		"mixed case":        strings.ToUpper(words[0]) + "-" + strings.Join(words[1:], "-"),
		"surrounding space": "\t  " + canonical + "\n ",
		"double hyphen":     strings.Join(words, "--"),
		"hyphen and space":  strings.Join(words, " - "),
		"mixed separators":  strings.Join(words[:5], "-") + " " + strings.Join(words[5:], " "),
		"newlines":          strings.Join(words, "\n"),
	}
	for name, in := range variants {
		got, err := ParseRecoveryKey(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != canonical {
			t.Errorf("%s: got %q, want %q", name, got, canonical)
		}
	}
}

// A locatable typo is the reason there is no checksum: the error must name the
// position, so a user can fix one word rather than re-check ten.
func TestParseRecoveryKeyReportsTheBadWordByPosition(t *testing.T) {
	canonical, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for pos := 1; pos <= RecoveryKeyWords; pos++ {
		words := strings.Split(canonical, "-")
		words[pos-1] = "zzzznotaword"
		_, err := ParseRecoveryKey(strings.Join(words, "-"))

		var werr *RecoveryWordError
		if !errors.As(err, &werr) {
			t.Fatalf("position %d: got %v, want a *RecoveryWordError", pos, err)
		}
		if werr.Position != pos {
			t.Fatalf("reported word %d, the bad word was %d", werr.Position, pos)
		}
		if werr.Word != "zzzznotaword" {
			t.Fatalf("reported word %q, want %q", werr.Word, "zzzznotaword")
		}
		if !strings.Contains(werr.Error(), "word ") {
			t.Fatalf("error message does not name the word: %q", werr.Error())
		}
	}
}

func TestParseRecoveryKeyReportsWrongLength(t *testing.T) {
	canonical, _ := GenerateRecoveryKey()
	words := strings.Split(canonical, "-")

	for _, tc := range []struct {
		name string
		in   string
		want int
	}{
		{"too few", strings.Join(words[:9], "-"), 9},
		{"too many", canonical + "-" + words[0], 11},
		{"empty", "   ", 0},
	} {
		var lerr *RecoveryLengthError
		_, err := ParseRecoveryKey(tc.in)
		if !errors.As(err, &lerr) {
			t.Fatalf("%s: got %v, want a *RecoveryLengthError", tc.name, err)
		}
		if lerr.Got != tc.want || lerr.Want != RecoveryKeyWords {
			t.Fatalf("%s: got %d/%d, want %d/%d", tc.name, lerr.Got, lerr.Want, tc.want, RecoveryKeyWords)
		}
	}
}

func TestRecoveryWordlistShape(t *testing.T) {
	if n := RecoveryWordlistSize(); n != 2048 {
		t.Fatalf("wordlist has %d words, want 2048", n)
	}
	// Unique four-character prefixes are what make a typo locatable and what
	// lets a UI offer completions. Losing that property silently would remove
	// the justification given for having no checksum.
	prefixes := make(map[string]string, 2048)
	for i := 0; i < RecoveryWordlistSize(); i++ {
		w, ok := RecoveryKeyWordAt(i)
		if !ok {
			t.Fatalf("word %d missing", i)
		}
		if len(w) < 3 {
			t.Fatalf("word %q is implausibly short", w)
		}
		p := w
		if len(p) > 4 {
			p = p[:4]
		}
		if prev, dup := prefixes[p]; dup {
			t.Fatalf("words %q and %q share the prefix %q", prev, w, p)
		}
		prefixes[p] = w
	}
	if _, ok := RecoveryKeyWordAt(-1); ok {
		t.Fatal("negative index accepted")
	}
	if _, ok := RecoveryKeyWordAt(2048); ok {
		t.Fatal("out-of-range index accepted")
	}
}

// The distribution check. A modulo-biased generator over 2048 entries would
// over-represent some slice of the list, so this asserts two things: that every
// single word is reachable, and that the observed counts are not wildly uneven.
//
// It is a smoke test, not a statistical proof — a subtle bias would survive it.
// What it does catch is the failure modes that actually happen: a range that is
// never produced, an off-by-one that clips the last word, or a byte-per-word
// implementation that can only reach 256 of the 2048.
func TestRecoveryKeyGeneratorCoversTheWordlistEvenly(t *testing.T) {
	const draws = 300000 // 300k words over 2048 slots: ~146 expected each

	counts := make([]int, RecoveryWordlistSize())
	index := make(map[string]int, RecoveryWordlistSize())
	for i := range counts {
		w, _ := RecoveryKeyWordAt(i)
		index[w] = i
	}

	for n := 0; n < draws/RecoveryKeyWords; n++ {
		key, err := GenerateRecoveryKey()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		for _, w := range strings.Split(key, "-") {
			counts[index[w]]++
		}
	}

	expected := float64(draws) / float64(len(counts))
	var chi2 float64
	minCount, maxCount := math.MaxInt32, 0
	for i, c := range counts {
		if c == 0 {
			w, _ := RecoveryKeyWordAt(i)
			t.Fatalf("word %d (%q) was never generated in %d draws", i, w, draws)
		}
		if c < minCount {
			minCount = c
		}
		if c > maxCount {
			maxCount = c
		}
		d := float64(c) - expected
		chi2 += d * d / expected
	}

	// With 2047 degrees of freedom a fair generator gives chi-square ~= 2047,
	// with a standard deviation of sqrt(2*2047) ~= 64. The bound is set far out
	// (about 15 sigma) so this cannot flake, while still being nowhere near what
	// a real bias would produce: dropping even a single word's worth of
	// probability mass pushes chi-square well past it.
	if chi2 > 3000 {
		t.Errorf("chi-square %.1f over %d draws suggests a biased generator (expected ~%d, min %d, max %d, mean %.1f)",
			chi2, draws, len(counts)-1, minCount, maxCount, expected)
	}
}

// bitsAt is the whole of the bits-to-word mapping, so it gets checked against
// hand-computed values rather than only through the generator.
func TestBitsAt(t *testing.T) {
	// 0xFF 0x00 0xFF -> 111111110000000011111111
	buf := []byte{0xFF, 0x00, 0xFF}
	for _, tc := range []struct{ off, n, want int }{
		{0, 8, 0xFF},
		{8, 8, 0x00},
		{0, 11, 0b11111111000},
		{4, 11, 0b11110000000},
		{13, 11, 0b00011111111},
		{0, 1, 1},
		{8, 1, 0},
	} {
		if got := bitsAt(buf, tc.off, tc.n); got != tc.want {
			t.Errorf("bitsAt(off=%d, n=%d) = %d, want %d", tc.off, tc.n, got, tc.want)
		}
	}
}
