package e2ee

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"strings"
)

// The recovery key: ten words, ~110 bits, generated not chosen.
//
// This is the only thing standing between an attacker holding the encrypted
// identity backup and the identity key inside it. That blob is attackable
// OFFLINE with no rate limiting — there is no server to lock them out, no
// attempt counter, nothing but the KDF slowing them down. A human-chosen
// passphrase loses that fight regardless of how the prompt is worded, so the
// key is generated and the user's only job is to write it down (proposal §1).
//
// Ten words from 2048 is 110 bits. Even against an attacker who has the blob
// and unlimited hardware, that plus argon2id (see identitybackup.go) is not a
// search anybody finishes.
//
// # This is NOT BIP39, and deliberately has no checksum
//
// The wordlist is BIP39's English list, chosen because it is well-tested for
// exactly the properties needed here — unique four-character prefixes, no
// confusable pairs, no words that sound alike read aloud. The ENCODING is not
// BIP39: there is no checksum word, no PBKDF2 mnemonic-to-seed step, and no
// derivation path.
//
// A checksum was considered and rejected. Adding one would make this look like
// a BIP39 seed phrase, and the predictable consequence of something looking
// like a seed phrase is that somebody eventually pastes it into a wallet — or,
// worse, pastes a wallet phrase in here. Ten words with no checksum cannot be
// mistaken for a valid twelve/twenty-four word BIP39 mnemonic in either
// direction, and that separation is worth more than the typo detection a
// checksum would buy.
//
// The typo case is handled better anyway: ParseRecoveryKey reports WHICH word
// is wrong. A checksum can only say "something is wrong somewhere", which for a
// user staring at ten handwritten words is barely more useful than silence.

// recoveryWordCount is how many words make up a recovery key. It is a security
// parameter — 11 bits each, so ten words is 110 bits — not a formatting choice.
const recoveryWordCount = 10

// RecoveryKeyWords is the word count, exported so a UI can lay out the right
// number of input slots without hardcoding it.
const RecoveryKeyWords = recoveryWordCount

// recoveryWordBits is log2(len(wordlist)). The list is exactly 2048 entries so
// this is exact — see GenerateRecoveryKey for why that is what makes the
// mapping from random bits to words unbiased.
const recoveryWordBits = 11

//go:embed wordlist_english.txt
var recoveryWordlistRaw string

// recoveryWordlist is the 2048-word list, and recoveryWordIndex is its reverse
// map. Both are built once at init because the list is fixed at compile time.
var (
	recoveryWordlist  []string
	recoveryWordIndex map[string]int
)

func init() {
	recoveryWordlist = strings.Fields(recoveryWordlistRaw)
	if n := len(recoveryWordlist); n != 1<<recoveryWordBits {
		// A truncated or duplicated list would silently reduce the entropy of
		// every recovery key ever generated, and would do it invisibly. Failing
		// at startup is the only honest response.
		panic(fmt.Sprintf("e2ee: recovery wordlist has %d words, want %d", n, 1<<recoveryWordBits))
	}
	recoveryWordIndex = make(map[string]int, len(recoveryWordlist))
	for i, w := range recoveryWordlist {
		if _, dup := recoveryWordIndex[w]; dup {
			panic("e2ee: duplicate word in recovery wordlist: " + w)
		}
		recoveryWordIndex[w] = i
	}
}

// RecoveryWordError names the position of the first word that is not in the
// list.
//
// Reporting the position is the entire reason the list has unique
// four-character prefixes: a typo in a handwritten key is locatable, and "word
// 7 isn't a valid word" lets a user fix it. "Wrong recovery key" sends someone
// to re-check all ten, or worse, to conclude their key is lost when one letter
// is smudged.
//
// The offending word is carried too, but a UI should think before echoing it:
// the rest of the key is a live secret and this struct is the sort of thing
// that ends up in a log line.
type RecoveryWordError struct {
	// Position is 1-based, matching how the words are presented to a human.
	Position int
	Word     string
}

func (e *RecoveryWordError) Error() string {
	return fmt.Sprintf("e2ee: word %d (%q) is not in the recovery wordlist", e.Position, e.Word)
}

// RecoveryLengthError reports a key with the wrong number of words, and how
// many were found — again so the message can be specific ("that's 9 words, a
// recovery key has 10") rather than a flat rejection.
type RecoveryLengthError struct {
	Got  int
	Want int
}

func (e *RecoveryLengthError) Error() string {
	return fmt.Sprintf("e2ee: recovery key has %d words, want %d", e.Got, e.Want)
}

// GenerateRecoveryKey produces a fresh ten-word recovery key in canonical form
// (lowercase, hyphen-separated).
//
// # Why this is free of modulo bias
//
// The wordlist is exactly 2048 = 2^11 entries, so an 11-bit value drawn
// uniformly at random maps one-to-one onto the list: every word is produced by
// exactly one of the 2048 possible bit patterns, and every pattern is equally
// likely because it comes straight off crypto/rand. There is no remainder to
// discard, so no rejection sampling is needed and none is performed.
//
// This is the one case where "no rejection loop" is correct rather than lazy,
// and it is only correct BECAUSE the list size is a power of two — which init()
// enforces. If the list were ever 2000 words, this function would need
// rejection sampling and the panic in init() is what stops that change landing
// silently.
//
// The bits are read as a contiguous stream rather than a byte per word, so no
// entropy is discarded and the mapping is a pure re-slicing of 110 random bits.
func GenerateRecoveryKey() (string, error) {
	// ceil(10*11 / 8) = 14 bytes. The last two bits are unused.
	const nbytes = (recoveryWordCount*recoveryWordBits + 7) / 8
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("e2ee: recovery key entropy: %w", err)
	}
	words := make([]string, recoveryWordCount)
	for i := range words {
		words[i] = recoveryWordlist[bitsAt(buf, i*recoveryWordBits, recoveryWordBits)]
	}
	return strings.Join(words, "-"), nil
}

// bitsAt reads n bits (n <= 16) from buf starting at bit offset off, most
// significant bit first, and returns them as an integer.
//
// Big-endian bit order is arbitrary but must never change: it is not on the
// wire, but it decides which word a given random draw produces, and altering it
// would be a silent no-op that only shows up as generated keys looking
// different from the ones in the tests.
func bitsAt(buf []byte, off, n int) int {
	var acc int
	for i := 0; i < n; i++ {
		bit := off + i
		b := (buf[bit/8] >> (7 - uint(bit%8))) & 1
		acc = acc<<1 | int(b)
	}
	return acc
}

// ParseRecoveryKey normalises and validates user input, returning the key in
// canonical form.
//
// Input arrives from a human retyping something off paper, so it accepts what
// that actually looks like: leading and trailing whitespace, upper case, spaces
// or hyphens as separators (or both, mixed), and repeated separators from an
// enthusiastic double-tap. What it does NOT do is guess — a word that is not in
// the list is an error naming its position, not a nearest-match correction,
// because silently substituting a word would turn a typo into an
// undiagnosable decryption failure later.
func ParseRecoveryKey(s string) (string, error) {
	words := splitRecoveryKey(s)
	if len(words) != recoveryWordCount {
		return "", &RecoveryLengthError{Got: len(words), Want: recoveryWordCount}
	}
	for i, w := range words {
		if _, ok := recoveryWordIndex[w]; !ok {
			return "", &RecoveryWordError{Position: i + 1, Word: w}
		}
	}
	return strings.Join(words, "-"), nil
}

// splitRecoveryKey lowercases and splits on any run of hyphens or whitespace.
// Empty fields are dropped, which is what collapses repeated separators.
func splitRecoveryKey(s string) []string {
	return strings.FieldsFunc(strings.ToLower(strings.TrimSpace(s)), func(r rune) bool {
		switch r {
		case '-', ' ', '\t', '\n', '\r', '\v', '\f':
			return true
		}
		return false
	})
}

// RecoveryKeyWordAt returns the nth (1-based) word of the list, for tests and
// for a UI that wants to offer completions from the four-character prefixes.
func RecoveryKeyWordAt(i int) (string, bool) {
	if i < 0 || i >= len(recoveryWordlist) {
		return "", false
	}
	return recoveryWordlist[i], true
}

// RecoveryWordlistSize is the number of words available. Exposed so a caller
// can state the entropy in a UI without recomputing it from a magic number.
func RecoveryWordlistSize() int { return len(recoveryWordlist) }
