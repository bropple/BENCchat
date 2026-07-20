package e2ee

// Emoji rendering of a safety number.
//
// The digits are correct and nobody reads them. Thirty of them, in six groups,
// compared against a phone held up on a video call — the task is tedious enough
// that people skip it, and a verification step that is skipped provides exactly
// as much protection as no verification step. Emoji are compared far more
// readily because they are nameable: "otter, anchor, cactus" survives being read
// aloud in a way "48173 90244" does not.
//
// This is a rendering of the SAME digest the digits come from (safetyDigest),
// not a second, independent code. Both are shown; matching either means the same
// thing.
//
// # Why eighteen and not seven
//
// Matrix's SAS shows seven emoji from a set of sixty-four: 42 bits. That is
// sound for what it is — an INTERACTIVE verification, where an attacker has to
// produce a colliding short string live, during the exchange, with one attempt.
//
// A BENCchat safety number is not that. It is static, it describes a key set
// that persists, and an attacker can grind candidate device keys offline for as
// long as they like looking for a set that renders the same. At 42 bits that is
// roughly four trillion hashes — hours on one GPU. Copying the count from Matrix
// without copying its threat model would have quietly cut this from ~100 bits to
// ~42 and left the UI looking more trustworthy than before.
//
// So the emoji carry the digits' full strength instead: eighteen emoji at six
// bits each is 108 bits, against the digits' 6 * log2(100000) ~= 99.7. Longer to
// read than seven, still far easier than thirty digits, and it does not weaken
// what it renders.

// safetyEmojiCount is how many emoji make up a rendering. See the note above
// before changing it: it is a security parameter, not a layout preference.
const safetyEmojiCount = 18

// SafetyEmoji is one position in the rendering. The name matters as much as the
// glyph — it is what gets read aloud, and it is the fallback wherever a font
// renders the glyph as a box.
type SafetyEmoji struct {
	Emoji string `json:"emoji"`
	Name  string `json:"name"`
}

// safetyEmojiAlphabet is 64 entries, so each consumes exactly six bits.
//
// Chosen to survive the ways this actually gets used: read aloud over a bad
// phone line, and rendered by whatever font three different platforms happen to
// ship. So: no skin-tone modifiers, no ZWJ sequences, no flags, no gendered
// variants, nothing whose name is ambiguous in English, and no two entries that
// look alike at 24 pixels. Order is part of the wire contract — appending is
// fine, reordering silently changes everybody's safety number.
var safetyEmojiAlphabet = [64]SafetyEmoji{
	{"🐶", "dog"}, {"🐱", "cat"}, {"🦁", "lion"}, {"🐴", "horse"},
	{"🦄", "unicorn"}, {"🐷", "pig"}, {"🐘", "elephant"}, {"🐰", "rabbit"},
	{"🐻", "bear"}, {"🐦", "bird"}, {"🐧", "penguin"}, {"🐢", "turtle"},
	{"🐟", "fish"}, {"🐙", "octopus"}, {"🦋", "butterfly"}, {"🐌", "snail"},
	{"🌷", "flower"}, {"🌳", "tree"}, {"🌵", "cactus"}, {"🍄", "mushroom"},
	{"🌍", "globe"}, {"🌙", "moon"}, {"☁️", "cloud"}, {"🔥", "fire"},
	{"🍌", "banana"}, {"🍎", "apple"}, {"🍓", "strawberry"}, {"🌽", "corn"},
	{"🍕", "pizza"}, {"🎂", "cake"}, {"❤️", "heart"}, {"😀", "smiley"},
	{"🤖", "robot"}, {"🎩", "hat"}, {"👓", "glasses"}, {"🔧", "spanner"},
	{"🎅", "santa"}, {"👍", "thumbs up"}, {"☂️", "umbrella"}, {"⌛", "hourglass"},
	{"⏰", "clock"}, {"🎁", "gift"}, {"💡", "light bulb"}, {"📕", "book"},
	{"✏️", "pencil"}, {"📎", "paperclip"}, {"✂️", "scissors"}, {"🔒", "padlock"},
	{"🔑", "key"}, {"🔨", "hammer"}, {"☎️", "telephone"}, {"🏁", "flag"},
	{"🚂", "train"}, {"🚲", "bicycle"}, {"✈️", "aeroplane"}, {"🚀", "rocket"},
	{"🏆", "trophy"}, {"⚽", "ball"}, {"🎸", "guitar"}, {"🎺", "trumpet"},
	{"🔔", "bell"}, {"⚓", "anchor"}, {"🎧", "headphones"}, {"📁", "folder"},
}

// SafetyEmojiSet renders the same safety number as SafetyNumberSet, as emoji.
//
// Returns nil when either side has no keys, matching SafetyNumberSet's caller
// contract: there is nothing to compare until a key exchange has happened.
func SafetyEmojiSet(ours, theirs [][32]byte) []SafetyEmoji {
	if len(ours) == 0 || len(theirs) == 0 {
		return nil
	}
	return emojiFromDigest(safetyDigest(ours, theirs))
}

// emojiFromDigest reads six bits at a time off the digest, most significant
// first, and indexes the alphabet with each. Eighteen positions consume 108 of
// the digest's 256 bits.
func emojiFromDigest(sum [32]byte) []SafetyEmoji {
	out := make([]SafetyEmoji, safetyEmojiCount)
	for i := 0; i < safetyEmojiCount; i++ {
		bit := i * 6
		// Six bits can straddle a byte boundary, so take a 16-bit window at the
		// starting byte and shift the wanted bits down to the bottom.
		hi := uint16(sum[bit/8]) << 8
		if bit/8+1 < len(sum) {
			hi |= uint16(sum[bit/8+1])
		}
		out[i] = safetyEmojiAlphabet[(hi>>(10-uint(bit%8)))&0x3F]
	}
	return out
}
