package wire

// USERLOOKUP (0x000A) — find a user by email address.

// UserLookup subgroups.
const (
	UserLookupErr         uint16 = 0x0001
	UserLookupFindByEmail uint16 = 0x0002
	UserLookupFindReply   uint16 = 0x0003
)

// UserLookupTLVEmailAddress is the reply TLV carrying the matched screen name.
// (The tag is nominally "email" but the value is the screen name.)
const UserLookupTLVEmailAddress uint16 = 0x0001

// UserLookupErrNoUserFound is the error code returned (as a bare uint16) when no
// account matches the queried email.
const UserLookupErrNoUserFound uint16 = 0x0014

// SNAC_0x0A_0x02_UserLookupFindByEmail queries by email. The email is the entire
// SNAC body as raw bytes — not TLV-wrapped, not length-prefixed.
type SNAC_0x0A_0x02_UserLookupFindByEmail struct {
	Email []byte
}

// SNAC_0x0A_0x03_UserLookupFindReply carries the match: TLV 0x01 holds the
// matched account's screen name.
type SNAC_0x0A_0x03_UserLookupFindReply struct {
	TLVRestBlock
}
