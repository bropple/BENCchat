package wire

// ODIR (0x000F) — the user directory. Unlike UserLookup (which resolves one
// email to one screen name), ODir searches profile/directory fields (name,
// interest) and can return several matches, each with directory info. The
// server searches by email, by interest keyword, or by first/last name; it does
// not treat a bare screen name as a search key.

// ODir subgroups. Only the info search is used.
const (
	ODirErr       uint16 = 0x0001
	ODirInfoQuery uint16 = 0x0002
	ODirInfoReply uint16 = 0x0003
)

// ODir search/result TLV tags. The same tags are used to phrase a query and to
// carry each result's fields.
const (
	ODirTLVFirstName    uint16 = 0x0001
	ODirTLVLastName     uint16 = 0x0002
	ODirTLVCountry      uint16 = 0x0006
	ODirTLVState        uint16 = 0x0007
	ODirTLVCity         uint16 = 0x0008
	ODirTLVScreenName   uint16 = 0x0009
	ODirTLVEmailAddress uint16 = 0x0005
	ODirTLVInterest     uint16 = 0x000B
)

// ODir search result status codes (InfoReply.Status).
const (
	ODirStatusTooManyResults uint16 = 0x03 // narrow the search
	ODirStatusNameMissing    uint16 = 0x04 // a name search needs a first or last name
	ODirStatusOK             uint16 = 0x05 // search ran (zero or more results)
)

// SNAC_0x0F_0x02_InfoQuery phrases a directory search as a set of TLVs (e.g.
// first/last name). The server picks the search kind from which tags are present.
type SNAC_0x0F_0x02_InfoQuery struct {
	TLVRestBlock
}

// SNAC_0x0F_0x03_InfoReply carries the search status and each match as a TLV
// block of directory fields.
//
// On the wire it is Status, an unused uint16, then a uint16-count-prefixed list
// of result blocks. (The server models the list nested inside a struct tagged
// count_prefix, but that tag is a no-op on a struct in the oscar codec, so the
// bytes are exactly a single count-prefixed slice — which is what this mirrors.)
type SNAC_0x0F_0x03_InfoReply struct {
	Status  uint16
	Unused  uint16
	Results []TLVBlock `oscar:"count_prefix=uint16"`
}
