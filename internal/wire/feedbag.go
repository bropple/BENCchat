package wire

// FEEDBAG (0x0013) — the server-stored buddy list.

// Feedbag item class IDs (the "type" of a buddy-list row). Only the ones
// BENCchat acts on are named; the full set the server accepts is larger.
const (
	FeedbagClassIdPermit          uint16 = 0x0002
	FeedbagClassIdDeny            uint16 = 0x0003
	FeedbagClassIdPdinfo          uint16 = 0x0004
	FeedbagClassIdBuddyPrefs      uint16 = 0x0005
	FeedbagClassIdNonbuddy        uint16 = 0x0006
	FeedbagClassIdClientPrefs     uint16 = 0x0009
	FeedbagClassIdWatchList       uint16 = 0x000D
	FeedbagClassIdIgnoreList      uint16 = 0x000E
	FeedbagClassIdImportTimestamp uint16 = 0x0013
	FeedbagClassIdBart            uint16 = 0x0014
)

// Feedbag item attribute TLV tags.
const (
	// FeedbagAttributesOrder holds a packed uint16 array. On the root group it
	// lists group IDs in display order; on a group it lists that group's child
	// buddy item IDs. The whole buddy-list tree is expressed through this tag —
	// the server stores items verbatim and neither builds nor validates the tree.
	FeedbagAttributesOrder uint16 = 0x00C8
	// FeedbagAttributesAlias is a user-assigned local nickname for a buddy.
	FeedbagAttributesAlias uint16 = 0x0131
	// FeedbagAttributesPending marks a buddy awaiting authorization.
	FeedbagAttributesPending uint16 = 0x0066
	// FeedbagAttributesNote is a free-form note attached to a buddy.
	FeedbagAttributesNote uint16 = 0x013C
	// FeedbagAttributesPdMode holds the privacy mode (uint8) on the pdinfo item.
	FeedbagAttributesPdMode uint16 = 0x00CA
)

// Privacy (permit/deny) modes, stored as a uint8 in the pdinfo item's PdMode
// TLV. The mode governs how the permit/deny lists are applied.
const (
	FeedbagPDModePermitAll    uint8 = 0x01
	FeedbagPDModeDenyAll      uint8 = 0x02
	FeedbagPDModePermitSome   uint8 = 0x03
	FeedbagPDModeDenySome     uint8 = 0x04
	FeedbagPDModePermitOnList uint8 = 0x05
)

// FeedbagItem is one row of the buddy list.
//
// Note the two easily-confused prefixes: Name is uint16-length-prefixed (screen
// names everywhere else are uint8-prefixed), and the embedded TLVLBlock is a
// BYTE-LENGTH prefix — unlike TLVUserInfo's count prefix, which has the same
// wire width but different meaning.
//
//	uint16 nameLen | name | uint16 groupID | uint16 itemID | uint16 classID |
//	uint16 tlvByteLen | TLVs
type FeedbagItem struct {
	Name    string `oscar:"len_prefix=uint16"`
	GroupID uint16
	ItemID  uint16
	ClassID uint16
	TLVLBlock
}

// SNAC_0x13_0x06_FeedbagReply is the whole buddy list.
type SNAC_0x13_0x06_FeedbagReply struct {
	Version    uint8
	Items      []FeedbagItem `oscar:"count_prefix=uint16"`
	LastUpdate uint32
}

// SNAC_0x13_0x08_FeedbagInsertItem adds items to the server-stored list. The
// item list runs to the end of the SNAC (no count prefix).
type SNAC_0x13_0x08_FeedbagInsertItem struct {
	Items []FeedbagItem
}

// SNAC_0x13_0x09_FeedbagUpdateItem replaces existing items (matched by group +
// item ID). Used to rewrite a group's ordering TLV or a buddy's alias.
type SNAC_0x13_0x09_FeedbagUpdateItem struct {
	Items []FeedbagItem
}

// SNAC_0x13_0x0A_FeedbagDeleteItem removes items.
type SNAC_0x13_0x0A_FeedbagDeleteItem struct {
	Items []FeedbagItem
}

// SNAC_0x13_0x0E_FeedbagStatus is the server's per-item result for an
// insert/update/delete: one uint16 code per submitted item, in order.
type SNAC_0x13_0x0E_FeedbagStatus struct {
	Results []uint16
}

// Feedbag operation result codes (values in FeedbagStatus.Results).
const (
	FeedbagStatusSuccess      uint16 = 0x0000
	FeedbagStatusAuthRequired uint16 = 0x000E
)

// SNAC_0x13_0x02_FeedbagRightsQuery asks for list limits. The server parses the
// body and then ignores it entirely, so an empty block is fine.
type SNAC_0x13_0x02_FeedbagRightsQuery struct {
	TLVRestBlock
}

// SNAC_0x13_0x03_FeedbagRightsReply carries the list limits.
type SNAC_0x13_0x03_FeedbagRightsReply struct {
	TLVRestBlock
}

// IsRoot reports whether this item is the root group — the row whose Order TLV
// lists the group IDs. The root is identified by class Group with GroupID 0.
func (f FeedbagItem) IsRoot() bool {
	return f.ClassID == FeedbagClassIdGroup && f.GroupID == 0
}

// IsGroup reports whether this item is a (non-root) group.
func (f FeedbagItem) IsGroup() bool {
	return f.ClassID == FeedbagClassIdGroup && f.GroupID != 0
}

// IsBuddy reports whether this item is a buddy row.
func (f FeedbagItem) IsBuddy() bool { return f.ClassID == FeedbagClassIdBuddy }

// AppendOrder sets this item's ordering TLV (0x00C8) to the given IDs, packed
// as big-endian uint16s.
//
// On the root item these are group IDs; on a group item they are that group's
// child buddy item IDs. Adding a buddy means inserting the buddy item AND
// re-writing its parent group's order to include the new item ID — the server
// stores both verbatim and will not do it for you.
func (f *FeedbagItem) AppendOrder(ids []uint16) {
	f.Append(NewTLVBE(FeedbagAttributesOrder, packUint16s(ids)))
}

// SetOrder replaces this item's ordering TLV (0x00C8) with ids.
func (f *FeedbagItem) SetOrder(ids []uint16) {
	f.Set(NewTLVBE(FeedbagAttributesOrder, packUint16s(ids)))
}

// Order returns this item's ordering TLV as a slice of IDs (nil if unset).
func (f *FeedbagItem) Order() []uint16 {
	ids, _ := f.Uint16SliceBE(FeedbagAttributesOrder)
	return ids
}

// SetAlias sets (or, with an empty string, clears) the buddy's local alias.
func (f *FeedbagItem) SetAlias(alias string) {
	if alias == "" {
		f.Remove(FeedbagAttributesAlias)
		return
	}
	f.Set(NewTLVBE(FeedbagAttributesAlias, []byte(alias)))
}

func packUint16s(ids []uint16) []byte {
	b := make([]byte, 0, len(ids)*2)
	for _, id := range ids {
		b = append(b, byte(id>>8), byte(id))
	}
	return b
}
