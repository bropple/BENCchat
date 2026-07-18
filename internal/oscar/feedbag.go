package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// DefaultGroupName is what the buddy list shows for buddies whose group has no
// name, or no group item at all. AIM used this label for the same case.
const DefaultGroupName = "Buddies"

// BuddyEntry is one buddy-list row, flattened out of the feedbag tree.
type BuddyEntry struct {
	ScreenName string
	Group      string
	// Alias is the user's local nickname for this buddy, if set.
	Alias string
	// Blocked reports whether this buddy is on the deny list.
	Blocked bool
}

// BuddyList is a parsed feedbag: the buddies plus the group display order.
type BuddyList struct {
	Buddies []BuddyEntry
	// Groups is the group names in the order the list defines.
	Groups []string
	// Blocked is the normalized screen names on the deny list (may include
	// people who aren't buddies).
	Blocked []string
}

// LoadBuddyList fetches the feedbag and marks it in use.
//
// The FeedbagUse that follows the query is what tells the server our contacts
// are initialized. Without it we sign on but no buddy arrivals are ever
// delivered and nobody is told we came online — so the two steps belong
// together rather than being separately callable.
func (s *Session) LoadBuddyList() (BuddyList, error) {
	if err := s.Send(wire.Feedbag, wire.FeedbagQuery, nil); err != nil {
		return BuddyList{}, fmt.Errorf("oscar: send feedbag query: %w", err)
	}

	_, body, err := s.waitFor(wire.Feedbag, wire.FeedbagReply)
	if err != nil {
		return BuddyList{}, fmt.Errorf("oscar: awaiting feedbag reply: %w", err)
	}

	var reply wire.SNAC_0x13_0x06_FeedbagReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return BuddyList{}, fmt.Errorf("oscar: decode feedbag reply: %w", err)
	}

	// Keep the raw items in an editable mirror so buddy add/remove/rename can
	// build the right insert/update/delete SNACs later.
	s.feedbag = NewFeedbag(reply.Items)

	// FeedbagUse takes no body. It sets both "uses feedbag" and "contacts
	// initialized" server-side.
	if err := s.Send(wire.Feedbag, wire.FeedbagUse, nil); err != nil {
		return BuddyList{}, fmt.Errorf("oscar: send feedbag use: %w", err)
	}

	return s.feedbag.BuddyList(), nil
}

// ParseFeedbag reconstructs the buddy-list tree from a flat feedbag reply.
//
// The tree is a client-side convention — the server stores items verbatim and
// neither builds nor validates it:
//
//   - the root item (class Group, GroupID 0) lists group IDs in TLV 0x00C8,
//   - each group item (class Group, GroupID != 0) is named by Name,
//   - each buddy item (class Buddy) names its screen name and points at its
//     parent through GroupID.
//
// Items of other classes (permit, deny, prefs, icons) are ignored here.
func ParseFeedbag(reply wire.SNAC_0x13_0x06_FeedbagReply) BuddyList {
	return parseFeedbagItems(reply.Items)
}

// parseFeedbagItems is ParseFeedbag over a bare item slice, shared with the
// client-side editor which works directly with items.
func parseFeedbagItems(items []wire.FeedbagItem) BuddyList {
	groupNames := make(map[uint16]string)
	blocked := make(map[string]bool)
	var blockedList []string
	var root *wire.FeedbagItem

	for i := range items {
		item := &items[i]
		switch {
		case item.IsRoot():
			root = item
		case item.IsGroup():
			name := item.Name
			if name == "" {
				name = DefaultGroupName
			}
			groupNames[item.GroupID] = name
		case item.ClassID == wire.FeedbagClassIdDeny:
			key := normName(item.Name)
			if key != "" && !blocked[key] {
				blocked[key] = true
				blockedList = append(blockedList, key)
			}
		}
	}

	// Group display order comes from the root's ordering TLV. Groups the root
	// doesn't mention are appended afterwards rather than dropped — a buddy in an
	// unlisted group should still be visible.
	var order []string
	seen := make(map[string]bool)
	addGroup := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			order = append(order, name)
		}
	}
	if root != nil {
		if ids, ok := root.Uint16SliceBE(wire.FeedbagAttributesOrder); ok {
			for _, id := range ids {
				addGroup(groupNames[id])
			}
		}
	}
	for i := range items {
		if items[i].IsGroup() {
			addGroup(groupNames[items[i].GroupID])
		}
	}

	var buddies []BuddyEntry
	for i := range items {
		item := &items[i]
		if !item.IsBuddy() {
			continue
		}
		group, ok := groupNames[item.GroupID]
		if !ok {
			// A buddy whose group item is missing still belongs on the list.
			group = DefaultGroupName
			addGroup(group)
		}
		alias, _ := item.String(wire.FeedbagAttributesAlias)
		buddies = append(buddies, BuddyEntry{
			ScreenName: item.Name,
			Group:      group,
			Alias:      alias,
			Blocked:    blocked[normName(item.Name)],
		})
	}

	return BuddyList{Buddies: buddies, Groups: order, Blocked: blockedList}
}
