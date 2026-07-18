package oscar

import (
	"fmt"
	"strings"
	"sync"

	"github.com/benco-holdings/benchat/internal/wire"
)

// Feedbag is a client-side mirror of the server-stored buddy list, holding the
// raw items with their group/item IDs so edits can be expressed as the
// insert/update/delete SNACs the server expects.
//
// The buddy-list tree is a client convention the server does not maintain:
// adding a buddy means inserting the buddy item AND rewriting its parent
// group's ordering TLV (and creating the root/group when the list is empty).
// This type encapsulates that bookkeeping and emits the exact operations to send.
type Feedbag struct {
	mu    sync.Mutex
	items []wire.FeedbagItem
}

// NewFeedbag builds an editor over a copy of the loaded items.
func NewFeedbag(items []wire.FeedbagItem) *Feedbag {
	return &Feedbag{items: cloneItems(items)}
}

// editOp is one SNAC to send: an insert, update, or delete subgroup + body.
type editOp struct {
	subGroup uint16
	body     any
}

// BuddyList returns the current parsed list.
func (f *Feedbag) BuddyList() BuddyList {
	f.mu.Lock()
	defer f.mu.Unlock()
	return parseFeedbagItems(f.items)
}

// EnsureBaseStructure creates the list root and a default group when the feedbag
// is empty, returning the operations to persist them (nil if a root already
// exists). A fresh account has no server-stored list at all; without this the
// user would face a structureless list until their first add, and some AIM
// clients mishandle a rootless feedbag.
func (f *Feedbag) EnsureBaseStructure(defaultGroup string) []editOp {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.rootIndex() >= 0 {
		return nil
	}
	gid := f.nextGroupID()
	root := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 0, ItemID: 0}
	root.SetOrder([]uint16{gid})
	grp := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: gid, ItemID: 0, Name: defaultGroup}

	f.items = append(f.items, root, grp)
	return []editOp{
		{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{root, grp}}},
	}
}

// AddBuddy adds screenName to group, creating the group (and the list root) if
// they don't exist yet. It returns the operations to send, or an error if the
// buddy is already present.
func (f *Feedbag) AddBuddy(screenName, group string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return nil, fmt.Errorf("oscar: screen name is required")
	}
	if group == "" {
		group = DefaultGroupName
	}
	if f.findBuddy(screenName) >= 0 {
		return nil, fmt.Errorf("oscar: %q is already on your buddy list", screenName)
	}

	itemID := f.nextItemID()
	gIdx := f.findGroupByName(group)

	if gIdx >= 0 {
		// Existing group: insert the buddy, extend the group's ordering.
		gid := f.items[gIdx].GroupID
		buddy := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: gid, ItemID: itemID, Name: screenName}
		grp := f.items[gIdx]
		grp.SetOrder(append(grp.Order(), itemID))
		f.items[gIdx] = grp
		f.items = append(f.items, buddy)
		return []editOp{
			{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{buddy}}},
			{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{grp}}},
		}, nil
	}

	// New group. Build the group and buddy, and attach the group to the root —
	// creating the root itself when the list is completely empty.
	gid := f.nextGroupID()
	grp := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: gid, ItemID: 0, Name: group}
	grp.SetOrder([]uint16{itemID})
	buddy := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: gid, ItemID: itemID, Name: screenName}

	insert := []wire.FeedbagItem{grp, buddy}
	var ops []editOp

	rIdx := f.rootIndex()
	if rIdx < 0 {
		// Empty list: the root must be created too, listing the new group.
		root := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 0, ItemID: 0}
		root.SetOrder([]uint16{gid})
		insert = append([]wire.FeedbagItem{root}, insert...)
		f.items = append(f.items, root)
		ops = []editOp{{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: append([]wire.FeedbagItem(nil), insert...)}}}
	} else {
		root := f.items[rIdx]
		root.SetOrder(append(root.Order(), gid))
		f.items[rIdx] = root
		ops = []editOp{
			{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: append([]wire.FeedbagItem(nil), insert...)}},
			{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{root}}},
		}
	}
	f.items = append(f.items, grp, buddy)
	return ops, nil
}

// RemoveBuddy deletes screenName from the list and drops it from its group's
// ordering.
func (f *Feedbag) RemoveBuddy(screenName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bIdx := f.findBuddy(screenName)
	if bIdx < 0 {
		return nil, fmt.Errorf("oscar: %q is not on your buddy list", screenName)
	}
	buddy := f.items[bIdx]

	ops := []editOp{
		{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{buddy}}},
	}

	// Drop the buddy from its group's ordering, if the group is present.
	if gIdx := f.findGroupByID(buddy.GroupID); gIdx >= 0 {
		grp := f.items[gIdx]
		grp.SetOrder(without(grp.Order(), buddy.ItemID))
		f.items[gIdx] = grp
		ops = append(ops, editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{grp}}})
	}

	f.items = removeAt(f.items, bIdx)
	return ops, nil
}

// BlockBuddy blocks a user: it adds a deny item and ensures the privacy mode is
// "deny listed users" so the deny list is actually enforced. Blocking hides
// presence both ways and rejects messages in both directions.
func (f *Feedbag) BlockBuddy(screenName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return nil, fmt.Errorf("oscar: screen name is required")
	}
	if f.findDeny(screenName) >= 0 {
		return nil, fmt.Errorf("oscar: %q is already blocked", screenName)
	}

	var ops []editOp

	// Ensure the privacy mode enforces the deny list. An empty/absent pdinfo item
	// defaults to permit-all, under which a deny entry does nothing.
	if pi := f.findPdinfo(); pi < 0 {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdPdinfo, GroupID: 0, ItemID: f.nextItemID()}
		item.Set(wire.NewTLVBE(wire.FeedbagAttributesPdMode, wire.FeedbagPDModeDenySome))
		f.items = append(f.items, item)
		ops = append(ops, editOp{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{item}}})
	} else if mode, _ := f.items[pi].Uint8(wire.FeedbagAttributesPdMode); mode == 0 || mode == wire.FeedbagPDModePermitAll {
		item := f.items[pi]
		item.Set(wire.NewTLVBE(wire.FeedbagAttributesPdMode, wire.FeedbagPDModeDenySome))
		f.items[pi] = item
		ops = append(ops, editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{item}}})
	}

	deny := wire.FeedbagItem{ClassID: wire.FeedbagClassIdDeny, GroupID: 0, ItemID: f.nextItemID(), Name: screenName}
	f.items = append(f.items, deny)
	ops = append(ops, editOp{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{deny}}})
	return ops, nil
}

// UnblockBuddy removes a user's deny item. The privacy mode is left as-is — an
// empty deny list under "deny some" simply blocks no one.
func (f *Feedbag) UnblockBuddy(screenName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	i := f.findDeny(screenName)
	if i < 0 {
		return nil, fmt.Errorf("oscar: %q is not blocked", screenName)
	}
	deny := f.items[i]
	f.items = removeAt(f.items, i)
	return []editOp{
		{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{deny}}},
	}, nil
}

// RenameBuddy sets (or clears, with an empty alias) a buddy's local nickname.
func (f *Feedbag) RenameBuddy(screenName, alias string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bIdx := f.findBuddy(screenName)
	if bIdx < 0 {
		return nil, fmt.Errorf("oscar: %q is not on your buddy list", screenName)
	}
	buddy := f.items[bIdx]
	buddy.SetAlias(alias)
	f.items[bIdx] = buddy
	return []editOp{
		{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{buddy}}},
	}, nil
}

// --- Session integration ---

// AddBuddy adds a buddy to the server-stored list and returns the updated list.
func (s *Session) AddBuddy(screenName, group string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.AddBuddy(screenName, group) })
}

// RemoveBuddy removes a buddy from the list.
func (s *Session) RemoveBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.RemoveBuddy(screenName) })
}

// RenameBuddy sets or clears a buddy's local alias.
func (s *Session) RenameBuddy(screenName, alias string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.RenameBuddy(screenName, alias) })
}

// BlockBuddy blocks a user.
func (s *Session) BlockBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.BlockBuddy(screenName) })
}

// UnblockBuddy unblocks a user.
func (s *Session) UnblockBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.UnblockBuddy(screenName) })
}

// applyEdit runs a feedbag mutation, sends the resulting SNACs, and returns the
// updated list. The edit is optimistic: the local mirror is authoritative and
// the server's FeedbagStatus is observed asynchronously by the read loop.
func (s *Session) applyEdit(mutate func() ([]editOp, error)) (BuddyList, error) {
	if s.feedbag == nil {
		return BuddyList{}, fmt.Errorf("oscar: buddy list not loaded")
	}
	ops, err := mutate()
	if err != nil {
		return BuddyList{}, err
	}
	if err := s.sendEdits(ops); err != nil {
		return BuddyList{}, err
	}
	s.buddyList = s.feedbag.BuddyList()
	return s.buddyList, nil
}

// sendEdits transmits a sequence of feedbag edit SNACs in order.
func (s *Session) sendEdits(ops []editOp) error {
	for _, op := range ops {
		if err := s.Send(wire.Feedbag, op.subGroup, op.body); err != nil {
			return fmt.Errorf("oscar: send feedbag edit (subgroup 0x%04x): %w", op.subGroup, err)
		}
	}
	return nil
}

// --- internal helpers (all assume the lock is held) ---

func (f *Feedbag) rootIndex() int {
	for i := range f.items {
		if f.items[i].IsRoot() {
			return i
		}
	}
	return -1
}

func (f *Feedbag) findGroupByName(name string) int {
	for i := range f.items {
		if f.items[i].IsGroup() && strings.EqualFold(f.items[i].Name, name) {
			return i
		}
	}
	return -1
}

func (f *Feedbag) findGroupByID(gid uint16) int {
	for i := range f.items {
		if f.items[i].IsGroup() && f.items[i].GroupID == gid {
			return i
		}
	}
	return -1
}

func (f *Feedbag) findBuddy(screenName string) int {
	want := normName(screenName)
	for i := range f.items {
		if f.items[i].IsBuddy() && normName(f.items[i].Name) == want {
			return i
		}
	}
	return -1
}

func (f *Feedbag) findDeny(screenName string) int {
	want := normName(screenName)
	for i := range f.items {
		if f.items[i].ClassID == wire.FeedbagClassIdDeny && normName(f.items[i].Name) == want {
			return i
		}
	}
	return -1
}

func (f *Feedbag) findPdinfo() int {
	for i := range f.items {
		if f.items[i].ClassID == wire.FeedbagClassIdPdinfo {
			return i
		}
	}
	return -1
}

// nextItemID returns an item ID not currently in use. Item IDs must be unique
// within the list; allocating above the current maximum guarantees that.
func (f *Feedbag) nextItemID() uint16 {
	var max uint16
	for i := range f.items {
		if !f.items[i].IsGroup() && f.items[i].ItemID > max {
			max = f.items[i].ItemID
		}
	}
	return max + 1
}

// nextGroupID returns a group ID not currently in use.
func (f *Feedbag) nextGroupID() uint16 {
	var max uint16
	for i := range f.items {
		if f.items[i].GroupID > max {
			max = f.items[i].GroupID
		}
	}
	return max + 1
}

func normName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

func without(ids []uint16, id uint16) []uint16 {
	out := ids[:0]
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

func removeAt(items []wire.FeedbagItem, i int) []wire.FeedbagItem {
	return append(items[:i], items[i+1:]...)
}

// cloneItems deep-copies items so edits to the mirror can't alias the caller's
// slices — the TLV lists inside are reference types.
func cloneItems(items []wire.FeedbagItem) []wire.FeedbagItem {
	out := make([]wire.FeedbagItem, len(items))
	for i, it := range items {
		out[i] = it
		out[i].TLVList = append(wire.TLVList(nil), it.TLVList...)
	}
	return out
}
