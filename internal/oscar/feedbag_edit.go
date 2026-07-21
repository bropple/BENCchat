package oscar

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/benco-holdings/benchat/internal/wire"
)

// ErrAlreadyBuddy reports an add of someone already on the list. It is a
// sentinel so callers (e.g. the approve-connection flow, which adds
// reciprocally) can treat "already there" as success rather than a failure.
var ErrAlreadyBuddy = errors.New("oscar: already on the buddy list")

// ErrNotABuddy is returned by edits that target a buddy who isn't on the list —
// including when the other party removed you, so your mirror no longer has them.
// Callers use errors.Is to reconcile that case rather than surfacing it as a
// failure.
var ErrNotABuddy = errors.New("not on your buddy list")

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
		return nil, fmt.Errorf("%q: %w", screenName, ErrAlreadyBuddy)
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
// ordering, cleaning up the group if that left it empty.
func (f *Feedbag) RemoveBuddy(screenName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bIdx := f.findBuddy(screenName)
	if bIdx < 0 {
		return nil, fmt.Errorf("oscar: %q is %w", screenName, ErrNotABuddy)
	}
	buddy := f.items[bIdx]

	ops := []editOp{
		{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{buddy}}},
	}
	f.items = removeAt(f.items, bIdx)
	ops = append(ops, f.pruneGroupMembership(buddy.GroupID, buddy.ItemID)...)
	return ops, nil
}

// pruneGroupMembership removes itemID from group groupID's member ordering. If
// that empties a NON-default group, the group is deleted and unlinked from the
// root, so removing the last buddy from a custom group doesn't leave an orphaned
// empty group behind. The default group is kept even when empty — it's where new
// buddies land. Returns the resulting edit ops and mutates the mirror.
func (f *Feedbag) pruneGroupMembership(groupID, itemID uint16) []editOp {
	gIdx := f.findGroupByID(groupID)
	if gIdx < 0 {
		return nil
	}
	grp := f.items[gIdx]
	grp.SetOrder(without(grp.Order(), itemID))

	if len(grp.Order()) == 0 && !strings.EqualFold(grp.Name, DefaultGroupName) {
		var ops []editOp
		if rIdx := f.rootIndex(); rIdx >= 0 {
			root := f.items[rIdx]
			root.SetOrder(without(root.Order(), groupID))
			f.items[rIdx] = root
			ops = append(ops, editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{root}}})
		}
		ops = append(ops, editOp{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{grp}}})
		if gj := f.findGroupByID(groupID); gj >= 0 {
			f.items = removeAt(f.items, gj)
		}
		return ops
	}

	f.items[gIdx] = grp
	return []editOp{{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{grp}}}}
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

// RenameGroup changes a group's display name. Members ride along automatically —
// they reference the group by id, and each buddy's .Group is derived from this
// name. Errors if the group is missing or if a DIFFERENT group already has the
// target name; a case-only change of the same group is allowed.
func (f *Feedbag) RenameGroup(oldName, newName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newName = strings.TrimSpace(newName)
	if newName == "" {
		return nil, fmt.Errorf("oscar: group name is required")
	}
	gIdx := f.findGroupByName(oldName)
	if gIdx < 0 {
		return nil, fmt.Errorf("oscar: no group named %q", oldName)
	}
	if gj := f.findGroupByName(newName); gj >= 0 && gj != gIdx {
		return nil, fmt.Errorf("oscar: a group named %q already exists", newName)
	}
	grp := f.items[gIdx]
	grp.Name = newName
	f.items[gIdx] = grp
	return []editOp{
		{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{grp}}},
	}, nil
}

// DeleteGroup removes an EMPTY group and unlinks it from the root. It refuses a
// non-empty group (move its members out first) and the default group. Deleting a
// non-empty group is done at a higher layer by moving members to the default,
// which auto-prunes the group; this handles a group that is already empty (e.g.
// one left orphaned before empty-group cleanup existed).
func (f *Feedbag) DeleteGroup(name string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if strings.EqualFold(strings.TrimSpace(name), DefaultGroupName) {
		return nil, fmt.Errorf("oscar: the default group cannot be deleted")
	}
	gIdx := f.findGroupByName(name)
	if gIdx < 0 {
		return nil, fmt.Errorf("oscar: no group named %q", name)
	}
	grp := f.items[gIdx]
	if len(grp.Order()) > 0 {
		return nil, fmt.Errorf("oscar: group %q is not empty", name)
	}
	var ops []editOp
	if rIdx := f.rootIndex(); rIdx >= 0 {
		root := f.items[rIdx]
		root.SetOrder(without(root.Order(), grp.GroupID))
		f.items[rIdx] = root
		ops = append(ops, editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{root}}})
	}
	ops = append(ops, editOp{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{grp}}})
	if gj := f.findGroupByName(name); gj >= 0 {
		f.items = removeAt(f.items, gj)
	}
	return ops, nil
}

// MoveBuddy moves an existing buddy to a different group WITHOUT severing the
// connection. A group change in OSCAR is a delete of the old row plus an insert
// under the target group; done in that order the server would see a bare buddy
// delete and revoke the connection (feedbag DeleteItem's mutual-removal). So the
// order is reversed here — insert the new row FIRST, then delete the old — which
// guarantees a row for this buddy always exists, and the server recognises it as
// a move rather than a removal. The alias and any pending tag ride along on the
// copied item.
func (f *Feedbag) MoveBuddy(screenName, newGroup string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newGroup = strings.TrimSpace(newGroup)
	if newGroup == "" {
		newGroup = DefaultGroupName
	}
	bIdx := f.findBuddy(screenName)
	if bIdx < 0 {
		return nil, fmt.Errorf("oscar: %q is %w", screenName, ErrNotABuddy)
	}
	old := f.items[bIdx]

	// Already in the target group: nothing to do.
	if gi := f.findGroupByID(old.GroupID); gi >= 0 && strings.EqualFold(f.items[gi].Name, newGroup) {
		return nil, nil
	}

	// The moved row keeps the buddy's TLVs (alias, pending) but takes a new item
	// id — and, below, the target group's id — since (group,item) is its identity.
	newItemID := f.nextItemID()
	moved := old
	moved.TLVList = append(wire.TLVList(nil), old.TLVList...)
	moved.ItemID = newItemID

	var ops []editOp

	// 1. Insert the buddy under the target group, creating the group if needed.
	if gIdx := f.findGroupByName(newGroup); gIdx >= 0 {
		moved.GroupID = f.items[gIdx].GroupID
		grp := f.items[gIdx]
		grp.SetOrder(append(grp.Order(), newItemID))
		f.items[gIdx] = grp
		f.items = append(f.items, moved)
		ops = append(ops,
			editOp{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{moved}}},
			editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{grp}}},
		)
	} else {
		gid := f.nextGroupID()
		moved.GroupID = gid
		grp := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: gid, ItemID: 0, Name: newGroup}
		grp.SetOrder([]uint16{newItemID})
		rIdx := f.rootIndex()
		root := f.items[rIdx]
		root.SetOrder(append(root.Order(), gid))
		f.items[rIdx] = root
		f.items = append(f.items, grp, moved)
		ops = append(ops,
			editOp{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{grp, moved}}},
			editOp{wire.FeedbagUpdateItem, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{root}}},
		)
	}

	// 2. Delete the old row, remove it from the mirror, then prune its old group
	// (which auto-deletes the group if this was its last member and it isn't the
	// default). Remove by original identity — the appends above shifted indices,
	// and the old row's name now matches the moved row too.
	ops = append(ops, editOp{wire.FeedbagDeleteItem, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{old}}})
	for i := range f.items {
		if f.items[i].IsBuddy() && f.items[i].GroupID == old.GroupID && f.items[i].ItemID == old.ItemID {
			f.items = removeAt(f.items, i)
			break
		}
	}
	ops = append(ops, f.pruneGroupMembership(old.GroupID, old.ItemID)...)

	return ops, nil
}

// ApplyServerUpsert merges server-pushed items into the mirror, keyed by their
// SSI identity (group id + item id, which is consistent across an account's
// sessions). An item already present is replaced; a new one is appended. Used to
// reflect edits made on another device — blocks, adds, renames, moves.
func (f *Feedbag) ApplyServerUpsert(items []wire.FeedbagItem) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, it := range items {
		if idx := f.indexByID(it.GroupID, it.ItemID); idx >= 0 {
			f.items[idx] = it
		} else {
			f.items = append(f.items, it)
		}
	}
}

// ApplyServerDelete removes server-pushed items from the mirror by SSI identity.
func (f *Feedbag) ApplyServerDelete(items []wire.FeedbagItem) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, it := range items {
		if idx := f.indexByID(it.GroupID, it.ItemID); idx >= 0 {
			f.items = removeAt(f.items, idx)
		}
	}
}

// indexByID finds an item by its SSI identity (group id + item id), the pair
// that uniquely identifies a feedbag row. Returns -1 when absent.
func (f *Feedbag) indexByID(groupID, itemID uint16) int {
	for i := range f.items {
		if f.items[i].GroupID == groupID && f.items[i].ItemID == itemID {
			return i
		}
	}
	return -1
}

// --- Session integration ---

// AddBuddy adds a buddy to the server-stored list and returns the updated list.
//
// The insert's request ID is tracked so a FeedbagStatusAuthRequired reply — the
// server refusing to store the buddy until they authorize — can be tied back to
// this screen name for the pending re-add (see ReAddBuddyPending).
func (s *Session) AddBuddy(screenName, group string) (BuddyList, error) {
	if s.feedbag == nil {
		return BuddyList{}, fmt.Errorf("oscar: buddy list not loaded")
	}
	ops, err := s.feedbag.AddBuddy(screenName, group)
	if err != nil {
		return BuddyList{}, err
	}
	if err := s.sendEditsTracking(ops, screenName); err != nil {
		return BuddyList{}, err
	}
	s.buddyList = s.feedbag.BuddyList()
	return s.buddyList, nil
}

// RemoveBuddy removes a buddy from the list.
func (s *Session) RemoveBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.RemoveBuddy(screenName) })
}

// RenameBuddy sets or clears a buddy's local alias.
func (s *Session) RenameBuddy(screenName, alias string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.RenameBuddy(screenName, alias) })
}

// MoveBuddy moves a buddy to a different group. The ops (insert-then-delete) are
// sent in order by sendEdits, which is what keeps the server from reading the
// move as a removal.
func (s *Session) MoveBuddy(screenName, newGroup string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.MoveBuddy(screenName, newGroup) })
}

// RenameGroup renames a buddy group.
func (s *Session) RenameGroup(oldName, newName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.RenameGroup(oldName, newName) })
}

// DeleteGroup removes an empty group.
func (s *Session) DeleteGroup(name string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.DeleteGroup(name) })
}

// BlockBuddy blocks a user.
func (s *Session) BlockBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.BlockBuddy(screenName) })
}

// UnblockBuddy unblocks a user.
func (s *Session) UnblockBuddy(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.UnblockBuddy(screenName) })
}

// ApplyServerUpsert merges a feedbag insert/update the server pushed from ANOTHER
// of this account's sessions (a buddy added, blocked, renamed or moved on another
// device) into the local mirror, and returns the updated list. No SNAC is sent —
// this is inbound reconciliation, not an edit.
func (s *Session) ApplyServerUpsert(items []wire.FeedbagItem) BuddyList {
	if s.feedbag == nil {
		return BuddyList{}
	}
	s.feedbag.ApplyServerUpsert(items)
	s.buddyList = s.feedbag.BuddyList()
	return s.buddyList
}

// ApplyServerDelete mirrors ApplyServerUpsert for a delete pushed from another
// session (a buddy removed or unblocked elsewhere).
func (s *Session) ApplyServerDelete(items []wire.FeedbagItem) BuddyList {
	if s.feedbag == nil {
		return BuddyList{}
	}
	s.feedbag.ApplyServerDelete(items)
	s.buddyList = s.feedbag.BuddyList()
	return s.buddyList
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
	return s.sendEditsTracking(ops, "")
}

// sendEditsTracking is sendEdits that, when trackName is set, records the
// request ID of the first InsertItem op (the one carrying the buddy) so its
// FeedbagStatus can later be matched. A single add inserts at most one buddy,
// so only the first insert is tracked.
func (s *Session) sendEditsTracking(ops []editOp, trackName string) error {
	for _, op := range ops {
		reqID, err := s.sendPaced(wire.Feedbag, op.subGroup, op.body)
		if err != nil {
			return fmt.Errorf("oscar: send feedbag edit (subgroup 0x%04x): %w", op.subGroup, err)
		}
		if trackName != "" && op.subGroup == wire.FeedbagInsertItem {
			s.recordAuthReq(reqID, trackName)
			trackName = ""
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
