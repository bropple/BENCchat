package oscar

import (
	"bytes"
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

// itemsOf collects every FeedbagItem across a sequence of edit ops, so tests can
// assert on exactly what would be sent to the server.
func insertedItems(ops []editOp) []wire.FeedbagItem {
	var out []wire.FeedbagItem
	for _, op := range ops {
		switch b := op.body.(type) {
		case wire.SNAC_0x13_0x08_FeedbagInsertItem:
			out = append(out, b.Items...)
		case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
			out = append(out, b.Items...)
		case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
			out = append(out, b.Items...)
		}
	}
	return out
}

func findBuddyEntry(bl BuddyList, screenName string) (BuddyEntry, bool) {
	for _, b := range bl.Buddies {
		if normName(b.ScreenName) == normName(screenName) {
			return b, true
		}
	}
	return BuddyEntry{}, false
}

// TestAddBuddyToEmptyListCreatesStructure is the bob case: a completely
// empty feedbag must grow a root, a group, and the buddy in one insert.
func TestAddBuddyToEmptyListCreatesStructure(t *testing.T) {
	fb := NewFeedbag(nil)

	ops, err := fb.AddBuddy("alice", "BENCO")
	if err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}

	items := insertedItems(ops)
	var root, group, buddy *wire.FeedbagItem
	for i := range items {
		switch {
		case items[i].IsRoot():
			root = &items[i]
		case items[i].IsGroup():
			group = &items[i]
		case items[i].IsBuddy():
			buddy = &items[i]
		}
	}
	if root == nil || group == nil || buddy == nil {
		t.Fatalf("expected root+group+buddy to be created, got %d items", len(items))
	}
	if group.Name != "BENCO" {
		t.Errorf("group name = %q, want BENCO", group.Name)
	}
	if buddy.Name != "alice" {
		t.Errorf("buddy name = %q, want alice", buddy.Name)
	}
	// The root must reference the group, and the group must reference the buddy.
	if ord := root.Order(); len(ord) != 1 || ord[0] != group.GroupID {
		t.Errorf("root order = %v, want [%d]", ord, group.GroupID)
	}
	if ord := group.Order(); len(ord) != 1 || ord[0] != buddy.ItemID {
		t.Errorf("group order = %v, want [%d]", ord, buddy.ItemID)
	}
	if buddy.GroupID != group.GroupID {
		t.Errorf("buddy GroupID %d != group GroupID %d", buddy.GroupID, group.GroupID)
	}
	// And the parsed list reflects it.
	if b, ok := findBuddyEntry(fb.BuddyList(), "alice"); !ok || b.Group != "BENCO" {
		t.Errorf("BuddyList missing alice in BENCO: %+v", fb.BuddyList())
	}
}

func TestEnsureBaseStructureThenAdd(t *testing.T) {
	fb := NewFeedbag(nil)

	base := fb.EnsureBaseStructure("Buddies")
	if len(base) == 0 {
		t.Fatal("EnsureBaseStructure should create structure for an empty list")
	}
	// A second call is a no-op — the structure already exists.
	if again := fb.EnsureBaseStructure("Buddies"); again != nil {
		t.Error("EnsureBaseStructure should be a no-op when a root exists")
	}

	// Adding into the existing default group must reuse it, not make a new one.
	// Only a fresh INSERT of a group counts as creation — re-sending the group in
	// an UPDATE to rewrite its order is expected.
	ops, err := fb.AddBuddy("alice", "Buddies")
	if err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}
	for _, op := range ops {
		if op.subGroup != wire.FeedbagInsertItem {
			continue
		}
		for _, it := range op.body.(wire.SNAC_0x13_0x08_FeedbagInsertItem).Items {
			if it.IsGroup() && !it.IsRoot() {
				t.Errorf("adding to an existing group should not insert another group (%q)", it.Name)
			}
		}
	}
	bl := fb.BuddyList()
	if len(bl.Groups) != 1 || bl.Groups[0] != "Buddies" {
		t.Errorf("groups = %v, want [Buddies]", bl.Groups)
	}
}

func TestAddBuddyUniqueItemIDs(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")

	if _, err := fb.AddBuddy("alice", "Buddies"); err != nil {
		t.Fatal(err)
	}
	if _, err := fb.AddBuddy("bob", "Buddies"); err != nil {
		t.Fatal(err)
	}

	// Both buddies must have distinct, non-zero item IDs, and the group order must
	// list both.
	fb.mu.Lock()
	defer fb.mu.Unlock()
	seen := map[uint16]bool{}
	var groupOrder []uint16
	for _, it := range fb.items {
		if it.IsBuddy() {
			if it.ItemID == 0 || seen[it.ItemID] {
				t.Errorf("duplicate or zero item ID %d", it.ItemID)
			}
			seen[it.ItemID] = true
		}
		if it.IsGroup() && !it.IsRoot() {
			groupOrder = it.Order()
		}
	}
	if len(groupOrder) != 2 {
		t.Errorf("group order = %v, want two buddies", groupOrder)
	}
}

func TestAddBuddyRejectsDuplicate(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	if _, err := fb.AddBuddy("alice", "Buddies"); err != nil {
		t.Fatal(err)
	}
	// Case/space-insensitive: "A L I C E" is the same account.
	if _, err := fb.AddBuddy("A L I C E", "Buddies"); err == nil {
		t.Error("expected duplicate add to be rejected")
	}
}

func TestRemoveBuddyUpdatesOrder(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("alice", "Buddies")
	fb.AddBuddy("bob", "Buddies")

	ops, err := fb.RemoveBuddy("alice")
	if err != nil {
		t.Fatalf("RemoveBuddy: %v", err)
	}
	// The delete must target alice, and a group update must drop her item ID.
	var deleted bool
	for _, op := range ops {
		if op.subGroup == wire.FeedbagDeleteItem {
			for _, it := range op.body.(wire.SNAC_0x13_0x0A_FeedbagDeleteItem).Items {
				if normName(it.Name) == "alice" {
					deleted = true
				}
			}
		}
	}
	if !deleted {
		t.Error("remove did not issue a delete for alice")
	}

	if _, ok := findBuddyEntry(fb.BuddyList(), "alice"); ok {
		t.Error("alice still present after removal")
	}
	if _, ok := findBuddyEntry(fb.BuddyList(), "bob"); !ok {
		t.Error("bob should remain after removing alice")
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()
	for _, it := range fb.items {
		if it.IsGroup() && !it.IsRoot() {
			if len(it.Order()) != 1 {
				t.Errorf("group order after removal = %v, want one entry", it.Order())
			}
		}
	}
}

func TestRemoveUnknownBuddyErrors(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	if _, err := fb.RemoveBuddy("ghost"); err == nil {
		t.Error("removing a non-buddy should error")
	}
}

func TestMoveBuddyChangesGroupInsertBeforeDelete(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("alice", "Buddies")
	fb.RenameBuddy("alice", "The User") // alias must survive the move

	ops, err := fb.MoveBuddy("alice", "Work")
	if err != nil {
		t.Fatalf("MoveBuddy: %v", err)
	}

	// Ordering is the whole point: the server tells a move from a removal by the
	// buddy still having a row after the delete, which only holds if the insert
	// is sent first. So the first InsertItem naming alice must precede the
	// DeleteItem naming alice.
	firstInsert, firstDelete := -1, -1
	for i, op := range ops {
		switch op.subGroup {
		case wire.FeedbagInsertItem:
			for _, it := range op.body.(wire.SNAC_0x13_0x08_FeedbagInsertItem).Items {
				if it.IsBuddy() && normName(it.Name) == "alice" && firstInsert == -1 {
					firstInsert = i
				}
			}
		case wire.FeedbagDeleteItem:
			for _, it := range op.body.(wire.SNAC_0x13_0x0A_FeedbagDeleteItem).Items {
				if it.IsBuddy() && normName(it.Name) == "alice" && firstDelete == -1 {
					firstDelete = i
				}
			}
		}
	}
	if firstInsert == -1 || firstDelete == -1 {
		t.Fatalf("move should both insert and delete alice; insert=%d delete=%d", firstInsert, firstDelete)
	}
	if firstInsert >= firstDelete {
		t.Errorf("insert (op %d) must come before delete (op %d) or the server reads a move as a removal", firstInsert, firstDelete)
	}

	// Final state: exactly one alice, in Work, alias intact.
	b, ok := findBuddyEntry(fb.BuddyList(), "alice")
	if !ok {
		t.Fatal("alice missing after move")
	}
	if b.Group != "Work" {
		t.Errorf("alice group = %q, want Work", b.Group)
	}
	if b.Alias != "The User" {
		t.Errorf("alias lost in move: %q", b.Alias)
	}
	// No stray duplicate left behind in the old group.
	count := 0
	for _, e := range fb.BuddyList().Buddies {
		if normName(e.ScreenName) == "alice" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("alice appears %d times after move, want 1", count)
	}
}

func TestMoveBuddyToSameGroupIsNoop(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("alice", "Buddies")
	ops, err := fb.MoveBuddy("alice", "Buddies")
	if err != nil {
		t.Fatalf("MoveBuddy: %v", err)
	}
	if len(ops) != 0 {
		t.Errorf("moving to the same group should be a no-op, got %d ops", len(ops))
	}
}

func TestRenameBuddySetsAlias(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("alice", "Buddies")

	ops, err := fb.RenameBuddy("alice", "The User")
	if err != nil {
		t.Fatalf("RenameBuddy: %v", err)
	}
	items := insertedItems(ops)
	if len(items) != 1 {
		t.Fatalf("rename should update one item, got %d", len(items))
	}
	if alias, _ := items[0].String(wire.FeedbagAttributesAlias); alias != "The User" {
		t.Errorf("alias TLV = %q, want The User", alias)
	}
	if b, _ := findBuddyEntry(fb.BuddyList(), "alice"); b.Alias != "The User" {
		t.Errorf("BuddyList alias = %q", b.Alias)
	}

	// Clearing the alias removes the TLV.
	ops, _ = fb.RenameBuddy("alice", "")
	if alias, ok := insertedItems(ops)[0].String(wire.FeedbagAttributesAlias); ok && alias != "" {
		t.Errorf("cleared alias should remove the TLV, got %q", alias)
	}
}

// TestEditedFeedbagReparsesConsistently round-trips the edited items through the
// same decode path the server would use, catching any malformed item.
func TestEditedFeedbagReparsesConsistently(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("alice", "Work")
	fb.AddBuddy("bob", "Work")
	fb.AddBuddy("carol", "Family")

	fb.mu.Lock()
	items := cloneItems(fb.items)
	fb.mu.Unlock()

	// Marshal every item as the server would receive it, then decode it back.
	reply := wire.SNAC_0x13_0x06_FeedbagReply{Items: items}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(reply, buf); err != nil {
		t.Fatalf("marshal edited feedbag: %v", err)
	}
	var decoded wire.SNAC_0x13_0x06_FeedbagReply
	if err := wire.UnmarshalBE(&decoded, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("edited feedbag failed to re-decode: %v", err)
	}
	bl := ParseFeedbag(decoded)
	if len(bl.Buddies) != 3 {
		t.Fatalf("buddy count after round trip = %d, want 3", len(bl.Buddies))
	}
	for _, name := range []string{"alice", "bob", "carol"} {
		if _, ok := findBuddyEntry(bl, name); !ok {
			t.Errorf("%q missing after round trip", name)
		}
	}
}

// --- blocking ---

func TestBlockBuddyCreatesPdinfoAndDeny(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")

	ops, err := fb.BlockBuddy("meanie")
	if err != nil {
		t.Fatalf("BlockBuddy: %v", err)
	}

	var pdinfo, deny *wire.FeedbagItem
	for _, it := range insertedItems(ops) {
		c := it
		switch it.ClassID {
		case wire.FeedbagClassIdPdinfo:
			pdinfo = &c
		case wire.FeedbagClassIdDeny:
			deny = &c
		}
	}
	if pdinfo == nil {
		t.Fatal("blocking should create a pdinfo item")
	}
	if mode, _ := pdinfo.Uint8(wire.FeedbagAttributesPdMode); mode != wire.FeedbagPDModeDenySome {
		t.Errorf("privacy mode = 0x%02x, want DenySome (a deny entry does nothing under permit-all)", mode)
	}
	if deny == nil || deny.Name != "meanie" {
		t.Fatalf("blocking should add a deny item for the user, got %+v", deny)
	}

	bl := fb.BuddyList()
	if len(bl.Blocked) != 1 || bl.Blocked[0] != "meanie" {
		t.Errorf("Blocked = %v, want [meanie]", bl.Blocked)
	}
}

func TestBlockThenUnblock(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	if _, err := fb.BlockBuddy("meanie"); err != nil {
		t.Fatal(err)
	}
	if _, err := fb.BlockBuddy("meanie"); err == nil {
		t.Error("double-block should error")
	}

	ops, err := fb.UnblockBuddy("meanie")
	if err != nil {
		t.Fatalf("UnblockBuddy: %v", err)
	}
	found := false
	for _, op := range ops {
		if op.subGroup == wire.FeedbagDeleteItem {
			found = true
		}
	}
	if !found {
		t.Error("unblock should delete the deny item")
	}
	if len(fb.BuddyList().Blocked) != 0 {
		t.Error("no one should be blocked after unblock")
	}
}

func TestBlockBuddyOnList(t *testing.T) {
	fb := NewFeedbag(nil)
	fb.EnsureBaseStructure("Buddies")
	fb.AddBuddy("rtriy", "Buddies")
	fb.BlockBuddy("rtriy")

	for _, b := range fb.BuddyList().Buddies {
		if normName(b.ScreenName) == "rtriy" && !b.Blocked {
			t.Error("a blocked buddy should be marked Blocked in the list")
		}
	}
}
