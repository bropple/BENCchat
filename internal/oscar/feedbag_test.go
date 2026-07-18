package oscar

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

// buildFeedbag assembles a reply the way the server would.
func rootItem(groupIDs ...uint16) wire.FeedbagItem {
	it := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 0, ItemID: 0}
	it.AppendOrder(groupIDs)
	return it
}

func groupItem(id uint16, name string, childIDs ...uint16) wire.FeedbagItem {
	it := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: id, Name: name}
	it.AppendOrder(childIDs)
	return it
}

func buddyItem(groupID, itemID uint16, name string) wire.FeedbagItem {
	return wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: groupID, ItemID: itemID, Name: name}
}

func TestParseFeedbagBuildsTree(t *testing.T) {
	reply := wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(2, 1), // root lists Work before Family
		groupItem(1, "Family", 10),
		groupItem(2, "Work", 20, 21),
		buddyItem(1, 10, "mom"),
		buddyItem(2, 20, "boss"),
		buddyItem(2, 21, "coworker"),
	}}

	got := ParseFeedbag(reply)

	// Group order must follow the root's ordering TLV, not item order.
	wantGroups := []string{"Work", "Family"}
	if len(got.Groups) != len(wantGroups) {
		t.Fatalf("groups = %v, want %v", got.Groups, wantGroups)
	}
	for i := range wantGroups {
		if got.Groups[i] != wantGroups[i] {
			t.Fatalf("groups = %v, want %v", got.Groups, wantGroups)
		}
	}

	if len(got.Buddies) != 3 {
		t.Fatalf("buddy count = %d, want 3", len(got.Buddies))
	}
	byName := map[string]BuddyEntry{}
	for _, b := range got.Buddies {
		byName[b.ScreenName] = b
	}
	if byName["mom"].Group != "Family" {
		t.Errorf("mom's group = %q, want Family", byName["mom"].Group)
	}
	if byName["boss"].Group != "Work" {
		t.Errorf("boss's group = %q, want Work", byName["boss"].Group)
	}
}

func TestParseFeedbagAlias(t *testing.T) {
	buddy := buddyItem(1, 10, "rtriy")
	buddy.Append(wire.NewTLVBE(wire.FeedbagAttributesAlias, []byte("R. Triy")))

	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(1), groupItem(1, "BENCO", 10), buddy,
	}})

	if len(got.Buddies) != 1 || got.Buddies[0].Alias != "R. Triy" {
		t.Fatalf("alias not parsed: %+v", got.Buddies)
	}
}

// TestParseFeedbagOrphanBuddy covers a buddy whose group item is missing. It
// must still appear rather than vanish from the list.
func TestParseFeedbagOrphanBuddy(t *testing.T) {
	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(),
		buddyItem(99, 10, "orphan"), // no group item with ID 99
	}})

	if len(got.Buddies) != 1 {
		t.Fatalf("buddy count = %d, want 1 (orphan must not be dropped)", len(got.Buddies))
	}
	if got.Buddies[0].Group != DefaultGroupName {
		t.Errorf("orphan group = %q, want %q", got.Buddies[0].Group, DefaultGroupName)
	}
	// The synthesized group must be present in the order, or the UI has a buddy
	// pointing at a group it never heard of.
	if len(got.Groups) != 1 || got.Groups[0] != DefaultGroupName {
		t.Errorf("groups = %v, want [%s]", got.Groups, DefaultGroupName)
	}
}

// TestParseFeedbagUnnamedGroup covers the server's empty-name group.
func TestParseFeedbagUnnamedGroup(t *testing.T) {
	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(1), groupItem(1, "", 10), buddyItem(1, 10, "someone"),
	}})

	if len(got.Buddies) != 1 || got.Buddies[0].Group != DefaultGroupName {
		t.Fatalf("unnamed group should display as %q, got %+v", DefaultGroupName, got.Buddies)
	}
}

// TestParseFeedbagGroupMissingFromRootOrder ensures a group the root doesn't
// mention still shows up.
func TestParseFeedbagGroupMissingFromRootOrder(t *testing.T) {
	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(1), // root only mentions group 1
		groupItem(1, "Listed", 10),
		groupItem(2, "Unlisted", 20),
		buddyItem(1, 10, "a"),
		buddyItem(2, 20, "b"),
	}})

	if len(got.Groups) != 2 {
		t.Fatalf("groups = %v, want both Listed and Unlisted", got.Groups)
	}
	if got.Groups[0] != "Listed" || got.Groups[1] != "Unlisted" {
		t.Errorf("groups = %v, want ordered [Listed Unlisted]", got.Groups)
	}
}

// TestParseFeedbagIgnoresNonBuddyClasses ensures permit/deny/prefs rows don't
// leak into the buddy list.
func TestParseFeedbagIgnoresNonBuddyClasses(t *testing.T) {
	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{
		rootItem(1),
		groupItem(1, "BENCO", 10),
		buddyItem(1, 10, "real"),
		{ClassID: wire.FeedbagClassIdDeny, Name: "blocked-guy", ItemID: 30},
		{ClassID: wire.FeedbagClassIdPdinfo, ItemID: 31},
		{ClassID: wire.FeedbagClassIdBuddyPrefs, ItemID: 32},
	}})

	if len(got.Buddies) != 1 || got.Buddies[0].ScreenName != "real" {
		t.Fatalf("non-buddy classes leaked into the list: %+v", got.Buddies)
	}
}

func TestParseFeedbagEmpty(t *testing.T) {
	got := ParseFeedbag(wire.SNAC_0x13_0x06_FeedbagReply{})
	if len(got.Buddies) != 0 || len(got.Groups) != 0 {
		t.Fatalf("empty feedbag should yield an empty list, got %+v", got)
	}
}
