package main

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
)

// TestReformedRoomNameIsUnguessable: the new room's name is the only thing
// keeping the person left behind from following, since OSCAR has no join
// control. It must be random, and repeated reforms must not pile up suffixes.
func TestReformedRoomNameIsUnguessable(t *testing.T) {
	const base = "project-planning"

	first, err := reformedRoomName(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, base+"-x") {
		t.Fatalf("name %q should keep the original as a prefix", first)
	}
	if first == base {
		t.Fatal("reformed name is identical to the original")
	}

	// Random: two reforms of the same room must differ.
	second, _ := reformedRoomName(base)
	if first == second {
		t.Fatal("two reformed names collided — the name is predictable")
	}

	// Reforming a reformed room replaces the suffix rather than appending.
	third, _ := reformedRoomName(first)
	if strings.Count(third, "-x") != 1 {
		t.Errorf("suffixes accumulated across reforms: %q", third)
	}
	if len(third) != len(first) {
		t.Errorf("reformed-of-reformed changed length: %q vs %q", third, first)
	}

	// Room names travel through OSCAR and become part of the cookie, so keep to
	// characters that can't need escaping.
	for _, r := range third {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-", r) {
			t.Errorf("reformed name %q contains %q, which may not survive the wire", third, r)
		}
	}
}

// TestRoomMembersTracksDeliberateInvitesOnly is the guard on the rule that
// rotation redistributes to people we INVITED, never to whoever happens to be
// in the room — otherwise an uninvited walk-in would be handed a key the moment
// anybody left.
func TestRoomMembersTracksDeliberateInvitesOnly(t *testing.T) {
	var m roomMembers
	m.add("room-1", "bob")
	m.add("room-1", "ALICE") // casing must not create a second entry
	m.add("room-2", "someone-else")

	got := m.list("room-1")
	if len(got) != 2 {
		t.Fatalf("room-1 members = %v, want 2", got)
	}
	m.add("room-1", "alice")
	if len(m.list("room-1")) != 2 {
		t.Error("re-inviting the same person created a duplicate")
	}

	m.remove("room-1", "BOB")
	if len(m.list("room-1")) != 1 {
		t.Error("remove did not normalize the screen name")
	}
	if len(m.list("room-2")) != 1 {
		t.Error("rooms are not isolated from each other")
	}

	m.forget("room-1")
	if len(m.list("room-1")) != 0 {
		t.Error("forget left members behind")
	}
	if len(m.list("never-seen")) != 0 {
		t.Error("an unknown room reported members")
	}
}

// TestOnlyInvitedMembersAreServedHistory is the access check on catch-up.
//
// Rooms are joinable by name with no permission check, so being present proves
// nothing. History is exactly what we withheld from an uninvited joiner by not
// giving them the key — serving it on request would hand it over anyway.
func TestOnlyInvitedMembersAreServedHistory(t *testing.T) {
	a := &App{}
	a.members.add("4-0-room", "bob")

	if !a.isRoomMember("4-0-room", "bob") {
		t.Error("an invited member was not recognized")
	}
	if !a.isRoomMember("4-0-room", "BOB") {
		t.Error("member check is case-sensitive; screen names are not")
	}
	if a.isRoomMember("4-0-room", "randomjoiner") {
		t.Error("an uninvited joiner would be served room history")
	}
	if a.isRoomMember("4-0-otherroom", "bob") {
		t.Error("membership leaked between rooms")
	}
}

// TestRoomKeyRotationOnlyFromMembers: an invite naming a room we are already in
// is applied as a rotation, which changes the key we SEND under. Arriving over
// the encrypted 1:1 channel proves nothing about room membership — peer keys are
// fetched on demand for any account — so a stranger who learns the room name
// must not be able to redirect our traffic onto a key they hold.
func TestRoomKeyRotationOnlyFromMembers(t *testing.T) {
	store := state.NewStore()
	a := &App{store: store, client: client.New(store, nil)}
	store.UpsertRoom("room-1", "secret room")
	store.SetRoomJoined("room-1", true)
	a.client.MarkRoomEncrypted("room-1")
	a.members.add("room-1", "alice") // alice gave us this room's chains

	attacker, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	a.handleRoomInvite("mallory", e2ee.RoomInvite{
		Room:   "secret room",
		Chains: []e2ee.ChainView{attacker.View()},
	})
	if _, ok := a.client.ChainViews("room-1")[attacker.ID]; ok {
		t.Error("a non-member's chain was installed — their messages would read as the room's")
	}

	// The person who invited us can still hand over chains.
	legit, _ := e2ee.NewChain()
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:   "secret room",
		Chains: []e2ee.ChainView{legit.View()},
	})
	if _, ok := a.client.ChainViews("room-1")[legit.ID]; !ok {
		t.Error("a legitimate chain from the member who invited us was rejected")
	}
}

// rosterTestApp is an App wired just enough to drive the room roster paths.
func rosterTestApp(t *testing.T, self string) *App {
	t.Helper()
	store := state.NewStore()
	a := &App{store: store, client: client.New(store, nil)}
	a.cfg.LastScreenName = self
	store.UpsertRoom("room-1", "secret room")
	store.SetRoomJoined("room-1", true)
	return a
}

// chainWasReplaced reports whether the room's outbound chain is due for
// replacement — the observable effect of a removal now that re-keying is lazy.
// Calling this performs the replacement, so assert with it last.
func chainWasReplaced(a *App, cookie, before string) bool {
	view, fresh, err := a.client.EnsureOutboundChain(cookie)
	return err == nil && fresh && view.ID != before
}

func sortedMembers(a *App, cookie string) string {
	got := a.members.list(cookie)
	sort.Strings(got)
	return strings.Join(got, ",")
}

// TestRosterFromInviteReachesEveryMember is the three-way bug.
//
// Membership used to be recorded only for people WE invited, so in a room where
// Alice invited both Bob and Carol, Carol knew only Alice. A rotation by Carol
// then reached nobody but Alice, and Bob silently lost the room. The roster
// travelling with the key is what closes that.
func TestRosterFromInviteReachesEveryMember(t *testing.T) {
	a := rosterTestApp(t, "carol")
	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey: %v", err)
	}
	a.client.SetRoomKey("room-1", key)
	a.members.add("room-1", "alice") // all we learn from being invited

	if got := sortedMembers(a, "room-1"); got != "alice" {
		t.Fatalf("precondition: members = %q", got)
	}

	// Alice adds Dave and tells the whole room. Same key, so this is a roster
	// announcement rather than a rotation.
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:    "secret room",
		Key:     key,
		Members: []string{"alice", "bob", "carol", "dave"},
	})

	// Everyone but ourselves — a.members means "other people holding this key".
	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Errorf("members = %q, want %q", got, "alice,bob,dave")
	}
	if cur, ok := a.client.RoomKey("room-1"); !ok || cur.ID() != key.ID() {
		t.Error("a roster announcement changed the room key")
	}
}

// TestRotationRosterPropagatesRemoval: a rotation is authoritative about who
// holds the key it carries, so it REPLACES the roster. This is the mechanism by
// which a removal actually reaches the rest of the room.
func TestRotationRosterPropagatesRemoval(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	fresh, _ := e2ee.NewChain()
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:    "secret room",
		Chains:  []e2ee.ChainView{fresh.View()},
		Members: []string{"alice", "bob", "carol"}, // dave is out
	})

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want %q — a removal did not propagate", got, "alice,bob")
	}
	if _, ok := a.client.ChainViews("room-1")[fresh.ID]; !ok {
		t.Error("the re-keyed chain was not installed")
	}
}

// TestSameKeyRosterUnionsRatherThanReplaces: two people inviting at once must
// not erase each other's newcomer. Only a rotation replaces.
func TestSameKeyRosterUnionsRatherThanReplaces(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	// We invited Eve a moment ago; Alice has not heard about her yet.
	a.members.setAll("room-1", []string{"alice", "eve"}, "carol")

	// A roster-only invite: no chains, so this is somebody announcing an ADD.
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:    "secret room",
		Members: []string{"alice", "carol", "dave"},
	})

	if got := sortedMembers(a, "room-1"); got != "alice,dave,eve" {
		t.Errorf("members = %q, want %q — a concurrent invite was lost", got, "alice,dave,eve")
	}
}

// TestV1InviteDoesNotWipeRoster: an older client sends no roster. Absent means
// "said nothing", not "the room is empty".
func TestV1InviteDoesNotWipeRoster(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	fresh, _ := e2ee.NewChain()
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room: "secret room", Chains: []e2ee.ChainView{fresh.View()},
	})

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want %q — a rosterless invite emptied the room", got, "alice,bob")
	}
}

// TestNonMemberCannotInjectRoster: the membership check that stops a stranger
// replacing the room key must also stop them rewriting who is in the room —
// otherwise they could add themselves and rotate next time.
func TestNonMemberCannotInjectRoster(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.add("room-1", "alice")

	attacker, _ := e2ee.NewChain()
	a.handleRoomInvite("mallory", e2ee.RoomInvite{
		Room:    "secret room",
		Chains:  []e2ee.ChainView{attacker.View()},
		Members: []string{"mallory", "carol"},
	})

	if got := sortedMembers(a, "room-1"); got != "alice" {
		t.Errorf("members = %q — a non-member rewrote the roster", got)
	}
	if _, ok := a.client.ChainViews("room-1")[attacker.ID]; ok {
		t.Error("a non-member's chain was installed")
	}
}

// TestRosterOnTheWireIncludesUs: a roster we send must name us, or the person
// receiving it never learns WE hold the key and will refuse our own rotations
// as coming from a non-member.
func TestRosterOnTheWireIncludesUs(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	roster := a.roomRoster("room-1")
	sort.Strings(roster)
	if strings.Join(roster, ",") != "alice,bob,carol" {
		t.Errorf("roster = %v, want alice,bob,carol", roster)
	}
}

// TestRemovingAMemberDropsThemFromTheRoster is R3's backend half: the drop list
// has always been supported, and until now the UI never passed one.
func TestRemovingAMemberDropsThemFromTheRoster(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	before, _, err := a.client.EnsureOutboundChain("room-1")
	if err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")

	a.RotateRoomKey("room-1", []string{"bob"})

	if got := sortedMembers(a, "room-1"); got != "alice" {
		t.Errorf("members = %q, want %q", got, "alice")
	}
	// The roster that goes to the people who remain must not name the removed
	// person, or their next re-key would include them straight back in.
	for _, r := range a.roomRoster("room-1") {
		if r == "bob" {
			t.Errorf("a removed member is still on the outgoing roster: %v", a.roomRoster("room-1"))
		}
	}
	// And our chain must be due for replacement, or the next message we send is
	// still readable by the person we just removed. Lazily: the new chain is
	// minted and broadcast at that send, not here.
	if !chainWasReplaced(a, "room-1", before.ID) {
		t.Error("removing a member left our chain in place, so they can still read what we send next")
	}
}

// TestDeviceRemovalRekeysOnlyAffectedRooms is K6.
//
// A room key is sealed to every device an account publishes, so dropping one
// device from a manifest takes nothing back — it keeps every room key it held,
// and OSCAR lets it rejoin any room whose name it knows. Rooms it could read get
// a new key; rooms it was never in are left alone.
func TestDeviceRemovalRekeysOnlyAffectedRooms(t *testing.T) {
	store := state.NewStore()
	a := &App{store: store, client: client.New(store, nil)}
	a.cfg.LastScreenName = "me"

	store.UpsertRoom("room-a", "alpha")
	store.SetRoomJoined("room-a", true)
	store.UpsertRoom("room-b", "beta")
	store.SetRoomJoined("room-b", true)

	a.client.MarkRoomEncrypted("room-a")
	a.client.MarkRoomEncrypted("room-b")
	beforeA, _, _ := a.client.EnsureOutboundChain("room-a")
	beforeB, _, _ := a.client.EnsureOutboundChain("room-b")
	a.members.add("room-a", "bob")
	a.members.add("room-b", "carol")

	a.rotateRoomsAfterDeviceRemoval("bob")

	if !chainWasReplaced(a, "room-a", beforeA.ID) {
		t.Error("a room the removed device could read was not marked for re-keying")
	}
	if chainWasReplaced(a, "room-b", beforeB.ID) {
		t.Error("a room the removed device was never in was re-keyed anyway")
	}
}

// TestOwnDeviceRemovalRekeysEveryRoom: our own removed device held the keys to
// every encrypted room we are in, so all of them are affected.
func TestOwnDeviceRemovalRekeysEveryRoom(t *testing.T) {
	store := state.NewStore()
	a := &App{store: store, client: client.New(store, nil)}
	a.cfg.LastScreenName = "me"

	store.UpsertRoom("room-a", "alpha")
	store.SetRoomJoined("room-a", true)
	store.UpsertRoom("room-b", "beta")
	store.SetRoomJoined("room-b", true)
	// A room we are in but which is NOT encrypted has no key to rotate.
	store.UpsertRoom("room-c", "plain")
	store.SetRoomJoined("room-c", true)

	a.client.MarkRoomEncrypted("room-a")
	a.client.MarkRoomEncrypted("room-b")
	beforeA, _, _ := a.client.EnsureOutboundChain("room-a")
	beforeB, _, _ := a.client.EnsureOutboundChain("room-b")
	a.members.add("room-a", "bob")

	a.rotateRoomsAfterDeviceRemoval("")

	if !chainWasReplaced(a, "room-a", beforeA.ID) {
		t.Error("room-a was not re-keyed after our own device was removed")
	}
	// room-b has no other members, but our removed device still held its chain.
	if !chainWasReplaced(a, "room-b", beforeB.ID) {
		t.Error("a room with no other members was skipped, but the removed device held its chain")
	}
	if a.client.RoomEncrypted("room-c") {
		t.Error("an unencrypted room was marked encrypted")
	}
}

// TestCatchupNeverReachesBeforeWeJoined is stage three's point.
//
// The old floor was a flat 24 hours whenever a room had no local messages, so a
// fresh joiner asked for a day of conversation from before they arrived. Chains
// make that unreadable, so it now returns a screenful of "sent before you
// joined" — the ratchet working correctly, rendered as a fault. The floor is the
// moment we joined.
func TestCatchupNeverReachesBeforeWeJoined(t *testing.T) {
	a := rosterTestApp(t, "me")

	// Before we have joined anything, the old behaviour still applies: a room we
	// have no record of is a day's window, not everything ever said.
	if since := a.roomLastSeen("room-1"); time.Since(since) < 23*time.Hour {
		t.Errorf("an unknown room asked back only %v", time.Since(since))
	}

	joined := time.Now()
	a.noteRoomJoined("room-1")

	since := a.roomLastSeen("room-1")
	if since.Before(joined.Add(-time.Second)) {
		t.Errorf("catch-up reached back to %v, before we joined at %v", since, joined)
	}
}

// TestJoinTimeIsPinnedOnce: re-entering a room must not move the floor forward,
// or a member who reconnects can never catch up on anything.
func TestJoinTimeIsPinnedOnce(t *testing.T) {
	a := rosterTestApp(t, "me")

	a.noteRoomJoined("room-1")
	first, ok := a.roomJoinedAtTime("room-1")
	if !ok {
		t.Fatal("join time was not recorded")
	}

	time.Sleep(5 * time.Millisecond)
	a.noteRoomJoined("room-1")
	again, _ := a.roomJoinedAtTime("room-1")
	if !again.Equal(first) {
		t.Errorf("rejoining moved the floor from %v to %v — a returning member "+
			"would never catch up on anything", first, again)
	}
}

// TestLocalHistoryWinsOverJoinTime: once we have messages, the window starts at
// the last one. Otherwise every reconnect would re-request the whole session.
func TestLocalHistoryWinsOverJoinTime(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.noteRoomJoined("room-1")

	last := time.Now().Add(time.Hour) // later than the join
	a.store.AddRoomMessage("room-1", state.Message{From: "alice", Text: "hi", At: last})

	if since := a.roomLastSeen("room-1"); !since.Equal(last) {
		t.Errorf("catch-up window starts at %v, want the last local message at %v", since, last)
	}
}

// TestJoinTimeStillFloorsOlderHistory: a stale local message must not drag the
// window back past the join — that is the disclosure chains exist to prevent.
func TestJoinTimeStillFloorsOlderHistory(t *testing.T) {
	a := rosterTestApp(t, "me")

	old := time.Now().Add(-48 * time.Hour)
	a.store.AddRoomMessage("room-1", state.Message{From: "alice", Text: "ancient", At: old})
	a.noteRoomJoined("room-1")

	joined, _ := a.roomJoinedAtTime("room-1")
	if since := a.roomLastSeen("room-1"); since.Before(joined) {
		t.Errorf("a message from %v dragged the window back to %v, before we joined at %v",
			old, since, joined)
	}
}
