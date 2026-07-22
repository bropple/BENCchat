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

// roster is a membership statement as it would arrive from the wire. Signature
// checking happens in the client before applyRoster ever sees one, so these
// exercise the AUTHORITY rules — epoch, ownership, and what a shrink does.
func roster(room, owner, author string, epoch uint64, members ...string) e2ee.Roster {
	return e2ee.Roster{Room: room, Epoch: epoch, Members: members, Owner: owner, Author: author}
}

// TestRosterReachesEveryMember is the three-way bug.
//
// Membership used to be recorded only for people WE invited, so in a room where
// Alice invited both Bob and Carol, Carol knew only Alice. A rotation by Carol
// then reached nobody but Alice, and Bob silently lost the room.
func TestRosterReachesEveryMember(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.add("room-1", "alice") // all we learn from being invited
	a.members.pinOwner("room-1", "alice")

	a.applyRoster("room-1", roster("secret room", "alice", "alice", 1, "alice", "bob", "carol", "dave"))

	// Everyone but ourselves — a.members means "other people holding this key".
	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Errorf("members = %q, want %q", got, "alice,bob,dave")
	}
}

// TestOwnerRemovalPropagatesAndStalesOurChain is H1, and it is the whole point
// of signing rosters.
//
// Under the old shared room key a rotation CARRIED the new key, so holding new
// key material doubled as proof of authority and a removal propagated by
// accident. Chains took the key away and nothing replaced the proof: every
// member except the one who clicked Remove carried on sending on chains the
// removed member still held.
func TestOwnerRemovalPropagatesAndStalesOurChain(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")
	before, _, err := a.client.EnsureOutboundChain("room-1")
	if err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}

	a.applyRoster("room-1", roster("secret room", "alice", "alice", 1, "alice", "bob", "carol")) // dave is out

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want %q — a removal did not propagate", got, "alice,bob")
	}
	if !chainWasReplaced(a, "room-1", before.ID) {
		t.Error("a removal left OUR chain in place, so the removed member still reads what we send next")
	}
}

// TestAnyMemberMayAdd: additions stay flat. Gating them would buy nothing —
// you can only add somebody you can already reach, and they would learn the
// room name regardless.
func TestAnyMemberMayAdd(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	a.applyRoster("room-1", roster("secret room", "alice", "bob", 1, "alice", "bob", "carol", "dave"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Errorf("members = %q, want %q — a member could not add", got, "alice,bob,dave")
	}
}

// TestOnlyTheOwnerMayRemove: a flat model where any member can evict any other
// is not an access control, it is a griefing surface — and worse, it makes the
// roster an injection point for cutting people out of a room.
func TestOnlyTheOwnerMayRemove(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")
	before, _, _ := a.client.EnsureOutboundChain("room-1")

	// Bob is a member in good standing. He is not the owner.
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 1, "alice", "bob", "carol"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Errorf("members = %q — a non-owner removed somebody", got)
	}
	if chainWasReplaced(a, "room-1", before.ID) {
		t.Error("a refused removal still cycled our chain, which a stranger could use to churn the room")
	}
}

// TestARosterCannotBeReplayed: the cheapest attack on a removal is to capture
// the roster from before it and send that back afterwards.
func TestARosterCannotBeReplayed(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	full := roster("secret room", "alice", "alice", 4, "alice", "bob", "carol", "dave")
	a.applyRoster("room-1", full)
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 5, "alice", "bob", "carol"))
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Fatalf("precondition: members = %q, want alice,bob", got)
	}

	a.applyRoster("room-1", full) // the capture, replayed

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a replayed roster undid a removal", got)
	}
	// Same epoch, different contents: an attacker who cannot rewind may still try
	// to sit ON the current epoch.
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 5, "alice", "bob", "carol", "mallory"))
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a roster at an epoch already used was accepted", got)
	}
}

// TestAMemberCannotPushTheEpochOutOfReach.
//
// Members' rosters must not move the owner's epoch. If they did, anybody could
// stamp a huge one and lock the owner out of ever removing anyone again — a
// denial of the only authority in the room, available to every member.
func TestAMemberCannotPushTheEpochOutOfReach(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	a.applyRoster("room-1", roster("secret room", "alice", "bob", 9_000_000, "alice", "bob", "carol", "dave"))
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 2, "alice", "bob", "carol"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a member's epoch locked the owner out of removing anyone", got)
	}
}

// TestTheOwnerCannotBeSwappedOut: the owner is pinned on the first roster we
// see and every later one must agree, or a member could promote themselves and
// then start removing people.
func TestTheOwnerCannotBeSwappedOut(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	a.applyRoster("room-1", roster("secret room", "bob", "bob", 2, "bob", "carol"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Errorf("members = %q — somebody named themselves owner and it stuck", got)
	}
	if a.members.ownerOf("room-1") != "alice" {
		t.Errorf("owner = %q, want alice", a.members.ownerOf("room-1"))
	}
}

// TestARosterlessInviteDoesNotWipeTheRoom: an invite for a room we are already
// in carries chains and nothing else. Absent must read as "said nothing".
func TestARosterlessInviteDoesNotWipeTheRoom(t *testing.T) {
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
	if _, ok := a.client.ChainViews("room-1")[fresh.ID]; !ok {
		t.Error("a member's chain was not installed")
	}
}

// TestNonMemberCannotInjectChains: reaching us over the encrypted 1:1 channel
// proves nothing about room membership — peer keys are fetched on demand for
// anyone.
func TestNonMemberCannotInjectChains(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.add("room-1", "alice")

	attacker, _ := e2ee.NewChain()
	a.handleRoomInvite("mallory", e2ee.RoomInvite{
		Room:   "secret room",
		Chains: []e2ee.ChainView{attacker.View()},
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

// TestRemovingWithoutOwningRefusesLoudly.
//
// The failure this guards against is the quiet one. Only the owner's shrink is
// honoured, so a member who clicks Remove and is told "Room key rotated" would
// be looking at a room where their own chain had cycled, every other client had
// ignored the roster, and the person they meant to remove was still reading.
func TestRemovingWithoutOwningRefusesLoudly(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")
	before, _, _ := a.client.EnsureOutboundChain("room-1")

	msg := a.RotateRoomKey("room-1", []string{"bob"})

	if msg == "" {
		t.Fatal("removing somebody from a room we don't own reported success")
	}
	if !strings.Contains(msg, "alice") {
		t.Errorf("the refusal doesn't say who can do it: %q", msg)
	}
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a refused removal was applied locally anyway", got)
	}
	if chainWasReplaced(a, "room-1", before.ID) {
		t.Error("a refused removal still cycled our chain, costing the room a re-key for nothing")
	}
}

// TestTheCreatorOwnsTheRoom: somebody has to be able to remove people, and the
// person who made the room is the only candidate available at that moment.
func TestTheCreatorOwnsTheRoom(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")

	if msg := a.RotateRoomKey("room-1", []string{"bob"}); msg != "" {
		t.Fatalf("the room's owner could not remove anyone: %q", msg)
	}
	if got := sortedMembers(a, "room-1"); got != "alice" {
		t.Errorf("members = %q, want alice", got)
	}
	// And what we send from here on says the same thing, or the members who
	// remain would put bob back on their next roster.
	for _, r := range a.roomRoster("room-1") {
		if r == "bob" {
			t.Errorf("a removed member is still on the outgoing roster: %v", a.roomRoster("room-1"))
		}
	}
}

// TestANonMemberCannotAddThemselves.
//
// Reaching us over the encrypted 1:1 channel proves nothing about room
// membership — peer keys are fetched on demand for anybody who asks. A stranger
// who knows the room name can sign a perfectly valid roster naming the real
// owner. If we took it, every member's next chain broadcast would seal them a
// slot and they would simply be in the room.
func TestANonMemberCannotAddThemselves(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	a.applyRoster("room-1", roster("secret room", "alice", "mallory", 5,
		"alice", "bob", "carol", "mallory"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a stranger signed their way into the room", got)
	}
}

// TestConcurrentAddsBothSurvive.
//
// Two members inviting at the same time both stamp the same epoch, neither
// having seen the other's roster. If a member's roster had to clear the highest
// epoch from anybody, the second to arrive would lose and one of the two
// newcomers would be silently missing from everyone's list — which is precisely
// the three-way bug this whole mechanism exists to prevent, reintroduced by the
// replay defence.
func TestConcurrentAddsBothSurvive(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	// The same epoch from two different members — neither had seen the other's
	// roster, so neither could have stamped a higher one.
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 3, "alice", "bob", "carol", "dave"))
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 3, "alice", "bob", "carol", "eve"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave,eve" {
		t.Errorf("members = %q, want alice,bob,dave,eve — a concurrent invite was lost", got)
	}
}

// TestAMembersRosterCannotRemoveByOmission: a member announcing "I invited Dave"
// is telling the truth about Dave and nothing at all about anybody else. Taking
// their list as complete would let any member quietly drop any other.
func TestAMembersRosterCannotRemoveByOmission(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")
	before, _, _ := a.client.EnsureOutboundChain("room-1")

	// Bob adds Eve and omits Dave in the same breath.
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 4, "alice", "bob", "carol", "eve"))

	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave,eve" {
		t.Errorf("members = %q — a member removed somebody by leaving them off", got)
	}
	if chainWasReplaced(a, "room-1", before.ID) {
		t.Error("a non-owner's omission still cycled our chain, which is a free way to churn the room")
	}
}

// TestARemovalSurvivesAReplayedAdd: the owner removes Dave, and somebody replays
// a member's older roster that still names him. Rolling a removal back is the
// whole reason the epoch exists.
func TestARemovalSurvivesAReplayedAdd(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	memberAdd := roster("secret room", "alice", "bob", 4, "alice", "bob", "carol", "dave")
	a.applyRoster("room-1", memberAdd)
	if got := sortedMembers(a, "room-1"); got != "alice,bob,dave" {
		t.Fatalf("precondition: members = %q", got)
	}
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 5, "alice", "bob", "carol"))
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Fatalf("precondition: the removal did not apply: %q", got)
	}

	a.applyRoster("room-1", memberAdd) // the capture, replayed

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — replaying an old add undid a removal", got)
	}
}

// TestOurOwnRosterOutranksEverythingWeHaveSeen: if we stamped an epoch that was
// already used, our roster would be discarded as a replay of somebody else's and
// the removal it carried would never land.
func TestOurOwnRosterOutranksEverythingWeHaveSeen(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")
	a.members.acceptOwnerEpoch("room-1", 40)
	a.members.noteEpoch("room-1", 12)

	r, err := a.signedRoster("room-1", "secret room")
	if err != nil {
		t.Fatalf("signedRoster: %v", err)
	}
	if r.Epoch <= 40 {
		t.Errorf("epoch = %d, want past the highest we've seen (40)", r.Epoch)
	}
	// And twice running must not repeat, or the second is read as a replay of
	// the first.
	next, _ := a.signedRoster("room-1", "secret room")
	if next.Epoch <= r.Epoch {
		t.Errorf("two rosters of ours shared or reversed an epoch: %d then %d", r.Epoch, next.Epoch)
	}
}

// TestARemovalSurvivesAConcurrentAdd is the case ordering alone cannot settle.
//
// The owner removes Dave at the same moment a member's roster goes out still
// naming him. Neither has seen the other, so there is no epoch relationship to
// appeal to — and the member's roster may well arrive last. Removal has to be
// durable state, not a message that wins a race.
func TestARemovalSurvivesAConcurrentAdd(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	a.applyRoster("room-1", roster("secret room", "alice", "alice", 6, "alice", "bob", "carol"))
	// Bob's, sent before he heard, arriving after.
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 6, "alice", "bob", "carol", "dave", "eve"))

	if a.isRoomMember("room-1", "dave") {
		t.Error("a concurrent add resurrected somebody the owner had removed")
	}
	if !a.isRoomMember("room-1", "eve") {
		t.Error("the same roster's legitimate add was lost")
	}
}

// TestTheOwnerCanReinviteSomeoneRemoved: a tombstone is durable, not permanent.
// Only the owner can lift it, which is the same authority that laid it.
func TestTheOwnerCanReinviteSomeoneRemoved(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	a.applyRoster("room-1", roster("secret room", "alice", "alice", 7, "alice", "bob", "carol"))
	// A member cannot undo it...
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 8, "alice", "bob", "carol", "dave"))
	if a.isRoomMember("room-1", "dave") {
		t.Fatal("a member lifted the owner's removal")
	}
	// ...but the owner can.
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 9, "alice", "bob", "carol", "dave"))
	if !a.isRoomMember("room-1", "dave") {
		t.Error("the owner could not re-invite somebody they had removed")
	}
}

// TestOurOwnRemovalIsNotUndoneByTheNextRoster: we remove Bob, and Alice's next
// roster — built from a list that still names him, because she has not heard
// yet — arrives. Without a tombstone on our own removals it would put him back.
func TestOurOwnRemovalIsNotUndoneByTheNextRoster(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")

	if msg := a.RotateRoomKey("room-1", []string{"bob"}); msg != "" {
		t.Fatalf("removing bob: %q", msg)
	}
	a.applyRoster("room-1", roster("secret room", "me", "alice", 3, "me", "alice", "bob"))

	if a.isRoomMember("room-1", "bob") {
		t.Error("a member's stale roster undid our own removal")
	}
}
