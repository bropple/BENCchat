package main

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/roomkeys"
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
// exercise the AUTHORITY rules — epoch, ownership, and what a removal does.
func roster(room, owner, author string, epoch uint64, members ...string) e2ee.Roster {
	return e2ee.Roster{Room: room, Epoch: epoch, Members: members, Owner: owner, Author: author}
}

// rosterRemoving is roster plus the signed removed set — the form every real
// removal arrives in, since the removed set (not each recipient's local diff)
// is what tombstones and triggers rotation.
func rosterRemoving(room, owner, author string, epoch uint64, removed []string, members ...string) e2ee.Roster {
	r := roster(room, owner, author, epoch, members...)
	r.Removed = removed
	return r
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

	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 1,
		[]string{"dave"}, "alice", "bob", "carol")) // dave is out

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
	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 5,
		[]string{"dave"}, "alice", "bob", "carol"))
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
	a.members.pinOwner("room-1", "me") // as CreateEncryptedRoom does
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
// The pin is laid at creation — CreateEncryptedRoom does it — never inferred
// later from whoever happens to ask.
func TestTheCreatorOwnsTheRoom(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "me") // as CreateEncryptedRoom does
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
	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 5,
		[]string{"dave"}, "alice", "bob", "carol"))
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
	a.members.pinOwner("room-1", "me")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")
	a.members.acceptOwnerEpoch("room-1", 40)

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

	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 6,
		[]string{"dave"}, "alice", "bob", "carol"))
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

	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 7,
		[]string{"dave"}, "alice", "bob", "carol"))
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
	a.members.pinOwner("room-1", "me")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")

	if msg := a.RotateRoomKey("room-1", []string{"bob"}); msg != "" {
		t.Fatalf("removing bob: %q", msg)
	}
	a.applyRoster("room-1", roster("secret room", "me", "alice", 3, "me", "alice", "bob"))

	if a.isRoomMember("room-1", "bob") {
		t.Error("a member's stale roster undid our own removal")
	}
}

// TestARosterCannotEstablishARoomsOwner is the seizure hole.
//
// "No owner pinned" is the NORMAL state for a room joined by name and for one
// whose invite carried no verifiable roster. The pin used to be established as a
// side effect of evaluating the incoming roster itself, so on such a room the
// first roster claiming Owner == Author made its author the owner — the
// membership check short-circuits when author IS owner — and from there they
// tombstoned every real member by name, durably. A roster must never be able to
// create the authority it is judged against, whoever signs it.
func TestARosterCannotEstablishARoomsOwner(t *testing.T) {
	attempts := []e2ee.Roster{
		// The seizure: a stranger names themselves owner and evicts everyone.
		rosterRemoving("secret room", "mallory", "mallory", 1, []string{"alice", "carol"}, "mallory"),
		// Subtler: joins quietly without evicting, so nobody notices the pin.
		roster("secret room", "mallory", "mallory", 1, "alice", "carol", "mallory"),
		// Naming somebody else as owner changes nothing either.
		roster("secret room", "alice", "mallory", 1, "alice", "carol", "mallory"),
		// Even a roster from the one genuine member: no authorized path pinned
		// an owner, so there is no authority to judge it against.
		roster("secret room", "alice", "alice", 1, "alice", "carol", "dave"),
	}
	for _, r := range attempts {
		a := rosterTestApp(t, "carol")
		a.client.MarkRoomEncrypted("room-1")
		a.members.add("room-1", "alice") // joined by name; alice is all we know
		before, _, _ := a.client.EnsureOutboundChain("room-1")

		a.applyRoster("room-1", r)

		if got := a.members.ownerOf("room-1"); got != "" {
			t.Fatalf("roster %+v established an owner pin: %q", r, got)
		}
		if got := sortedMembers(a, "room-1"); got != "alice" {
			t.Errorf("roster %+v changed membership: %q", r, got)
		}
		if a.members.wasRemoved("room-1", "alice") {
			t.Errorf("roster %+v tombstoned a real member", r)
		}
		if chainWasReplaced(a, "room-1", before.ID) {
			t.Errorf("roster %+v churned our chain despite being refused", r)
		}
	}
}

// TestRemovingFromAnUnownedRoomDoesNotSelfPin is the same mutator bug from the
// other side.
//
// The removal guard used to CALL the pinning helper, so on an unpinned room it
// installed the caller as owner and waved the removal through — every other
// client then rejected the roster as naming the wrong owner, the UI said "Room
// key rotated" while nothing happened elsewhere, and our mis-pin rejected the
// real owner's rosters forever after.
func TestRemovingFromAnUnownedRoomDoesNotSelfPin(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")
	before, _, _ := a.client.EnsureOutboundChain("room-1")

	msg := a.RotateRoomKey("room-1", []string{"bob"})

	if msg == "" {
		t.Fatal("removing somebody from a room with no owner reported success")
	}
	if got := a.members.ownerOf("room-1"); got != "" {
		t.Fatalf("the refused removal installed an owner: %q", got)
	}
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q — a refused removal was applied locally anyway", got)
	}
	if a.members.wasRemoved("room-1", "bob") {
		t.Error("a refused removal still laid a tombstone")
	}
	if chainWasReplaced(a, "room-1", before.ID) {
		t.Error("a refused removal still cycled our chain")
	}
}

// TestAMemberEpochCannotSaturateTheCounter is the epoch-poisoning denial.
//
// A member's roster is deliberately unordered, yet its epoch used to raise the
// shared high-water mark our own rosters stamp from — so one roster stamped
// near 2^64 wrapped the increment to zero and every roster we sent afterwards
// read as a replay, permanently and across restarts. Whatever a member stamps,
// the owner must still be able to remove, and our own stamps must stay small
// and strictly increasing.
func TestAMemberEpochCannotSaturateTheCounter(t *testing.T) {
	for _, poison := range []uint64{1 << 63, ^uint64(0) - 1, ^uint64(0)} {
		a := rosterTestApp(t, "carol")
		a.client.MarkRoomEncrypted("room-1")
		a.members.pinOwner("room-1", "alice")
		a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

		a.applyRoster("room-1", roster("secret room", "alice", "bob", poison,
			"alice", "bob", "carol", "dave"))
		if !a.isRoomMember("room-1", "dave") {
			t.Fatalf("poison=%d: the add itself should still land", poison)
		}

		// The owner's ordinary next roster must still be accepted...
		a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 2,
			[]string{"dave"}, "alice", "bob", "carol"))
		if a.isRoomMember("room-1", "dave") {
			t.Errorf("poison=%d: a member's epoch locked the owner out of removing", poison)
		}
		// ...and our own stamps must be untouched by the poison: strictly
		// increasing, nowhere near the ceiling, never zero.
		first := a.members.nextEpoch("room-1", time.Now())
		second := a.members.nextEpoch("room-1", time.Now())
		if first == 0 || second == 0 || second <= first {
			t.Errorf("poison=%d: our stamps wrapped or stalled: %d then %d", poison, first, second)
		}
		// And nowhere near the poison. Our stamps are floored at the wall clock
		// (so an owner's two devices agree without talking), so "small" is no
		// longer the test — "not dragged toward what the member claimed" is.
		clean := rosterTestApp(t, "carol")
		clean.members.pinOwner("room-1", "alice")
		if want := clean.members.nextEpoch("room-1", time.Now()); first > want+60 {
			t.Errorf("poison=%d: a member's epoch dragged our counter to %d, want about %d",
				poison, first, want)
		}
	}
}

// TestNextEpochSaturatesInsteadOfWrapping: at the ceiling — reachable only by
// the owner signing it — the counter must stick rather than wrap. A wrap to
// zero would both read as the oldest roster ever and reset the counter, so
// every later stamp would repeat an epoch already spent.
func TestNextEpochSaturatesInsteadOfWrapping(t *testing.T) {
	var m roomMembers
	m.acceptOwnerEpoch("r", ^uint64(0))
	for i := 0; i < 3; i++ {
		if got := m.nextEpoch("r", time.Now()); got != ^uint64(0) {
			t.Fatalf("nextEpoch at the ceiling = %d, want it pinned there", got)
		}
	}
}

// TestTheOwnersOwnEpochIsRecorded: an owner never receives their own rosters —
// SendRoster skips self — so unless signing one records the stamp, the owner's
// persisted anti-rollback mark stays at zero and a replay of their own earlier
// roster walks straight back in.
func TestTheOwnersOwnEpochIsRecorded(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "me")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")

	r, err := a.signedRoster("room-1", "secret room")
	if err != nil {
		t.Fatalf("signedRoster: %v", err)
	}
	if got := a.members.ownerEpochOf("room-1"); got < r.Epoch {
		t.Fatalf("owner epoch = %d after stamping %d — our own rosters don't count as ours", got, r.Epoch)
	}

	// The replay a server could mount: our own earlier roster, fed back with a
	// membership we have since walked away from.
	a.applyRoster("room-1", roster("secret room", "me", "me", r.Epoch, "me", "alice", "bob", "mallory"))
	if a.isRoomMember("room-1", "mallory") {
		t.Error("a replay of our own roster at a spent epoch was accepted")
	}
}

// TestSignedRosterRefusesAnUnownedRoom: a roster must name an owner, and on an
// unpinned room there is no true answer — the old code answered by pinning
// OURSELVES, which is how a mere member of a badly-bootstrapped room became its
// owner in everyone else's eyes.
func TestSignedRosterRefusesAnUnownedRoom(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	if _, err := a.signedRoster("room-1", "secret room"); err == nil {
		t.Fatal("signed a roster for a room with no pinned owner")
	}
	if got := a.members.ownerOf("room-1"); got != "" {
		t.Fatalf("building a roster pinned an owner: %q", got)
	}
}

// TestReinvitingARemovedMemberIsRefused is the tombstone bypass.
//
// InviteToRoom never consulted the tombstone, and the chain bundle it hands
// over is wound to the present — so any member re-inviting a removed person
// restored their read access to everyone's CURRENT traffic, while the follow-up
// roster was rejected by every other client and nobody else ever learned.
func TestReinvitingARemovedMemberIsRefused(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")
	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 2,
		[]string{"dave"}, "alice", "bob", "carol"))
	if a.isRoomMember("room-1", "dave") {
		t.Fatal("precondition: the removal did not apply")
	}

	msg := a.InviteToRoom("room-1", "dave")

	if msg == "" {
		t.Fatal("re-inviting a removed member reported success")
	}
	if !strings.Contains(msg, "alice") {
		t.Errorf("the refusal doesn't say who can readmit them: %q", msg)
	}
	if a.isRoomMember("room-1", "dave") {
		t.Error("the removed member is back on the list")
	}
	if !a.members.wasRemoved("room-1", "dave") {
		t.Error("the refused re-invite lifted the tombstone")
	}
}

// TestTheOwnerCanReadmitByInvite: the tombstone is the owner's statement, so the
// owner's own invite lifts it — and a failed delivery lays it back, because a
// lift nobody was told about would leak into our next signed roster.
func TestTheOwnerCanReadmitByInvite(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "me")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")
	if msg := a.RotateRoomKey("room-1", []string{"bob"}); msg != "" {
		t.Fatalf("removing bob: %q", msg)
	}

	// The invite itself fails — this client has no session — so the readmission
	// must be rolled back whole: no membership, and the tombstone re-laid.
	if msg := a.InviteToRoom("room-1", "bob"); msg == "" {
		t.Fatal("an undeliverable invite reported success")
	}
	if a.isRoomMember("room-1", "bob") {
		t.Error("a failed re-invite left the member recorded")
	}
	if !a.members.wasRemoved("room-1", "bob") {
		t.Error("a failed re-invite left the tombstone lifted")
	}
}

// TestInvitingFromAnUnownedRoomIsRefused: an invite from a pinless room hands
// out chains with a membership claim nobody can verify — the exact bootstrap
// that used to let a stranger's roster stick.
func TestInvitingFromAnUnownedRoomIsRefused(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.add("room-1", "alice")

	if msg := a.InviteToRoom("room-1", "dave"); msg == "" {
		t.Fatal("invited somebody from a room with no confirmed owner")
	}
	if a.isRoomMember("room-1", "dave") {
		t.Error("the refused invite recorded a member anyway")
	}
}

// TestRemovalRotatesEvenWhenWeNeverKnewTheRemoved is the blind-spot rotation.
//
// A replace-semantics roster cannot say "D was removed" to somebody who never
// learned D existed — and that somebody may be exactly the leak, because the
// invite that admitted D handed over every chain while the roster announcing D
// travelled separately and failed. The rotation trigger is therefore the SIGNED
// removed set, which reaches everyone the roster reaches regardless of what
// they knew.
func TestRemovalRotatesEvenWhenWeNeverKnewTheRemoved(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	// Our list never included dave: the roster announcing him never reached us.
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")
	before, _, _ := a.client.EnsureOutboundChain("room-1")

	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 2,
		[]string{"dave"}, "alice", "bob", "carol"))

	if !a.members.wasRemoved("room-1", "dave") {
		t.Error("a removal of somebody we never knew laid no tombstone, so a member's add can seat them")
	}
	if !chainWasReplaced(a, "room-1", before.ID) {
		t.Error("our chain was not retired — the person we never knew keeps reading everything we send")
	}
}

// TestAnOwnerRosterWithoutNewRemovalsDoesNotChurnChains: the removed set is the
// full tombstone list, so most of it is old news on every roster after the
// first — re-keying for names already processed would rotate the room on every
// invite the owner makes.
func TestAnOwnerRosterWithoutNewRemovalsDoesNotChurnChains(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 2,
		[]string{"dave"}, "alice", "bob", "carol"))
	first, fresh, _ := a.client.EnsureOutboundChain("room-1")
	if !fresh {
		t.Fatal("precondition: the removal did not retire our chain")
	}

	// The owner invites eve; dave still rides along in the tombstone list.
	a.applyRoster("room-1", rosterRemoving("secret room", "alice", "alice", 3,
		[]string{"dave"}, "alice", "bob", "carol", "eve"))

	if chainWasReplaced(a, "room-1", first.ID) {
		t.Error("an already-processed removal retired our chain again — every owner roster would re-key the room")
	}
	if !a.isRoomMember("room-1", "eve") {
		t.Error("the roster's add was lost")
	}
}

// TestOwnerOmissionAloneDoesNotTombstone: an owner's list omitting somebody we
// know is not the same claim as removing them — the owner may simply never have
// learned of a concurrent invite. Omission drops them from the list until the
// inviter's next roster restores them; only the signed removed set makes it
// permanent. Tombstoning on omission is how a concurrent invite got durably
// erased by an owner roster that predated it.
func TestOwnerOmissionAloneDoesNotTombstone(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	// The owner's roster omits dave — signed before bob's invite of dave
	// reached them — but removes nobody.
	a.applyRoster("room-1", roster("secret room", "alice", "alice", 2, "alice", "bob", "carol"))

	if a.members.wasRemoved("room-1", "dave") {
		t.Fatal("an omission laid a tombstone, so a concurrent invite is durably erased")
	}
	// Bob's roster, still naming dave, seats him again.
	a.applyRoster("room-1", roster("secret room", "alice", "bob", 2, "alice", "bob", "carol", "dave"))
	if !a.isRoomMember("room-1", "dave") {
		t.Error("a concurrently-invited member could not be restored")
	}
}

// TestAdoptInviteStatePinsOnlyFromAVerifiedRoster: the invite's roster is the
// ONE unauthorized-free path that may pin an owner for a room we did not
// create, and it may do so only when it verified. An unverifiable invite joins
// degraded — no pin, and applyRoster refuses everything until re-invited.
func TestAdoptInviteStatePinsOnlyFromAVerifiedRoster(t *testing.T) {
	verifiedRoster := rosterRemoving("secret room", "alice", "alice", 5,
		[]string{"mallory"}, "alice", "bob", "carol")

	a := rosterTestApp(t, "carol")
	a.adoptInviteState("room-1", "alice", e2ee.RoomInvite{Room: "secret room"}, verifiedRoster, true)
	if got := a.members.ownerOf("room-1"); got != "alice" {
		t.Fatalf("owner = %q, want alice pinned from the verified invite roster", got)
	}
	if got := a.members.ownerEpochOf("room-1"); got != 5 {
		t.Errorf("owner epoch = %d, want 5 bootstrapped from the invite", got)
	}
	if !a.members.wasRemoved("room-1", "mallory") {
		t.Error("the owner's tombstones did not bootstrap with the membership")
	}
	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want alice,bob", got)
	}

	// The same invite arriving unverifiable must pin nothing at all.
	b := rosterTestApp(t, "carol")
	b.adoptInviteState("room-1", "alice", e2ee.RoomInvite{Room: "secret room"}, e2ee.Roster{}, false)
	if got := b.members.ownerOf("room-1"); got != "" {
		t.Fatalf("an unverified invite pinned an owner: %q", got)
	}
	// The inviter is still recorded — they are the one member the encrypted 1:1
	// channel actually authenticated.
	if !b.isRoomMember("room-1", "alice") {
		t.Error("the inviter was not recorded as a member")
	}
	// And the room stays deaf to rosters, including one from the inviter naming
	// themselves owner — that is the degraded state working as intended.
	b.applyRoster("room-1", roster("secret room", "alice", "alice", 1, "alice", "bob", "carol"))
	if b.isRoomMember("room-1", "bob") {
		t.Error("a pinless room acted on a roster")
	}
}

// TestAcceptingAnUnverifiableInviteDefersTheJoin: joining anyway — the old
// behaviour, a log line and a shrug — left the room permanently unable to pin
// its owner, which is permanently vulnerable to whoever claims it first. The
// invitation must survive the refusal so the user can retry once the inviter's
// keys arrive.
func TestAcceptingAnUnverifiableInviteDefersTheJoin(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.pendingMu.Lock()
	a.pendingInvites = map[string]e2ee.RoomInvite{
		"other room": {Room: "other room", Roster: "\x1bBENCO-ROSTER:v2:AAAA"},
	}
	a.pendingInviteFrom = map[string]string{"other room": "alice"}
	a.pendingMu.Unlock()

	msg := a.AcceptRoomInvite("other room")

	if msg == "" {
		t.Fatal("an invite whose roster could not be verified was accepted")
	}
	a.pendingMu.Lock()
	_, still := a.pendingInvites["other room"]
	a.pendingMu.Unlock()
	if !still {
		t.Error("the refused invitation was discarded rather than re-queued")
	}
}

// TestMergedRoomEntryNeverZeroesAntiRollbackMarks is A7's actual invariant,
// tested on the merge itself so no OS keyring sits in the loop.
//
// The scenario it guards: restoreRoomKeys returned silently (keyring locked at
// sign-on), the keyring recovers mid-session, and the next save runs against
// in-memory state that never saw the file. A plain replacement then wrote zero
// over the owner pin, both epoch marks and every tombstone — re-arming each
// replay they existed to refuse.
func TestMergedRoomEntryNeverZeroesAntiRollbackMarks(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	// In-memory state is EMPTY for this room: the restore never ran.

	prev := roomkeys.Room{
		Name:        "secret room",
		Owner:       "alice",
		RosterEpoch: 9,
		OwnerEpoch:  7,
		Removed:     []string{"dave"},
		Members:     []string{"alice", "bob"},
		Out:         "not-really-a-chain",
		Shared:      true,
		Stale:       true,
		Views:       map[string]string{"chain-x": "view-x"},
		Seen:        map[string]uint32{"chain-x": 41},
		JoinedAt:    time.Now().Add(-time.Hour),
	}
	got := a.mergedRoomEntry("room-1", "secret room", prev)

	if got.Owner != "alice" {
		t.Errorf("Owner = %q — the pin was zeroed", got.Owner)
	}
	if got.RosterEpoch != 9 || got.OwnerEpoch != 7 {
		t.Errorf("epochs = %d/%d, want 9/7 — the high-water marks were rolled back",
			got.RosterEpoch, got.OwnerEpoch)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "dave" {
		t.Errorf("Removed = %v — a tombstone was erased", got.Removed)
	}
	if strings.Join(got.Members, ",") != "alice,bob" {
		t.Errorf("Members = %v — the saved member list was replaced with nothing", got.Members)
	}
	if got.Out != "not-really-a-chain" || !got.Shared || !got.Stale {
		t.Errorf("chain state was dropped: out=%q shared=%v stale=%v", got.Out, got.Shared, got.Stale)
	}
	if got.Views["chain-x"] != "view-x" || got.Seen["chain-x"] != 41 {
		t.Errorf("views/seen were dropped: %v / %v", got.Views, got.Seen)
	}
	if got.JoinedAt.IsZero() {
		t.Error("JoinedAt was zeroed, so catch-up loses its floor")
	}
}

// TestMergedRoomEntryPrefersLiveStateAndTombstonesEverywhere: the merge must
// not become a ratchet on things that legitimately move — live membership and
// live epochs win where they exist — and no tombstoned name may be written back
// as a member from either side.
func TestMergedRoomEntryPrefersLiveStateAndTombstonesEverywhere(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "alice")
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")
	a.members.acceptOwnerEpoch("room-1", 12)
	a.members.tombstone("room-1", []string{"dave"}, nil)

	prev := roomkeys.Room{
		Owner:       "alice",
		OwnerEpoch:  7,
		RosterEpoch: 3,
		Members:     []string{"alice", "bob", "dave", "eve"}, // dave removed this session
		Removed:     []string{"mallory"},                     // removed in an earlier session
	}
	got := a.mergedRoomEntry("room-1", "secret room", prev)

	if got.OwnerEpoch != 12 {
		t.Errorf("OwnerEpoch = %d, want the live 12", got.OwnerEpoch)
	}
	if strings.Join(got.Removed, ",") != "dave,mallory" {
		t.Errorf("Removed = %v, want the union dave,mallory", got.Removed)
	}
	for _, m := range got.Members {
		if m == "dave" || m == "mallory" {
			t.Errorf("a tombstoned name was written back as a member: %v", got.Members)
		}
	}
	if strings.Join(got.Members, ",") != "alice,bob" {
		t.Errorf("Members = %v, want the live alice,bob", got.Members)
	}
}

// TestStaleMarkSurvivesARestart: rotation is lazy, so between a removal and the
// next send the stale mark is the ONLY record that the chain must not be used.
// A restart that dropped it resumed sealing on the chain the removed member
// still holds — the removal undone by quitting the app.
func TestStaleMarkSurvivesARestart(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.client.MarkRoomEncrypted("room-1")
	a.members.pinOwner("room-1", "me")
	a.members.setAll("room-1", []string{"alice", "bob"}, "me")
	before, _, _ := a.client.EnsureOutboundChain("room-1")
	a.client.MarkChainShared("room-1")
	if msg := a.RotateRoomKey("room-1", []string{"bob"}); msg != "" {
		t.Fatalf("removing bob: %q", msg)
	}
	entry := a.mergedRoomEntry("room-1", "secret room", roomkeys.Room{})
	if !entry.Stale {
		t.Fatal("the stale mark did not reach the persisted entry")
	}

	// The restart: a fresh app restores the entry as restoreRoomKeys would.
	b := rosterTestApp(t, "me")
	b.applyRoomEntry("room-1", entry)

	view, fresh, err := b.client.EnsureOutboundChain("room-1")
	if err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}
	if !fresh || view.ID == before.ID {
		t.Error("the restored chain came back usable — the removed member reads everything sent after the restart")
	}
	if !b.members.wasRemoved("room-1", "bob") {
		t.Error("the tombstone did not survive the restart")
	}
}

// TestRestoreRefusesTombstonedMembers: a room file whose lists disagree —
// somebody in Members AND in Removed — must resolve in the removal's favour,
// or a restart resurrects them into every future distribution.
func TestRestoreRefusesTombstonedMembers(t *testing.T) {
	a := rosterTestApp(t, "carol")
	a.applyRoomEntry("room-1", roomkeys.Room{
		Members: []string{"alice", "dave"},
		Removed: []string{"dave"},
		Owner:   "alice",
	})
	if a.isRoomMember("room-1", "dave") {
		t.Error("a tombstoned name was restored as a member")
	}
	if !a.isRoomMember("room-1", "alice") {
		t.Error("an ordinary member was not restored")
	}
}

// TestAnOwnersTwoDevicesDoNotCollideOnEpochs.
//
// An owner's devices never see each other's rosters — SendRoster skips self, and
// the server refuses a self-addressed message anyway — so each keeps its own
// counter. With a plain increment the second device to remove somebody stamps an
// epoch the first already used, every recipient discards it as stale, and the
// owner is told the room was re-keyed. Flooring at the wall clock gives both
// devices a counter they already share without exchanging anything.
func TestAnOwnersTwoDevicesDoNotCollideOnEpochs(t *testing.T) {
	laptop := rosterTestApp(t, "me")
	desktop := rosterTestApp(t, "me")
	for _, a := range []*App{laptop, desktop} {
		a.client.MarkRoomEncrypted("room-1")
		a.members.pinOwner("room-1", "me")
		a.members.setAll("room-1", []string{"alice", "bob"}, "me")
	}

	now := time.Now()
	first := laptop.members.nextEpoch("room-1", now)
	// The desktop has never heard about that one, and stamps a second later.
	second := desktop.members.nextEpoch("room-1", now.Add(time.Second))

	if second <= first {
		t.Errorf("the second device's roster would be discarded as stale: %d then %d", first, second)
	}

	// Within the same second the clock cannot separate them, so the strict
	// increment must: a device removing twice in a row still moves forward.
	again := laptop.members.nextEpoch("room-1", now)
	if again <= first {
		t.Errorf("two removals in one second collided: %d then %d", first, again)
	}
}

// TestTheClockIsAFloorNotTheValue: a clock that has gone backwards must not
// stall or rewind an epoch, or a removal made after an NTP correction would be
// discarded as a replay of one made before it.
func TestTheClockIsAFloorNotTheValue(t *testing.T) {
	a := rosterTestApp(t, "me")
	a.members.pinOwner("room-1", "me")

	now := time.Now()
	first := a.members.nextEpoch("room-1", now)
	second := a.members.nextEpoch("room-1", now.Add(-24*time.Hour))
	if second <= first {
		t.Errorf("a backwards clock rewound the epoch: %d then %d", first, second)
	}

	// And a clock at the zero value must not drag it down either.
	third := a.members.nextEpoch("room-1", time.Time{})
	if third <= second {
		t.Errorf("a zero clock rewound the epoch: %d then %d", second, third)
	}
}
