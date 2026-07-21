package main

import (
	"sort"
	"strings"
	"testing"

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

	original, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey: %v", err)
	}
	a.client.SetRoomKey("room-1", original)
	a.members.add("room-1", "alice") // alice gave us this room's key

	attacker, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey: %v", err)
	}
	a.handleRoomInvite("mallory", e2ee.RoomInvite{Room: "secret room", Key: attacker})

	got, ok := a.client.RoomKey("room-1")
	if !ok {
		t.Fatal("the room key vanished")
	}
	if got.ID() == attacker.ID() {
		t.Fatal("a non-member replaced the key we send under — our messages would go to them, not the room")
	}
	if got.ID() != original.ID() {
		t.Fatalf("room key changed unexpectedly: got %s, want %s", got.ID(), original.ID())
	}

	// The person who gave us the key can still rotate it.
	rotated, err := e2ee.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey: %v", err)
	}
	a.handleRoomInvite("alice", e2ee.RoomInvite{Room: "secret room", Key: rotated})
	if got, _ = a.client.RoomKey("room-1"); got.ID() != rotated.ID() {
		t.Error("a legitimate rotation from the member who invited us was rejected")
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
	oldKey, _ := e2ee.GenerateRoomKey()
	a.client.SetRoomKey("room-1", oldKey)
	a.members.setAll("room-1", []string{"alice", "bob", "dave"}, "carol")

	newKey, _ := e2ee.GenerateRoomKey()
	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:    "secret room",
		Key:     newKey,
		Members: []string{"alice", "bob", "carol"}, // dave is out
	})

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want %q — a removal did not propagate", got, "alice,bob")
	}
	if cur, ok := a.client.RoomKey("room-1"); !ok || cur.ID() != newKey.ID() {
		t.Error("the rotated key was not installed")
	}
}

// TestSameKeyRosterUnionsRatherThanReplaces: two people inviting at once must
// not erase each other's newcomer. Only a rotation replaces.
func TestSameKeyRosterUnionsRatherThanReplaces(t *testing.T) {
	a := rosterTestApp(t, "carol")
	key, _ := e2ee.GenerateRoomKey()
	a.client.SetRoomKey("room-1", key)
	// We invited Eve a moment ago; Alice has not heard about her yet.
	a.members.setAll("room-1", []string{"alice", "eve"}, "carol")

	a.handleRoomInvite("alice", e2ee.RoomInvite{
		Room:    "secret room",
		Key:     key,
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
	oldKey, _ := e2ee.GenerateRoomKey()
	a.client.SetRoomKey("room-1", oldKey)
	a.members.setAll("room-1", []string{"alice", "bob"}, "carol")

	newKey, _ := e2ee.GenerateRoomKey()
	a.handleRoomInvite("alice", e2ee.RoomInvite{Room: "secret room", Key: newKey})

	if got := sortedMembers(a, "room-1"); got != "alice,bob" {
		t.Errorf("members = %q, want %q — a rosterless invite emptied the room", got, "alice,bob")
	}
}

// TestNonMemberCannotInjectRoster: the membership check that stops a stranger
// replacing the room key must also stop them rewriting who is in the room —
// otherwise they could add themselves and rotate next time.
func TestNonMemberCannotInjectRoster(t *testing.T) {
	a := rosterTestApp(t, "carol")
	key, _ := e2ee.GenerateRoomKey()
	a.client.SetRoomKey("room-1", key)
	a.members.add("room-1", "alice")

	attackerKey, _ := e2ee.GenerateRoomKey()
	a.handleRoomInvite("mallory", e2ee.RoomInvite{
		Room:    "secret room",
		Key:     attackerKey,
		Members: []string{"mallory", "carol"},
	})

	if got := sortedMembers(a, "room-1"); got != "alice" {
		t.Errorf("members = %q — a non-member rewrote the roster", got)
	}
	if cur, ok := a.client.RoomKey("room-1"); !ok || cur.ID() != key.ID() {
		t.Error("a non-member replaced the room key")
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
