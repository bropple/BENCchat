package main

import (
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
