package e2ee

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// TestRosterRoundTrips: a roster crosses the wire intact and verifies.
func TestRosterRoundTrips(t *testing.T) {
	kp := mustSigner(t)
	in, err := SignRoster(Roster{
		Room: "a room: with punctuation", Epoch: 7,
		Members: []string{"alice", "bob, jr", "carol"},
		Author:  "alice",
	}, kp)
	if err != nil {
		t.Fatalf("SignRoster: %v", err)
	}

	body, err := EncodeRoster(in)
	if err != nil {
		t.Fatalf("EncodeRoster: %v", err)
	}
	if !IsRoster(body) {
		t.Fatal("output not recognized as a roster")
	}
	got, err := DecodeRoster(body)
	if err != nil {
		t.Fatalf("DecodeRoster: %v", err)
	}
	if got.Room != in.Room || got.Epoch != in.Epoch || got.Author != in.Author {
		t.Errorf("header mangled: %+v", got)
	}
	if strings.Join(got.Members, "|") != strings.Join(in.Members, "|") {
		t.Errorf("members mangled: %v", got.Members)
	}
	if err := VerifyRoster(got, []ed25519.PublicKey{kp.Public}); err != nil {
		t.Errorf("a round-tripped roster did not verify: %v", err)
	}
}

// TestRosterSignatureCoversEveryField: anything a recipient acts on must be
// signed, or an attacker edits the part that isn't.
func TestRosterSignatureCoversEveryField(t *testing.T) {
	kp := mustSigner(t)
	base, _ := SignRoster(Roster{
		Room: "project", Epoch: 3, Members: []string{"alice", "bob"}, Author: "alice",
	}, kp)

	tamper := map[string]func(Roster) Roster{
		"room":            func(r Roster) Roster { r.Room = "other"; return r },
		"epoch":           func(r Roster) Roster { r.Epoch = 99; return r },
		"author":          func(r Roster) Roster { r.Author = "mallory"; return r },
		"a member":        func(r Roster) Roster { r.Members = []string{"alice", "mallory"}; return r },
		"member count":    func(r Roster) Roster { r.Members = []string{"alice"}; return r },
		"member ordering": func(r Roster) Roster { r.Members = []string{"bob", "alice"}; return r },
	}
	for name, edit := range tamper {
		if err := VerifyRoster(edit(base), []ed25519.PublicKey{kp.Public}); !errors.Is(err, ErrRosterSignature) {
			t.Errorf("editing %s left the signature valid", name)
		}
	}
}

// TestRosterFieldsAreUnambiguous: a roster carries three variable-length strings
// and a list of them, so the encoding must not let one field's content be read
// as another's boundary.
func TestRosterFieldsAreUnambiguous(t *testing.T) {
	kp := mustSigner(t)
	a, _ := SignRoster(Roster{Room: "a", Author: "b\x00c", Members: []string{"m"}}, kp)
	b, _ := SignRoster(Roster{Room: "a\x00b", Author: "c", Members: []string{"m"}}, kp)
	if string(rosterSigningContext(a)) == string(rosterSigningContext(b)) {
		t.Error("a NUL in a field shifts the boundary; length prefixes are missing")
	}
}

// TestRosterIsNotAnotherSignature: the device signing key also signs room
// messages and device attestations. None may spell another.
func TestRosterIsNotAnotherSignature(t *testing.T) {
	kp := mustSigner(t)
	r, _ := SignRoster(Roster{Room: "project", Epoch: 1, Members: []string{"alice"}, Author: "alice"}, kp)
	ctx := rosterSigningContext(r)

	if string(ctx[:len(rosterDomain)]) != rosterDomain {
		t.Fatal("roster context does not begin with its domain tag")
	}
	// A roster signature must not verify as a room message or an attestation,
	// and neither of theirs as a roster.
	nonce := []byte("a-32-byte-nonce-for-attestation!")
	if VerifyAttestation("alice", nonce, kp.Public, r.Signature) {
		t.Error("a roster signature verified as a device attestation")
	}
	attest := SignAttestation("alice", nonce, kp.Private)
	forged := r
	forged.Signature = attest
	if err := VerifyRoster(forged, []ed25519.PublicKey{kp.Public}); err == nil {
		t.Error("an attestation signature verified as a roster")
	}
}

// TestRosterRefusesImplausibleCounts: the member count arrives from the wire, so
// it must not be able to make us allocate without limit.
func TestRosterRefusesImplausibleCounts(t *testing.T) {
	kp := mustSigner(t)
	huge := make([]string, maxRosterMembers+1)
	for i := range huge {
		huge[i] = "someone"
	}
	if _, err := SignRoster(Roster{Room: "r", Members: huge}, kp); err == nil {
		t.Error("an oversized roster was signed instead of refused")
	}
	if _, err := DecodeRoster(RosterPrefix + "!!!not-base64"); err == nil {
		t.Error("a malformed roster decoded")
	}
}
