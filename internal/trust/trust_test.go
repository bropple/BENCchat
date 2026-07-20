package trust

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveLoadRoundTrip verifies verified keys persist and reload per account,
// using a temp config dir so the test never touches real user state.
func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	want := Store{"bob": {Verified: "AAAA", Seen: "AAAA"}, "carol": {Seen: "BBBB"}}
	if err := Save("Alice", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load("alice") // normalization: "Alice" and "alice" share a file
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(want) || got["bob"].Verified != "AAAA" || got["carol"].Seen != "BBBB" {
		t.Fatalf("round-trip mismatch: got %v, want %v", got, want)
	}
}

// TestLoadMissingIsEmpty: a first-run account with no file loads an empty,
// non-nil store rather than erroring.
func TestLoadMissingIsEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := Load("nobody")
	if err != nil {
		t.Fatalf("Load of missing file errored: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned a nil store; want empty non-nil")
	}
	if len(got) != 0 {
		t.Fatalf("Load of missing file returned %d entries, want 0", len(got))
	}
}

// TestPerAccountIsolation: two accounts don't share verification state.
func TestPerAccountIsolation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := Save("alice", Store{"bob": {Verified: "AAAA"}}); err != nil {
		t.Fatal(err)
	}
	if err := Save("dave", Store{"bob": {Verified: "ZZZZ"}}); err != nil {
		t.Fatal(err)
	}
	a, _ := Load("alice")
	d, _ := Load("dave")
	if a["bob"] == d["bob"] {
		t.Fatal("accounts shared verification state")
	}
}

// TestSafeNameStaysInDir: an account with path-y characters can't escape the
// trust directory.
func TestSafeNameStaysInDir(t *testing.T) {
	name := safeName("../../etc/passwd")
	if filepath.Base(name) != name {
		t.Fatalf("safeName produced a path with separators: %q", name)
	}
}

// TestLoadLegacyFormat: trust files written before the store tracked a
// last-seen key mapped each peer straight to a verified-key string. Those files
// must still load — and that key was by definition also the last one seen, so
// it populates both fields rather than resetting trust-on-first-use.
func TestLoadLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, err := path("alice")
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"peers":{"bob":"AAAA"}}`
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load("alice")
	if err != nil {
		t.Fatalf("Load of a legacy file errored: %v", err)
	}
	if got["bob"].Verified != "AAAA" {
		t.Errorf("legacy verified key = %q, want AAAA", got["bob"].Verified)
	}
	if got["bob"].Seen != "AAAA" {
		t.Errorf("legacy last-seen key = %q, want AAAA — a change would go unnoticed", got["bob"].Seen)
	}
}

// The counter high-water mark is the rollback defence, so it has to survive
// both a round trip and the unrelated writes that happen constantly around it.
// A peer save that quietly reset the identity pin would re-arm every replay the
// pin exists to refuse, and nothing would look wrong until it was exploited.
func TestIdentityPinsSurviveUnrelatedWrites(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	const acct = "alice"

	if err := SaveSelfIdentity(acct, Identity{Key: "self-key", Counter: 7}); err != nil {
		t.Fatalf("SaveSelfIdentity: %v", err)
	}
	// A peer verification lands afterwards, through the other write path.
	if err := Save(acct, Store{"bob": Entry{
		Verified: "bob-identity",
		Seen:     "bob-dev1,bob-dev2",
		Identity: Identity{Key: "bob-identity", Counter: 3},
	}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	self, err := LoadSelfIdentity(acct)
	if err != nil {
		t.Fatalf("LoadSelfIdentity: %v", err)
	}
	if self.Key != "self-key" || self.Counter != 7 {
		t.Errorf("self identity pin = %+v, want it preserved across a peer save", self)
	}

	f, err := LoadFile(acct)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := f.Peers["bob"].Identity; got.Key != "bob-identity" || got.Counter != 3 {
		t.Errorf("peer identity pin = %+v, want it round-tripped", got)
	}
	if f.Peers["bob"].Seen != "bob-dev1,bob-dev2" {
		t.Error("the peer's device set was lost")
	}

	// And the self pin write must not flatten the peers it doesn't touch.
	if err := SaveSelfIdentity(acct, Identity{Key: "self-key", Counter: 8}); err != nil {
		t.Fatalf("SaveSelfIdentity: %v", err)
	}
	f, _ = LoadFile(acct)
	if f.Peers["bob"].Identity.Counter != 3 {
		t.Error("peer trust was lost when the self identity pin advanced")
	}
	if f.Self.Counter != 8 {
		t.Errorf("self counter = %d, want 8", f.Self.Counter)
	}
}
