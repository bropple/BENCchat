package roomkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *[32]byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// TestSaveLoadRoundTrip: chain state and the members list survive a restart,
// which is the whole point — losing them locks the user out of their own room.
func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	key := testKey(t)

	want := Store{"4-0-secret": {
		Name:    "secret",
		Out:     "aabbccdd11223344:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		Views:   map[string]string{"1111222233334444": "enc-a", "5555666677778888": "enc-b"},
		Seen:    map[string]uint32{"1111222233334444": 42},
		Members: []string{"bob"},
		Updated: time.Now(),
	}}
	if err := Save("Alice", want, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load("alice", key) // normalization: same file either way
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	room, ok := got["4-0-secret"]
	if !ok {
		t.Fatal("room did not survive the round trip")
	}
	if room.Out != want["4-0-secret"].Out {
		t.Errorf("outbound chain mangled: %q", room.Out)
	}
	if len(room.Views) != 2 {
		t.Errorf("views mangled: %+v", room.Views)
	}
	if room.Seen["1111222233334444"] != 42 {
		t.Errorf("seen positions mangled: %+v", room.Seen)
	}
	if len(room.Members) != 1 || room.Members[0] != "bob" {
		t.Errorf("members mangled: %v", room.Members)
	}
}

// TestFileIsEncryptedAtRest: this file holds live chain state, which is worth
// the entire readable life of every room the account is in.
func TestFileIsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	key := testKey(t)

	if err := Save("alice", Store{"c": {Name: "very-secret-room", Out: "chain-material-here"}}, key); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "BENCchat", "rooms", "alice.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), sealedMagic) {
		t.Error("file is not sealed")
	}
	for _, leaked := range []string{"very-secret-room", "chain-material-here", "\"rooms\""} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("%q is readable on disk", leaked)
		}
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode is %v, want 0600", perm)
	}
}

// TestSaveRefusesWithoutAKey: a missing key is a programming error, never a
// licence to write live key material in the clear.
func TestSaveRefusesWithoutAKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := Save("alice", Store{"c": {Name: "n"}}, nil); err == nil {
		t.Fatal("saved without an encryption key")
	}
	if _, err := os.Stat(filepath.Join(dir, "BENCchat", "rooms", "alice.json")); !os.IsNotExist(err) {
		t.Error("a file was written despite the refusal")
	}
}

// TestWrongKeyRefusesRatherThanReturningEmpty is the dangerous case.
//
// Returning an empty store would look exactly like "no rooms yet", and the next
// save would overwrite real chain state with nothing — locking the account out
// of every room it is in. It has to be an error.
func TestWrongKeyRefusesRatherThanReturningEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := Save("alice", Store{"c": {Name: "n", Out: "chain"}}, testKey(t)); err != nil {
		t.Fatal(err)
	}
	got, err := Load("alice", testKey(t)) // a different key
	if err == nil {
		t.Fatal("loading with the wrong key succeeded")
	}
	if len(got) != 0 {
		t.Error("a partial store was returned alongside the error")
	}
}

// TestMissingFileIsFirstRun: absent is not an error, or every new account would
// look broken.
func TestMissingFileIsFirstRun(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := Load("nobody", testKey(t))
	if err != nil {
		t.Fatalf("Load on a missing file: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("got %+v, want an empty non-nil store", got)
	}
}
