package roomkeys

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSaveLoadRoundTrip: keys and the members list survive a restart, which is
// the whole point — losing them locks the user out of their own room.
func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	want := Store{"4-0-secret": {
		Name:      "secret",
		Keys:      map[string]string{"aabb": "a2V5MQ==", "ccdd": "a2V5Mg=="},
		CurrentID: "ccdd",
		Members:   []string{"bob"},
		Updated:   time.Now(),
	}}
	if err := Save("Alice", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load("alice") // normalization: same file either way
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	room, ok := got["4-0-secret"]
	if !ok {
		t.Fatal("room did not survive the round trip")
	}
	if room.CurrentID != "ccdd" || len(room.Keys) != 2 {
		t.Errorf("keys mangled: %+v", room)
	}
	if len(room.Members) != 1 || room.Members[0] != "bob" {
		t.Errorf("members mangled: %v", room.Members)
	}
	// Retired keys must be kept, or scrollback from before a rotation is lost.
	if _, ok := room.Keys["aabb"]; !ok {
		t.Error("the retired key was dropped — older messages would be unreadable")
	}
}

// TestFileIsNotWorldReadable: this file holds live message keys.
func TestFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := Save("alice", Store{"c": {Name: "n", Keys: map[string]string{"a": "b"}}}); err != nil {
		t.Fatal(err)
	}
	p, err := path("alice")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("room key file mode is %o — group/other can read the keys", mode)
	}
	di, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("room key directory mode is %o", mode)
	}
}

// TestMissingFileIsEmpty: first run is not an error.
func TestMissingFileIsEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := Load("nobody")
	if err != nil {
		t.Fatalf("Load of a missing file errored: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("want an empty non-nil store, got %v", got)
	}
}

// TestForgetRemovesOneRoom: leaving a room drops its keys but not others'.
func TestForgetRemovesOneRoom(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := Save("alice", Store{
		"room-a": {Name: "a", Keys: map[string]string{"1": "x"}},
		"room-b": {Name: "b", Keys: map[string]string{"2": "y"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Forget("alice", "room-a"); err != nil {
		t.Fatal(err)
	}
	got, _ := Load("alice")
	if _, ok := got["room-a"]; ok {
		t.Error("forgotten room is still present")
	}
	if _, ok := got["room-b"]; !ok {
		t.Error("forgetting one room removed another")
	}
}

// TestPerAccountIsolation: two screen names on one machine don't share keys.
func TestPerAccountIsolation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_ = Save("alice", Store{"r": {Name: "r", Keys: map[string]string{"1": "aaa"}}})
	_ = Save("bob", Store{"r": {Name: "r", Keys: map[string]string{"1": "bbb"}}})
	a, _ := Load("alice")
	b, _ := Load("bob")
	if a["r"].Keys["1"] == b["r"].Keys["1"] {
		t.Error("accounts shared room keys")
	}
}
