package history

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/state"
)

// isolate points os.UserConfigDir at a temp dir so tests never touch the real
// config location. On Linux UserConfigDir honors XDG_CONFIG_HOME.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// key mints a history key for a test.
func key(t *testing.T) *[32]byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// readFile returns the raw bytes on disk for an account, so tests can assert
// about the container rather than only about what Load hands back.
func readFile(t *testing.T, account string) []byte {
	t.Helper()
	p, err := path(account)
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return raw
}

func conv(sn string, msgs ...state.Message) state.Conversation {
	return state.Conversation{Key: state.NormalizeScreenName(sn), ScreenName: sn, Messages: msgs}
}

func room(cookie, name string, msgs ...state.Message) state.Room {
	return state.Room{Cookie: cookie, Name: name, Messages: msgs}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	isolate(t)
	want := Data{
		Conversations: []state.Conversation{
			conv("rtriy",
				state.Message{From: "rtriy", To: "me", Text: "hi", At: time.Unix(1000, 0)},
				state.Message{From: "me", To: "rtriy", Text: "hey", At: time.Unix(1001, 0), Outgoing: true},
			),
		},
		Rooms: []state.Room{
			room("4-0-lobby", "lobby", state.Message{From: "alice", Text: "yo", At: time.Unix(1002, 0)}),
		},
	}
	k := key(t)
	if err := Save("me", want, k); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The point of the exercise: what lands on disk is sealed, and the messages
	// are not sitting there in the clear for anything that can read the file.
	raw := readFile(t, "me")
	if !bytes.HasPrefix(raw, []byte(sealedMagic)) {
		t.Fatalf("history file is not sealed: starts %q", raw[:min(len(raw), 16)])
	}
	if bytes.Contains(raw, []byte("hey")) || bytes.Contains(raw, []byte("lobby")) {
		t.Fatal("message text is readable in the saved file")
	}

	got, err := Load("me", k)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Conversations) != 1 || len(got.Conversations[0].Messages) != 2 {
		t.Fatalf("conversation round-trip wrong: %+v", got.Conversations)
	}
	if !got.Conversations[0].Messages[1].Outgoing {
		t.Fatalf("message fields lost: %+v", got.Conversations[0].Messages)
	}
	if len(got.Rooms) != 1 || got.Rooms[0].Name != "lobby" || got.Rooms[0].Messages[0].Text != "yo" {
		t.Fatalf("room round-trip wrong: %+v", got.Rooms)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	isolate(t)
	got, err := Load("nobody", key(t))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(got.Conversations) != 0 || len(got.Rooms) != 0 {
		t.Fatalf("missing history returned %+v, want empty", got)
	}
}

// Two accounts on the same machine must not share history.
func TestPerAccountIsolation(t *testing.T) {
	isolate(t)
	// Separate keys as well as separate files: accounts on one machine share
	// neither.
	ka, kc := key(t), key(t)
	if err := Save("alice", Data{Conversations: []state.Conversation{conv("bob", state.Message{Text: "a", At: time.Unix(1, 0)})}}, ka); err != nil {
		t.Fatal(err)
	}
	if err := Save("carol", Data{Conversations: []state.Conversation{conv("dave", state.Message{Text: "c", At: time.Unix(1, 0)})}}, kc); err != nil {
		t.Fatal(err)
	}
	a, _ := Load("alice", ka)
	if len(a.Conversations) != 1 || a.Conversations[0].ScreenName != "bob" {
		t.Fatalf("alice history bled: %+v", a)
	}
	c, _ := Load("carol", kc)
	if len(c.Conversations) != 1 || c.Conversations[0].ScreenName != "dave" {
		t.Fatalf("carol history bled: %+v", c)
	}
}

func TestClear(t *testing.T) {
	isolate(t)
	k := key(t)
	if err := Save("me", Data{Conversations: []state.Conversation{conv("x", state.Message{Text: "y", At: time.Unix(1, 0)})}}, k); err != nil {
		t.Fatal(err)
	}
	if err := Clear("me"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, _ := Load("me", k)
	if len(got.Conversations) != 0 || len(got.Rooms) != 0 {
		t.Fatalf("history survived Clear: %+v", got)
	}
	if err := Clear("me"); err != nil {
		t.Fatalf("Clear on missing: %v", err)
	}
}

// A history file written before encryption existed is bare JSON. It must still
// load — an upgrade that silently loses everything the user ever said is not an
// upgrade — and the next save must seal it.
func TestLoadsPlaintextFromOlderVersion(t *testing.T) {
	isolate(t)
	p, err := path("me")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(fileFormat{
		Version: 1,
		Data: Data{Conversations: []state.Conversation{
			conv("rtriy", state.Message{From: "rtriy", Text: "from before", At: time.Unix(1000, 0)}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	k := key(t)
	got, err := Load("me", k)
	if err != nil {
		t.Fatalf("Load(plaintext): %v", err)
	}
	if len(got.Conversations) != 1 || got.Conversations[0].Messages[0].Text != "from before" {
		t.Fatalf("plaintext history did not migrate: %+v", got)
	}

	// Re-encrypted on the next save, so the migration actually completes rather
	// than leaving the file readable forever.
	if err := Save("me", got, k); err != nil {
		t.Fatalf("Save after migration: %v", err)
	}
	if raw := readFile(t, "me"); !bytes.HasPrefix(raw, []byte(sealedMagic)) {
		t.Fatal("a migrated file was rewritten in the clear")
	}
	again, err := Load("me", k)
	if err != nil || len(again.Conversations) != 1 {
		t.Fatalf("re-encrypted history did not load back: %+v, %v", again, err)
	}
}

// The wrong key must be an ERROR, not an empty history. Empty would read as "no
// history yet" to every caller, and the next save would overwrite a real file
// with nothing — losing to a key mix-up what the encryption was protecting.
func TestLoadWithWrongKeyFails(t *testing.T) {
	isolate(t)
	if err := Save("me", Data{Conversations: []state.Conversation{
		conv("x", state.Message{Text: "secret", At: time.Unix(1, 0)}),
	}}, key(t)); err != nil {
		t.Fatal(err)
	}

	got, err := Load("me", key(t)) // a different key
	if err == nil {
		t.Fatalf("Load with the wrong key succeeded, returning %+v", got)
	}
	if len(got.Conversations) != 0 {
		t.Fatalf("a failed decrypt leaked data: %+v", got)
	}

	// A sealed file with no key at all is the same refusal, since that is what
	// the app passes when the keyring could not be read.
	if _, err := Load("me", nil); err == nil {
		t.Fatal("Load of a sealed file with no key succeeded")
	}
}

// Save without a key must refuse outright. The tempting fallback — write it in
// the clear "just this once" — is exactly the outcome encrypting history exists
// to prevent, so there must be no file and no stray temp file either.
func TestSaveWithoutKeyRefuses(t *testing.T) {
	isolate(t)
	d := Data{Conversations: []state.Conversation{
		conv("x", state.Message{Text: "must not be written", At: time.Unix(1, 0)}),
	}}
	err := Save("me", d, nil)
	if err == nil {
		t.Fatal("Save with a nil key succeeded")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error should say what was missing, got %q", err)
	}

	p, perr := path("me")
	if perr != nil {
		t.Fatal(perr)
	}
	if _, serr := os.Stat(p); !os.IsNotExist(serr) {
		t.Fatal("a keyless Save wrote a history file")
	}
	if _, serr := os.Stat(p + ".tmp"); !os.IsNotExist(serr) {
		t.Fatal("a keyless Save left a plaintext temp file behind")
	}

	// And an existing file is left exactly as it was, rather than truncated by
	// an attempt that then failed.
	k := key(t)
	if err := Save("me", d, k); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, "me")
	if err := Save("me", Data{}, nil); err == nil {
		t.Fatal("Save with a nil key succeeded over an existing file")
	}
	if !bytes.Equal(before, readFile(t, "me")) {
		t.Fatal("a refused Save modified the existing history file")
	}
}

func TestPrune(t *testing.T) {
	old := time.Unix(1000, 0)
	recent := time.Unix(1_000_000, 0)
	cutoff := time.Unix(500_000, 0)

	in := Data{
		Conversations: []state.Conversation{
			conv("keep", state.Message{Text: "old", At: old}, state.Message{Text: "new", At: recent}),
			conv("drop", state.Message{Text: "ancient", At: old}),
		},
		Rooms: []state.Room{
			room("4-0-live", "live", state.Message{Text: "old", At: old}, state.Message{Text: "fresh", At: recent}),
			room("4-0-dead", "dead", state.Message{Text: "ancient", At: old}),
		},
	}
	got := Prune(in, cutoff)

	if len(got.Conversations) != 1 || got.Conversations[0].ScreenName != "keep" ||
		len(got.Conversations[0].Messages) != 1 || got.Conversations[0].Messages[0].Text != "new" {
		t.Fatalf("conversation prune wrong: %+v", got.Conversations)
	}
	if len(got.Rooms) != 1 || got.Rooms[0].Name != "live" ||
		len(got.Rooms[0].Messages) != 1 || got.Rooms[0].Messages[0].Text != "fresh" {
		t.Fatalf("room prune wrong: %+v", got.Rooms)
	}
	// Input untouched.
	if len(in.Conversations[0].Messages) != 2 || len(in.Rooms[0].Messages) != 2 {
		t.Fatal("Prune mutated its input")
	}
	// Zero cutoff passes everything through.
	if same := Prune(in, time.Time{}); len(same.Conversations) != 2 || len(same.Rooms) != 2 {
		t.Fatalf("zero cutoff should pass all through, got %+v", same)
	}
}
