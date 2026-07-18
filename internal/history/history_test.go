package history

import (
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
	if err := Save("me", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load("me")
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
	got, err := Load("nobody")
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
	if err := Save("alice", Data{Conversations: []state.Conversation{conv("bob", state.Message{Text: "a", At: time.Unix(1, 0)})}}); err != nil {
		t.Fatal(err)
	}
	if err := Save("carol", Data{Conversations: []state.Conversation{conv("dave", state.Message{Text: "c", At: time.Unix(1, 0)})}}); err != nil {
		t.Fatal(err)
	}
	a, _ := Load("alice")
	if len(a.Conversations) != 1 || a.Conversations[0].ScreenName != "bob" {
		t.Fatalf("alice history bled: %+v", a)
	}
	c, _ := Load("carol")
	if len(c.Conversations) != 1 || c.Conversations[0].ScreenName != "dave" {
		t.Fatalf("carol history bled: %+v", c)
	}
}

func TestClear(t *testing.T) {
	isolate(t)
	if err := Save("me", Data{Conversations: []state.Conversation{conv("x", state.Message{Text: "y", At: time.Unix(1, 0)})}}); err != nil {
		t.Fatal(err)
	}
	if err := Clear("me"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, _ := Load("me")
	if len(got.Conversations) != 0 || len(got.Rooms) != 0 {
		t.Fatalf("history survived Clear: %+v", got)
	}
	if err := Clear("me"); err != nil {
		t.Fatalf("Clear on missing: %v", err)
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
