package state

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestNormalizeScreenName(t *testing.T) {
	// OSCAR screen names ignore case and spaces: all of these are one account.
	for _, in := range []string{"R Triy", "rtriy", "RTriy", "r t r i y"} {
		if got := NormalizeScreenName(in); got != "rtriy" {
			t.Errorf("NormalizeScreenName(%q) = %q, want %q", in, got, "rtriy")
		}
	}
}

func TestUpdatePresenceMatchesAcrossSpacingAndCase(t *testing.T) {
	s := NewStore()
	s.ReplaceBuddyList([]Buddy{{ScreenName: "rtriy", Group: "BENCO"}}, []string{"BENCO"})

	// The server announces arrivals using its own casing/spacing; it must land on
	// the existing row rather than creating a duplicate.
	s.UpdatePresence("R Triy", PresenceOnline, "", time.Time{}, time.Now())

	if n := len(s.Buddies()); n != 1 {
		t.Fatalf("buddy count = %d, want 1 (presence update must not duplicate the row)", n)
	}
	b, ok := s.Buddy("rtriy")
	if !ok {
		t.Fatal("buddy not found by normalized key")
	}
	if b.Presence != PresenceOnline {
		t.Errorf("Presence = %q, want online", b.Presence)
	}
	if b.Group != "BENCO" {
		t.Errorf("Group = %q, want BENCO (existing row must be updated, not replaced)", b.Group)
	}
}

func TestReplaceBuddyListPreservesPresence(t *testing.T) {
	s := NewStore()
	s.ReplaceBuddyList([]Buddy{{ScreenName: "rtriy", Group: "BENCO"}}, []string{"BENCO"})
	s.UpdatePresence("rtriy", PresenceAway, "Out to lunch", time.Time{}, time.Now())

	// A feedbag reload describes list membership only — it says nothing about who
	// is online, so it must not blank out presence we already learned.
	s.ReplaceBuddyList([]Buddy{
		{ScreenName: "rtriy", Group: "BENCO"},
		{ScreenName: "newguy", Group: "BENCO"},
	}, []string{"BENCO"})

	b, _ := s.Buddy("rtriy")
	if b.Presence != PresenceAway {
		t.Errorf("Presence after reload = %q, want away (must be preserved)", b.Presence)
	}
	if b.AwayMessage != "Out to lunch" {
		t.Errorf("AwayMessage = %q, want preserved", b.AwayMessage)
	}
	if nb, ok := s.Buddy("newguy"); !ok || nb.Presence != PresenceOffline {
		t.Errorf("new buddy presence = %q, want offline default", nb.Presence)
	}
}

func TestReplaceBuddyListDropsRemovedBuddies(t *testing.T) {
	s := NewStore()
	s.ReplaceBuddyList([]Buddy{{ScreenName: "gone"}, {ScreenName: "stays"}}, nil)
	s.ReplaceBuddyList([]Buddy{{ScreenName: "stays"}}, nil)

	if _, ok := s.Buddy("gone"); ok {
		t.Error("buddy removed from the list should not survive a reload")
	}
	if _, ok := s.Buddy("stays"); !ok {
		t.Error("remaining buddy should survive a reload")
	}
}

func TestUpdatePresenceAddsUnknownBuddy(t *testing.T) {
	// The server can announce accounts we have no feedbag row for; dropping them
	// would lose context for messages that follow.
	s := NewStore()
	s.UpdatePresence("stranger", PresenceOnline, "", time.Time{}, time.Now())

	if b, ok := s.Buddy("stranger"); !ok || b.Presence != PresenceOnline {
		t.Fatal("presence update for an unknown buddy should add them")
	}
}

func TestBuddiesSortGroupsThenOnlineThenName(t *testing.T) {
	s := NewStore()
	s.ReplaceBuddyList([]Buddy{
		{ScreenName: "zeta", Group: "Work"},
		{ScreenName: "alpha", Group: "Work"},
		{ScreenName: "beta", Group: "Family"},
	}, []string{"Family", "Work"})
	s.UpdatePresence("zeta", PresenceOnline, "", time.Time{}, time.Now())

	got := s.Buddies()
	want := []string{"beta", "zeta", "alpha"} // Family first; in Work, online zeta before offline alpha
	for i, w := range want {
		if got[i].ScreenName != w {
			t.Fatalf("sort order = %v, want %v", names(got), want)
		}
	}
}

func names(bs []Buddy) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.ScreenName
	}
	return out
}

func TestBuddyDisplayPrefersAlias(t *testing.T) {
	if got := (Buddy{ScreenName: "rtriy", Alias: "R. Triy"}).Display(); got != "R. Triy" {
		t.Errorf("Display() = %q, want the alias", got)
	}
	if got := (Buddy{ScreenName: "rtriy"}).Display(); got != "rtriy" {
		t.Errorf("Display() = %q, want the screen name when no alias", got)
	}
}

func TestAddMessageKeysConversationByOtherParty(t *testing.T) {
	s := NewStore()
	s.AddMessage(Message{From: "R Triy", To: "me", Text: "hi", At: time.Now()})
	s.AddMessage(Message{From: "me", To: "rtriy", Text: "hello", At: time.Now(), Outgoing: true})

	// Both directions must land in ONE thread, keyed by the normalized name of
	// the other party.
	if n := len(s.Conversations()); n != 1 {
		t.Fatalf("conversation count = %d, want 1", n)
	}
	c, ok := s.Conversation("rtriy")
	if !ok {
		t.Fatal("conversation not found")
	}
	if len(c.Messages) != 2 {
		t.Fatalf("message count = %d, want 2", len(c.Messages))
	}
	// Only the inbound message counts as unread.
	if c.Unread != 1 {
		t.Errorf("Unread = %d, want 1 (outgoing messages must not count)", c.Unread)
	}
}

func TestMarkRead(t *testing.T) {
	s := NewStore()
	s.AddMessage(Message{From: "rtriy", To: "me", Text: "hi", At: time.Now()})
	s.MarkRead("R Triy") // normalization must apply here too

	c, _ := s.Conversation("rtriy")
	if c.Unread != 0 {
		t.Errorf("Unread = %d after MarkRead, want 0", c.Unread)
	}
}

func TestConversationScrollbackIsBounded(t *testing.T) {
	s := NewStore()
	for i := 0; i < maxMessagesPerConversation+50; i++ {
		s.AddMessage(Message{From: "rtriy", To: "me", Text: "spam", At: time.Now()})
	}
	c, _ := s.Conversation("rtriy")
	if len(c.Messages) != maxMessagesPerConversation {
		t.Fatalf("scrollback = %d messages, want capped at %d", len(c.Messages), maxMessagesPerConversation)
	}
}

func TestConversationSnapshotIsACopy(t *testing.T) {
	s := NewStore()
	s.AddMessage(Message{From: "rtriy", To: "me", Text: "original", At: time.Now()})

	c, _ := s.Conversation("rtriy")
	c.Messages[0].Text = "mutated"

	again, _ := s.Conversation("rtriy")
	if again.Messages[0].Text != "original" {
		t.Error("Conversation() must return a copy; caller mutated store state")
	}
}

func TestSubscribeAndUnsubscribe(t *testing.T) {
	s := NewStore()

	var mu sync.Mutex
	var got []string
	unsub := s.Subscribe(func(e Event) {
		mu.Lock()
		got = append(got, e.Kind)
		mu.Unlock()
	})

	s.SetSelf("me")
	s.UpdatePresence("rtriy", PresenceOnline, "", time.Time{}, time.Now())
	unsub()
	s.UpdatePresence("rtriy", PresenceOffline, "", time.Time{}, time.Time{})

	mu.Lock()
	defer mu.Unlock()
	want := []string{EventSelfChanged, EventBuddyChanged}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v (unsubscribe must stop delivery)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}

// TestSubscriberMayReadStore guards the emit-without-lock contract: a
// subscriber calling back into the Store must not deadlock.
func TestSubscriberMayReadStore(t *testing.T) {
	s := NewStore()
	done := make(chan struct{})

	s.Subscribe(func(e Event) {
		_ = s.Buddies()
		_ = s.Self()
		close(done)
	})
	s.SetSelf("me")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber deadlocked reading the Store from a callback")
	}
}

func TestSetAwayTogglesPresence(t *testing.T) {
	s := NewStore()
	s.SetSelf("me")

	s.SetAway("brb")
	if self := s.Self(); self.Presence != PresenceAway || self.AwayMessage != "brb" {
		t.Fatalf("self = %+v, want away with message", self)
	}
	s.SetAway("")
	if self := s.Self(); self.Presence != PresenceOnline || self.AwayMessage != "" {
		t.Fatalf("self = %+v, want online with no message", self)
	}
}

func TestResetClearsEverything(t *testing.T) {
	s := NewStore()
	s.SetSelf("me")
	s.ReplaceBuddyList([]Buddy{{ScreenName: "rtriy"}}, []string{"BENCO"})
	s.AddMessage(Message{From: "rtriy", To: "me", Text: "hi", At: time.Now()})

	s.Reset()

	if len(s.Buddies()) != 0 || len(s.Conversations()) != 0 || len(s.Groups()) != 0 {
		t.Error("Reset must clear buddies, conversations, and groups")
	}
	if s.Self().Presence != PresenceOffline {
		t.Error("Reset must mark self offline")
	}
}

// TestConcurrentAccess exercises the lock discipline: the protocol read loop
// writes while the UI reads.
func TestConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.UpdatePresence("rtriy", PresenceOnline, "", time.Time{}, time.Now())
				s.AddMessage(Message{From: "rtriy", To: "me", Text: "hi", At: time.Now()})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = s.Buddies()
				_, _ = s.Conversation("rtriy")
			}
		}()
	}
	wg.Wait()
}

func TestBuddyIconCache(t *testing.T) {
	s := NewStore()
	s.ReplaceBuddyList([]Buddy{{ScreenName: "picguy", Group: "BENCO"}}, []string{"BENCO"})

	const hash = "0102030405060708090a0b0c0d0e0f10"
	png := []byte("\x89PNG\r\n\x1a\nfake")

	// Arrival records only the hash; the bytes haven't landed, so serving returns
	// nothing yet — but we must report that we still need to download this hash.
	s.SetBuddyIcon("picguy", hash, nil)
	if b, _ := s.Buddy("picguy"); b.IconHash != hash {
		t.Fatalf("IconHash = %q, want %q", b.IconHash, hash)
	}
	if s.HaveIcon(hash) {
		t.Fatal("HaveIcon true before bytes arrived")
	}
	if s.BuddyIconData("picguy") != nil {
		t.Fatal("served icon bytes before they arrived")
	}

	// The download lands: bytes are cached and served, and we no longer need it.
	s.SetBuddyIcon("picguy", hash, png)
	if !s.HaveIcon(hash) {
		t.Fatal("HaveIcon false after caching")
	}
	if got := s.BuddyIconData("picguy"); !bytes.Equal(got, png) {
		t.Fatalf("BuddyIconData = %x, want %x", got, png)
	}

	// A feedbag reload carries no icon hash; it must not drop the cached icon.
	s.ReplaceBuddyList([]Buddy{{ScreenName: "picguy", Group: "BENCO"}}, []string{"BENCO"})
	if got := s.BuddyIconData("picguy"); !bytes.Equal(got, png) {
		t.Fatalf("icon lost across reload: %x", got)
	}

	// Clearing the icon (empty hash) stops serving it.
	s.SetBuddyIcon("picguy", "", nil)
	if s.BuddyIconData("picguy") != nil {
		t.Fatal("still serving icon after clear")
	}
}

func TestRoomsRestoreJoinAndMessages(t *testing.T) {
	s := NewStore()

	// Restored recents come back not-joined, with their scrollback.
	s.RestoreRooms([]Room{
		{Cookie: "4-0-lobby", Name: "lobby", Joined: true, Participants: []string{"stale"},
			Messages: []Message{{From: "x", Text: "hi", At: time.Unix(1, 0)}}},
	})
	r, ok := s.Room("4-0-lobby")
	if !ok || r.Joined || len(r.Participants) != 0 || len(r.Messages) != 1 {
		t.Fatalf("restored room wrong: %+v", r)
	}

	// Joining marks it live; roster + messages accrue on top of the scrollback.
	s.SetRoomJoined("4-0-lobby", true)
	s.RoomUsersJoined("4-0-lobby", []string{"me", "alice"})
	s.AddRoomMessage("4-0-lobby", Message{From: "alice", Text: "yo", At: time.Unix(2, 0)})
	r, _ = s.Room("4-0-lobby")
	if !r.Joined || len(r.Participants) != 2 || len(r.Messages) != 2 {
		t.Fatalf("joined room wrong: %+v", r)
	}

	// Leaving keeps it (as a recent) but drops the live roster.
	s.SetRoomJoined("4-0-lobby", false)
	r, _ = s.Room("4-0-lobby")
	if r.Joined || len(r.Participants) != 0 || len(r.Messages) != 2 {
		t.Fatalf("left room should stay with scrollback, no roster: %+v", r)
	}

	// Forgetting removes it entirely.
	s.RemoveRoom("4-0-lobby")
	if _, ok := s.Room("4-0-lobby"); ok {
		t.Fatal("room survived RemoveRoom")
	}
}

// TestDecryptPendingDoesNotHoldTheLock is the regression guard on a deadlock
// that hung the whole application.
//
// The decrypt callback belongs to the client layer and may do arbitrary work —
// recovering a room invitation, for instance, which reads this same store.
// Running it under the write lock meant the read could never be granted
// (RWMutex is not reentrant), so every later store access queued behind it,
// including the flush that runs at shutdown. Quitting appeared to crash.
func TestDecryptPendingDoesNotHoldTheLock(t *testing.T) {
	s := NewStore()
	s.SetSelf("alice")
	s.AddMessage(Message{From: "alice", To: "alice", Text: "placeholder", Cipher: "CIPHER", At: time.Now()})

	done := make(chan bool, 1)
	go func() {
		// The callback reads the store, exactly as recovering a room invite does.
		done <- s.DecryptPending("alice", func(cipher string) (string, bool) {
			_ = s.Rooms()
			_, _ = s.Conversation("alice")
			_ = s.Buddies()
			return "recovered: " + cipher, true
		})
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("DecryptPending reported no change")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DecryptPending deadlocked: the callback touched the store while the lock was held")
	}

	convo, _ := s.Conversation("alice")
	if len(convo.Messages) != 1 || convo.Messages[0].Text != "recovered: CIPHER" {
		t.Fatalf("message not recovered: %+v", convo.Messages)
	}
	if convo.Messages[0].Cipher != "" {
		t.Error("ciphertext retained after a successful decrypt")
	}
	if !convo.Messages[0].Encrypted {
		t.Error("recovered message not flagged encrypted")
	}
}

// TestConversationBasics covers the thread bookkeeping the UI depends on.
func TestConversationBasics(t *testing.T) {
	s := NewStore()
	s.SetSelf("alice")

	s.AddMessage(Message{From: "alice", To: "alice", Text: "in", At: time.Now()})
	s.AddMessage(Message{From: "alice", To: "alice", Text: "out", Outgoing: true, At: time.Now().Add(time.Second)})

	c, ok := s.Conversation("ALICE") // screen names are case-insensitive
	if !ok {
		t.Fatal("conversation not found by differently-cased name")
	}
	if len(c.Messages) != 2 {
		t.Fatalf("got %d messages, want 2", len(c.Messages))
	}
	if c.Unread != 1 {
		t.Errorf("unread = %d, want 1 (only the inbound message counts)", c.Unread)
	}

	// Snapshots must not alias the store's slice.
	c.Messages[0].Text = "tampered"
	again, _ := s.Conversation("alice")
	if again.Messages[0].Text != "in" {
		t.Error("a snapshot shared its message slice with the store")
	}

	s.MarkRead("alice")
	if c2, _ := s.Conversation("alice"); c2.Unread != 0 {
		t.Errorf("unread = %d after MarkRead, want 0", c2.Unread)
	}

	s.CloseConversation("alice")
	if _, ok := s.Conversation("alice"); ok {
		t.Error("closed conversation is still present")
	}
}

// TestRoomParticipantBookkeeping covers join/leave and the "recent room" state.
func TestRoomParticipantBookkeeping(t *testing.T) {
	s := NewStore()
	s.UpsertRoom("4-0-r", "project")
	s.SetRoomJoined("4-0-r", true)
	s.RoomUsersJoined("4-0-r", []string{"alice", "bob"})
	s.RoomUsersJoined("4-0-r", []string{"ALICE"}) // duplicate, differently cased

	r, ok := s.Room("4-0-r")
	if !ok {
		t.Fatal("room missing")
	}
	if len(r.Participants) != 2 {
		t.Fatalf("participants = %v, want 2 (the duplicate should be ignored)", r.Participants)
	}
	if r.Name != "project" || !r.Joined {
		t.Errorf("room = %+v, want named and joined", r)
	}

	s.RoomUsersLeft("4-0-r", []string{"BOB"})
	r, _ = s.Room("4-0-r")
	if len(r.Participants) != 1 || r.Participants[0] != "alice" {
		t.Errorf("participants after leave = %v, want just alice", r.Participants)
	}

	// Leaving keeps the room as a re-joinable "recent", with no stale roster.
	s.SetRoomJoined("4-0-r", false)
	r, _ = s.Room("4-0-r")
	if r.Joined {
		t.Error("room still marked joined")
	}
	if len(r.Participants) != 0 {
		t.Errorf("a room we are not in still lists participants: %v", r.Participants)
	}
}

// TestRestoreRoomsComeBackAsRecent: saved rooms are scrollback, not live
// connections, so they must not claim to be joined.
func TestRestoreRoomsComeBackAsRecent(t *testing.T) {
	s := NewStore()
	s.RestoreRooms([]Room{{
		Cookie: "4-0-r", Name: "project", Joined: true,
		Participants: []string{"stale"},
		Messages:     []Message{{From: "alice", Text: "old", At: time.Now()}},
	}})
	r, ok := s.Room("4-0-r")
	if !ok {
		t.Fatal("restored room missing")
	}
	if r.Joined {
		t.Error("a restored room claims to be joined")
	}
	if len(r.Participants) != 0 {
		t.Errorf("a restored room carries a stale roster: %v", r.Participants)
	}
	if len(r.Messages) != 1 {
		t.Error("restored scrollback was lost")
	}
}

// TestRestoreConversationsStartRead: restored history has already been seen, so
// it must not light up every thread as unread on sign-on.
func TestRestoreConversationsStartRead(t *testing.T) {
	s := NewStore()
	s.RestoreConversations([]Conversation{{
		ScreenName: "Alice", Unread: 7,
		Messages: []Message{{From: "alice", Text: "old", At: time.Now()}},
	}})
	c, ok := s.Conversation("alice")
	if !ok {
		t.Fatal("restored conversation missing (key not derived from the screen name?)")
	}
	if c.Unread != 0 {
		t.Errorf("unread = %d on restore, want 0", c.Unread)
	}
	if len(c.Messages) != 1 {
		t.Error("restored messages lost")
	}
}
