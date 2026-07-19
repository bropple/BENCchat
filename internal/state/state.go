// Package state is BENCchat's protocol-agnostic data model: the buddy list,
// presence, and open conversations.
//
// Nothing here imports the oscar or wire packages. That separation is
// deliberate (CLAUDE.md): the UI binds only to this layer, and a headless
// consumer — R. Triy, a Home Assistant integration — can drive the same model
// without dragging a UI along. The session layer translates SNACs into calls on
// a Store; the Store knows nothing about how it was told.
package state

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Presence is a buddy's availability.
type Presence string

const (
	PresenceOffline Presence = "offline"
	PresenceOnline  Presence = "online"
	PresenceAway    Presence = "away"
	PresenceIdle    Presence = "idle"
)

// NormalizeScreenName produces the canonical key for a screen name.
//
// OSCAR screen names are case- and space-insensitive: "R Triy", "rtriy", and
// "RTriy" are the same account. Every lookup must go through this, or a buddy
// who signs on as "R Triy" will not match the "rtriy" row in the buddy list.
func NormalizeScreenName(sn string) string {
	return strings.ToLower(strings.ReplaceAll(sn, " ", ""))
}

// Buddy is one entry in the buddy list.
type Buddy struct {
	// ScreenName is the display form (the casing the server or list gives us).
	ScreenName string `json:"screenName"`
	// Key is the normalized lookup form. Stable across presence updates.
	Key string `json:"key"`
	// Group is the buddy-list group this buddy belongs to.
	Group string `json:"group"`
	// Alias is a user-assigned local nickname, if any.
	Alias string `json:"alias,omitempty"`

	Presence Presence `json:"presence"`
	// AwayMessage is set when Presence is PresenceAway.
	AwayMessage string `json:"awayMessage,omitempty"`
	// Profile is the buddy's info text, fetched on demand.
	Profile string `json:"profile,omitempty"`
	// Blocked reports whether this buddy is on our deny list.
	Blocked bool `json:"blocked,omitempty"`
	// IconHash is the hex MD5 of the buddy's icon (BART), empty if they have
	// none. The image bytes are fetched separately and cached in the Store; the
	// UI reads them via the app's GetBuddyIcon. The hash changing is the signal
	// that a buddy swapped their icon.
	IconHash string `json:"iconHash,omitempty"`
	// E2EECapable reports whether the buddy's client advertised support for
	// encrypted IM. CapsKnown says whether they advertised any capabilities at
	// all — without it, "not capable" is indistinguishable from "hasn't told
	// us", and the UI must not claim a client can't encrypt on silence alone.
	E2EECapable bool `json:"e2eeCapable,omitempty"`
	CapsKnown   bool `json:"capsKnown,omitempty"`
	// IdleSince is zero unless the buddy is idle.
	IdleSince time.Time `json:"idleSince"`
	// SignedOnAt is when the buddy came online (zero if offline/unknown).
	SignedOnAt time.Time `json:"signedOnAt"`
}

// Display returns the name to show: the alias if the user set one, else the
// screen name.
func (b Buddy) Display() string {
	if b.Alias != "" {
		return b.Alias
	}
	return b.ScreenName
}

// Online reports whether the buddy is reachable in any form.
func (b Buddy) Online() bool { return b.Presence != PresenceOffline }

// Message is a single instant message in a conversation.
type Message struct {
	// From is the sender's screen name; To is the recipient's.
	From string    `json:"from"`
	To   string    `json:"to"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
	// Outgoing marks messages we sent, for UI alignment.
	Outgoing bool `json:"outgoing"`
	// AutoResponse marks an away-message auto-reply rather than a typed message.
	AutoResponse bool `json:"autoResponse,omitempty"`
	// Encrypted marks a message that was sent or received end-to-end encrypted.
	Encrypted bool `json:"encrypted,omitempty"`
	// SenderVerified means a room message carried a signature that checked out
	// against the sender's published keys. Absent on 1:1 messages, which are
	// authenticated by the encryption itself.
	SenderVerified bool `json:"senderVerified,omitempty"`
	// Forged marks a room message whose signature did NOT verify — positive
	// evidence of impersonation, not merely an unknown sender.
	Forged bool `json:"forged,omitempty"`
	// Envelope is the sealed room message exactly as it arrived, kept so it can
	// be forwarded verbatim when serving catch-up. Forwarding the ciphertext
	// rather than the plaintext means a member relaying history cannot alter
	// what anyone said — the recipient verifies the original signature.
	Envelope string `json:"-"`
	// Cipher holds the raw envelope of a message we could not decrypt on
	// arrival — normally because the sender's key hadn't been fetched yet.
	// Keeping it lets us decrypt retroactively once their key lands, instead of
	// stranding the message behind a placeholder forever. Cleared on success.
	Cipher string `json:"-"`
}

// Conversation is a 1:1 message thread, keyed by the normalized screen name of
// the other party.
type Conversation struct {
	Key        string    `json:"key"`
	ScreenName string    `json:"screenName"`
	Messages   []Message `json:"messages"`
	// Unread counts messages received since the UI last marked it read.
	Unread int `json:"unread"`
}

// Room is a joined multi-user chat room. Cookie is the server room identity
// ("{exchange}-{instance}-{name}"); Messages reuse the 1:1 Message shape, where
// From is the sender's screen name and Outgoing marks our own sends.
type Room struct {
	Cookie string `json:"cookie"`
	Name   string `json:"name"`
	// Joined is true while we hold a live Chat connection to the room; false for
	// a "recent" room restored from disk that can be re-joined. Not persisted.
	Joined       bool      `json:"joined"`
	Participants []string  `json:"participants"`
	Messages     []Message `json:"messages"`
}

// Self is the signed-on user's own state.
type Self struct {
	ScreenName  string   `json:"screenName"`
	Presence    Presence `json:"presence"`
	AwayMessage string   `json:"awayMessage,omitempty"`
	// WarningLevel is our warning percentage in tenths of a percent (1000 = 100%).
	WarningLevel uint16 `json:"warningLevel"`
}

// Event is a change notification emitted by a Store.
type Event struct {
	Kind string `json:"kind"`
	// Buddy is set for buddy-related events.
	Buddy *Buddy `json:"buddy,omitempty"`
	// Message is set for Kind == EventMessage.
	Message *Message `json:"message,omitempty"`
	// Conversation is the normalized key the event concerns, if any.
	Conversation string `json:"conversation,omitempty"`
	// Typing is set for Kind == EventTyping.
	Typing bool `json:"typing,omitempty"`
	// ScreenName names the party an event concerns, when no Buddy is attached.
	ScreenName string `json:"screenName,omitempty"`
	// Notice / NoticeLevel are set for Kind == EventNotice.
	Notice      string `json:"notice,omitempty"`
	NoticeLevel string `json:"noticeLevel,omitempty"`
	// SearchQuery / SearchFound are set for Kind == EventSearchResult.
	SearchQuery string `json:"searchQuery,omitempty"`
	SearchFound bool   `json:"searchFound,omitempty"`
	// Directory / DirectoryOK are set for Kind == EventDirectoryResult. A search
	// that ran but matched nobody has DirectoryOK true and an empty Directory;
	// DirectoryOK false means the search itself couldn't run (e.g. name missing).
	Directory   []DirEntry `json:"directory,omitempty"`
	DirectoryOK bool       `json:"directoryOK,omitempty"`
	// Room is set for Kind == EventRoomChanged; RoomKey is the room cookie an
	// EventRoomChanged/EventRoomMessage concerns.
	Room    *Room  `json:"room,omitempty"`
	RoomKey string `json:"roomKey,omitempty"`
}

// DirEntry is one user-directory match surfaced to the UI.
type DirEntry struct {
	ScreenName string `json:"screenName"`
	FirstName  string `json:"firstName,omitempty"`
	LastName   string `json:"lastName,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	Country    string `json:"country,omitempty"`
}

// Event kinds.
const (
	// EventBuddyListChanged means the whole list was replaced (e.g. feedbag load).
	EventBuddyListChanged = "buddyListChanged"
	// EventBuddyChanged means one buddy's presence or details changed.
	EventBuddyChanged = "buddyChanged"
	// EventMessage means a message was added to a conversation.
	EventMessage = "message"
	// EventSelfChanged means our own presence/away state changed.
	EventSelfChanged = "selfChanged"
	// EventTyping means the other party in a conversation started or stopped
	// typing. Typing is transient and intentionally not stored — it is only ever
	// broadcast.
	EventTyping = "typing"
	// EventDisconnected means the session ended. Message carries nothing; the
	// reason travels in ScreenName-free form via the bridge.
	EventDisconnected = "disconnected"
	// EventNotice is a transient message for the user (e.g. a warning result).
	EventNotice = "notice"
	// EventSearchResult delivers a user-search outcome.
	EventSearchResult = "searchResult"
	// EventDirectoryResult delivers a directory (ODir) search's result list.
	EventDirectoryResult = "directoryResult"
	// EventConversationsChanged means the whole conversation set was replaced
	// (local history restored on sign-on, or cleared). The UI re-reads via
	// GetConversations; individual new messages still come as EventMessage.
	EventConversationsChanged = "conversationsChanged"
	// EventRoomChanged means a chat room was joined/left or its roster changed.
	// Room carries the snapshot (nil when the room was left/removed).
	EventRoomChanged = "roomChanged"
	// EventRoomMessage means a message arrived in a chat room (RoomKey).
	EventRoomMessage = "roomMessage"
)

// SearchResult broadcasts the outcome of a user search. Found is false when no
// account matched.
func (s *Store) SearchResult(query, screenName string, found bool) {
	s.emit(Event{
		Kind:        EventSearchResult,
		ScreenName:  screenName,
		SearchQuery: query,
		SearchFound: found,
	})
}

// DirectoryResult broadcasts a directory search's result list. ok is false when
// the search couldn't run (e.g. no name given); an empty list with ok true means
// it ran but matched nobody.
func (s *Store) DirectoryResult(entries []DirEntry, ok bool) {
	s.emit(Event{
		Kind:        EventDirectoryResult,
		Directory:   entries,
		DirectoryOK: ok,
	})
}

// Notice is a level for a transient user notice.
type NoticeLevel string

const (
	NoticeInfo  NoticeLevel = "info"
	NoticeWarn  NoticeLevel = "warn"
	NoticeError NoticeLevel = "error"
)

// Notify broadcasts a transient notice to the UI. Notices are not stored.
func (s *Store) Notify(level NoticeLevel, text string) {
	s.emit(Event{Kind: EventNotice, Notice: text, NoticeLevel: string(level)})
}

// SetSelfWarning records our own warning level and notifies subscribers.
func (s *Store) SetSelfWarning(level uint16) {
	s.mu.Lock()
	s.self.WarningLevel = level
	s.mu.Unlock()
	s.emit(Event{Kind: EventSelfChanged})
}

// NotifyTyping broadcasts a typing notification without storing it.
func (s *Store) NotifyTyping(screenName string, typing bool) {
	s.emit(Event{
		Kind:         EventTyping,
		ScreenName:   screenName,
		Conversation: NormalizeScreenName(screenName),
		Typing:       typing,
	})
}

// maxMessagesPerConversation caps in-memory scrollback per thread. Without a
// bound, a long-lived session grows without limit; persistent history is a
// separate concern from live session state.
const maxMessagesPerConversation = 1000

// Store holds all live client state. It is safe for concurrent use: the OSCAR
// read loop writes to it from its own goroutine while the UI reads.
type Store struct {
	mu sync.RWMutex

	self          Self
	buddies       map[string]*Buddy
	groupOrder    []string
	conversations map[string]*Conversation
	rooms         map[string]*Room // chat rooms by cookie
	// icons caches buddy-icon image bytes by hex MD5. Keyed by hash rather than
	// buddy so several buddies sharing an icon store it once, and a buddy's icon
	// survives presence churn. Small (icons are a few KB) and never persisted.
	icons map[string][]byte

	subscribers map[int]func(Event)
	nextSubID   int
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{
		self:          Self{Presence: PresenceOffline},
		buddies:       make(map[string]*Buddy),
		conversations: make(map[string]*Conversation),
		rooms:         make(map[string]*Room),
		icons:         make(map[string][]byte),
		subscribers:   make(map[int]func(Event)),
	}
}

// Subscribe registers fn to receive every Event. The returned function
// unsubscribes.
//
// fn is called synchronously, without the Store lock held, so a subscriber may
// call back into the Store — but it must not block for long, since it runs on
// the caller's goroutine (usually the protocol read loop).
func (s *Store) Subscribe(fn func(Event)) (unsubscribe func()) {
	s.mu.Lock()
	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = fn
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
	}
}

// emit notifies subscribers. It must be called WITHOUT the lock held, because
// subscribers are allowed to read the Store.
func (s *Store) emit(e Event) {
	s.mu.RLock()
	fns := make([]func(Event), 0, len(s.subscribers))
	for _, fn := range s.subscribers {
		fns = append(fns, fn)
	}
	s.mu.RUnlock()

	for _, fn := range fns {
		fn(e)
	}
}

// SetSelf records the signed-on identity.
func (s *Store) SetSelf(screenName string) {
	s.mu.Lock()
	s.self.ScreenName = screenName
	s.self.Presence = PresenceOnline
	s.mu.Unlock()
	s.emit(Event{Kind: EventSelfChanged})
}

// Self returns our own state.
func (s *Store) Self() Self {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.self
}

// SetAway sets or clears our away message. An empty message means "back".
func (s *Store) SetAway(msg string) {
	s.mu.Lock()
	s.self.AwayMessage = msg
	if msg == "" {
		s.self.Presence = PresenceOnline
	} else {
		s.self.Presence = PresenceAway
	}
	s.mu.Unlock()
	s.emit(Event{Kind: EventSelfChanged})
}

// ReplaceBuddyList swaps in a freshly loaded list, preserving the presence of
// buddies already known.
//
// Presence is preserved deliberately: the feedbag only describes list
// membership, not who is online, so a naive replace would blank out presence
// we already learned from buddy-arrival notifications.
func (s *Store) ReplaceBuddyList(buddies []Buddy, groupOrder []string) {
	s.mu.Lock()
	next := make(map[string]*Buddy, len(buddies))
	for _, b := range buddies {
		b.Key = NormalizeScreenName(b.ScreenName)
		if old, ok := s.buddies[b.Key]; ok {
			b.Presence = old.Presence
			b.AwayMessage = old.AwayMessage
			// Preserve fetched profile across list edits (a reload carries no
			// profile text; re-fetching would be wasteful churn).
			if b.Profile == "" {
				b.Profile = old.Profile
			}
			// A reload carries no icon hash; keep the one we already learned so the
			// cached image isn't dropped and needlessly re-fetched.
			if b.IconHash == "" {
				b.IconHash = old.IconHash
			}
			b.IdleSince = old.IdleSince
			b.SignedOnAt = old.SignedOnAt
		} else if b.Presence == "" {
			b.Presence = PresenceOffline
		}
		next[b.Key] = &b
	}
	s.buddies = next
	s.groupOrder = groupOrder
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyListChanged})
}

// UpdatePresence records a presence change for a buddy.
//
// A buddy not in the list is added rather than dropped: the server can send
// arrivals for accounts we have no feedbag row for, and silently discarding
// them would lose real messages' context.
func (s *Store) UpdatePresence(screenName string, p Presence, awayMsg string, idleSince, signedOnAt time.Time) {
	key := NormalizeScreenName(screenName)

	s.mu.Lock()
	b, ok := s.buddies[key]
	if !ok {
		b = &Buddy{ScreenName: screenName, Key: key}
		s.buddies[key] = b
	}
	b.Presence = p
	b.AwayMessage = awayMsg
	b.IdleSince = idleSince
	b.SignedOnAt = signedOnAt
	snapshot := *b
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyChanged, Buddy: &snapshot})
}

// SetBuddyAwayMessage records a buddy's fetched away text without disturbing
// their presence (the away flag arrives via presence; the text is fetched
// separately). A no-op if the buddy isn't known.
func (s *Store) SetBuddyAwayMessage(screenName, msg string) {
	key := NormalizeScreenName(screenName)

	s.mu.Lock()
	b, ok := s.buddies[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	b.AwayMessage = msg
	snapshot := *b
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyChanged, Buddy: &snapshot})
}

// SetBuddyIcon records a buddy's icon. iconHash is the hex MD5 the buddy
// advertised ("" clears it); data is the image bytes, or nil when only the hash
// is known so far (bytes still downloading). Passing data caches it under
// iconHash for later retrieval. A no-op if the buddy isn't known.
//
// Called twice per icon in the common case: once on arrival with just the hash,
// then again with the bytes once the BART download lands — each emits a change
// so the UI re-reads the icon.
// SetBuddyCapabilities records what a buddy's client advertised it supports.
// capsKnown false means they advertised nothing, which is not the same as
// advertising no encryption support. A no-op if the buddy isn't known; only
// emits when something actually changed, since presence updates repeat these.
func (s *Store) SetBuddyCapabilities(screenName string, e2eeCapable, capsKnown bool) {
	key := NormalizeScreenName(screenName)

	s.mu.Lock()
	b, ok := s.buddies[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	if b.E2EECapable == e2eeCapable && b.CapsKnown == capsKnown {
		s.mu.Unlock()
		return
	}
	b.E2EECapable, b.CapsKnown = e2eeCapable, capsKnown
	snapshot := *b
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyChanged, Buddy: &snapshot})
}

func (s *Store) SetBuddyIcon(screenName, iconHash string, data []byte) {
	key := NormalizeScreenName(screenName)

	s.mu.Lock()
	b, ok := s.buddies[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	if data != nil && iconHash != "" {
		s.icons[iconHash] = data
	}
	b.IconHash = iconHash
	snapshot := *b
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyChanged, Buddy: &snapshot})
}

// HaveIcon reports whether the image bytes for iconHash are already cached, so
// the client can skip a redundant download.
func (s *Store) HaveIcon(iconHash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.icons[iconHash]
	return ok
}

// BuddyIconData returns the cached image bytes for a buddy's current icon, or
// nil if the buddy is unknown, has no icon, or the bytes haven't arrived yet.
func (s *Store) BuddyIconData(screenName string) []byte {
	key := NormalizeScreenName(screenName)
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.buddies[key]
	if !ok || b.IconHash == "" {
		return nil
	}
	return s.icons[b.IconHash]
}

// SetBuddyProfile records a buddy's fetched profile text. A no-op if the buddy
// isn't known.
func (s *Store) SetBuddyProfile(screenName, profile string) {
	key := NormalizeScreenName(screenName)

	s.mu.Lock()
	b, ok := s.buddies[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	b.Profile = profile
	snapshot := *b
	s.mu.Unlock()

	s.emit(Event{Kind: EventBuddyChanged, Buddy: &snapshot})
}

// Buddies returns a snapshot of the buddy list, sorted for display: online
// buddies first, then alphabetically within each group.
func (s *Store) Buddies() []Buddy {
	s.mu.RLock()
	out := make([]Buddy, 0, len(s.buddies))
	for _, b := range s.buddies {
		out = append(out, *b)
	}
	order := make(map[string]int, len(s.groupOrder))
	for i, g := range s.groupOrder {
		order[g] = i
	}
	s.mu.RUnlock()

	sort.SliceStable(out, func(i, j int) bool {
		gi, iOK := order[out[i].Group]
		gj, jOK := order[out[j].Group]
		switch {
		case iOK && jOK && gi != gj:
			return gi < gj
		case iOK != jOK:
			return iOK // known groups sort before unknown ones
		case out[i].Group != out[j].Group:
			return out[i].Group < out[j].Group
		case out[i].Online() != out[j].Online():
			return out[i].Online()
		default:
			return strings.ToLower(out[i].Display()) < strings.ToLower(out[j].Display())
		}
	})
	return out
}

// Buddy looks up a single buddy by screen name.
func (s *Store) Buddy(screenName string) (Buddy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.buddies[NormalizeScreenName(screenName)]
	if !ok {
		return Buddy{}, false
	}
	return *b, true
}

// Groups returns the group names in list order.
func (s *Store) Groups() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.groupOrder...)
}

// DecryptPending re-runs decryption over a conversation's undecrypted messages,
// which is how a message that arrived before we knew the sender's key gets
// recovered once it lands. open returns the plaintext and true on success;
// messages it can't open keep their ciphertext for a later attempt. Reports
// whether anything changed, emitting a conversation refresh if so.
func (s *Store) DecryptPending(screenName string, open func(cipher string) (string, bool)) bool {
	key := NormalizeScreenName(screenName)

	// Snapshot the ciphertexts, then decrypt with the lock RELEASED.
	//
	// The callback belongs to the client layer and may do arbitrary work —
	// recovering a room invitation, for one, which reads this same store. Running
	// it under the write lock deadlocked the whole application: RWMutex is not
	// reentrant, so the read that followed could never be granted, and every
	// later store access piled up behind it including the one that runs at
	// shutdown.
	s.mu.Lock()
	c, ok := s.conversations[key]
	if !ok {
		s.mu.Unlock()
		return false
	}
	type pending struct {
		idx    int
		cipher string
	}
	var todo []pending
	for i := range c.Messages {
		if c.Messages[i].Cipher != "" {
			todo = append(todo, pending{idx: i, cipher: c.Messages[i].Cipher})
		}
	}
	s.mu.Unlock()

	if len(todo) == 0 {
		return false
	}
	opened := make(map[string]string, len(todo))
	for _, p := range todo {
		if plain, got := open(p.cipher); got {
			opened[p.cipher] = plain
		}
	}
	if len(opened) == 0 {
		return false
	}

	// Re-acquire and apply. Messages are matched by ciphertext rather than by
	// index, since the slice may have grown or been trimmed meanwhile.
	s.mu.Lock()
	c, ok = s.conversations[key]
	if !ok {
		s.mu.Unlock()
		return false
	}
	changed := false
	kept := c.Messages[:0]
	for i := range c.Messages {
		m := c.Messages[i]
		plain, got := "", false
		if m.Cipher != "" {
			plain, got = opened[m.Cipher]
		}
		switch {
		case !got:
			kept = append(kept, m)
		case plain == "":
			// Recovered as protocol traffic rather than something a person
			// said — drop it instead of showing a placeholder.
			changed = true
		default:
			m.Text, m.Encrypted, m.Cipher = plain, true, ""
			kept = append(kept, m)
			changed = true
		}
	}
	c.Messages = kept
	s.mu.Unlock()

	if changed {
		s.emit(Event{Kind: EventConversationsChanged})
	}
	return changed
}

// --- Conversations ---------------------------------------------------------

// AddMessage appends a message to the conversation with the other party and
// returns the updated conversation key.
func (s *Store) AddMessage(m Message) string {
	other := m.From
	if m.Outgoing {
		other = m.To
	}
	key := NormalizeScreenName(other)

	s.mu.Lock()
	c, ok := s.conversations[key]
	if !ok {
		c = &Conversation{Key: key, ScreenName: other}
		s.conversations[key] = c
	}
	c.Messages = append(c.Messages, m)
	if len(c.Messages) > maxMessagesPerConversation {
		c.Messages = c.Messages[len(c.Messages)-maxMessagesPerConversation:]
	}
	if !m.Outgoing {
		c.Unread++
	}
	s.mu.Unlock()

	s.emit(Event{Kind: EventMessage, Message: &m, Conversation: key})
	return key
}

// Conversation returns a snapshot of one thread.
func (s *Store) Conversation(screenName string) (Conversation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.conversations[NormalizeScreenName(screenName)]
	if !ok {
		return Conversation{}, false
	}
	return conversationSnapshot(c), true
}

// Conversations returns snapshots of every thread, newest activity first.
func (s *Store) Conversations() []Conversation {
	s.mu.RLock()
	out := make([]Conversation, 0, len(s.conversations))
	for _, c := range s.conversations {
		out = append(out, conversationSnapshot(c))
	}
	s.mu.RUnlock()

	sort.SliceStable(out, func(i, j int) bool {
		return lastMessageAt(out[i]).After(lastMessageAt(out[j]))
	})
	return out
}

// conversationSnapshot copies a thread for handing outside the lock; the
// message slice is copied too, so a caller can never read it while the store
// mutates it.
func conversationSnapshot(c *Conversation) Conversation {
	out := *c
	out.Messages = append([]Message(nil), c.Messages...)
	return out
}

func lastMessageAt(c Conversation) time.Time {
	if len(c.Messages) == 0 {
		return time.Time{}
	}
	return c.Messages[len(c.Messages)-1].At
}

// MarkRead clears a thread's unread count.
func (s *Store) MarkRead(screenName string) {
	key := NormalizeScreenName(screenName)
	s.mu.Lock()
	c, ok := s.conversations[key]
	if !ok || c.Unread == 0 {
		s.mu.Unlock()
		return
	}
	c.Unread = 0
	s.mu.Unlock()
	s.emit(Event{Kind: EventConversationsChanged})
}

// CloseConversation drops a thread entirely (the user closed the window).
func (s *Store) CloseConversation(screenName string) {
	key := NormalizeScreenName(screenName)
	s.mu.Lock()
	delete(s.conversations, key)
	s.mu.Unlock()
	s.emit(Event{Kind: EventConversationsChanged})
}

// RestoreConversations loads saved threads at sign-on, replacing whatever is
// held. Restored history is already-read, so unread counts start at zero.
func (s *Store) RestoreConversations(cs []Conversation) {
	s.mu.Lock()
	s.conversations = make(map[string]*Conversation, len(cs))
	for i := range cs {
		c := cs[i]
		if c.Key == "" {
			c.Key = NormalizeScreenName(c.ScreenName)
		}
		if c.Key == "" {
			continue
		}
		c.Unread = 0
		s.conversations[c.Key] = &c
	}
	s.mu.Unlock()
	s.emit(Event{Kind: EventConversationsChanged})
}

// ClearConversations wipes all scrollback — both threads and room history —
// for the "clear history" action.
func (s *Store) ClearConversations() {
	s.mu.Lock()
	s.conversations = make(map[string]*Conversation)
	for _, r := range s.rooms {
		r.Messages = nil
	}
	s.mu.Unlock()
	s.emit(Event{Kind: EventConversationsChanged})
}

// --- Rooms -----------------------------------------------------------------

// UpsertRoom records a room and its display name, creating it if new.
func (s *Store) UpsertRoom(cookie, name string) {
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		r = &Room{Cookie: cookie}
		s.rooms[cookie] = r
	}
	if name != "" {
		r.Name = name
	}
	snapshot := roomSnapshot(r)
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie, Room: &snapshot})
}

// SetRoomJoined marks whether we hold a live connection to a room. A room we
// have left stays in the list as a "recent" one that can be re-joined.
func (s *Store) SetRoomJoined(cookie string, joined bool) {
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		r = &Room{Cookie: cookie}
		s.rooms[cookie] = r
	}
	r.Joined = joined
	if !joined {
		// Nobody is "in" a room we are not connected to; keeping the old roster
		// would show a participant list that is no longer true.
		r.Participants = nil
	}
	snapshot := roomSnapshot(r)
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie, Room: &snapshot})
}

// RoomUsersJoined adds participants, ignoring ones already listed.
func (s *Store) RoomUsersJoined(cookie string, names []string) {
	if len(names) == 0 {
		return
	}
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		r = &Room{Cookie: cookie}
		s.rooms[cookie] = r
	}
	have := make(map[string]bool, len(r.Participants))
	for _, p := range r.Participants {
		have[NormalizeScreenName(p)] = true
	}
	for _, n := range names {
		if n == "" || have[NormalizeScreenName(n)] {
			continue
		}
		have[NormalizeScreenName(n)] = true
		r.Participants = append(r.Participants, n)
	}
	snapshot := roomSnapshot(r)
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie, Room: &snapshot})
}

// RoomUsersLeft removes participants.
func (s *Store) RoomUsersLeft(cookie string, names []string) {
	if len(names) == 0 {
		return
	}
	gone := make(map[string]bool, len(names))
	for _, n := range names {
		gone[NormalizeScreenName(n)] = true
	}
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		s.mu.Unlock()
		return
	}
	kept := r.Participants[:0]
	for _, p := range r.Participants {
		if !gone[NormalizeScreenName(p)] {
			kept = append(kept, p)
		}
	}
	r.Participants = kept
	snapshot := roomSnapshot(r)
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie, Room: &snapshot})
}

// RestoreRooms loads saved rooms at sign-on. They come back as "recent" rooms —
// not joined — because a saved room is scrollback, not a live connection.
func (s *Store) RestoreRooms(rs []Room) {
	s.mu.Lock()
	s.rooms = make(map[string]*Room, len(rs))
	for i := range rs {
		r := rs[i]
		if r.Cookie == "" {
			continue
		}
		r.Joined = false
		r.Participants = nil
		s.rooms[r.Cookie] = &r
	}
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged})
}

// MergeRoomMessages folds recovered history into a room in timestamp order,
// skipping anything already present.
//
// Catch-up can overlap with what we already have — two members may serve
// overlapping ranges, or we may have been present for part of it — so the merge
// has to be idempotent rather than appending blindly. Reports how many were new.
func (s *Store) MergeRoomMessages(cookie string, msgs []Message) int {
	if len(msgs) == 0 {
		return 0
	}
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		s.mu.Unlock()
		return 0
	}
	have := make(map[string]bool, len(r.Messages))
	for _, m := range r.Messages {
		have[roomMsgKey(m)] = true
	}
	added := 0
	for _, m := range msgs {
		if have[roomMsgKey(m)] {
			continue
		}
		have[roomMsgKey(m)] = true
		r.Messages = append(r.Messages, m)
		added++
	}
	if added > 0 {
		sort.SliceStable(r.Messages, func(i, j int) bool {
			return r.Messages[i].At.Before(r.Messages[j].At)
		})
		if len(r.Messages) > maxMessagesPerConversation {
			r.Messages = r.Messages[len(r.Messages)-maxMessagesPerConversation:]
		}
	}
	snapshot := roomSnapshot(r)
	s.mu.Unlock()

	if added > 0 {
		s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie, Room: &snapshot})
	}
	return added
}

// roomMsgKey identifies a room message for de-duplication. Sender, second-level
// timestamp and text together are enough: a genuine duplicate of all three is
// indistinguishable from the same message arriving twice.
func roomMsgKey(m Message) string {
	return m.From + "\x00" + m.At.UTC().Format(time.RFC3339) + "\x00" + m.Text
}

// AddRoomMessage appends a message to a room and emits EventRoomMessage.
func (s *Store) AddRoomMessage(cookie string, m Message) {
	s.mu.Lock()
	r, ok := s.rooms[cookie]
	if !ok {
		r = &Room{Cookie: cookie}
		s.rooms[cookie] = r
	}
	r.Messages = append(r.Messages, m)
	if len(r.Messages) > maxMessagesPerConversation {
		r.Messages = r.Messages[len(r.Messages)-maxMessagesPerConversation:]
	}
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomMessage, Message: &m, RoomKey: cookie})
}

// roomSnapshot copies a room for handing outside the lock. The slices are
// copied too: returning the live ones would let a caller read them while the
// store mutates them.
func roomSnapshot(r *Room) Room {
	out := *r
	out.Participants = append([]string(nil), r.Participants...)
	out.Messages = append([]Message(nil), r.Messages...)
	return out
}

// Room returns a snapshot of one room.
func (s *Store) Room(cookie string) (Room, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rooms[cookie]
	if !ok {
		return Room{}, false
	}
	return roomSnapshot(r), true
}

// Rooms returns snapshots of all joined rooms.
func (s *Store) Rooms() []Room {
	s.mu.RLock()
	out := make([]Room, 0, len(s.rooms))
	for _, r := range s.rooms {
		out = append(out, roomSnapshot(r))
	}
	s.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RemoveRoom drops a room (we left it or its connection died). The event carries
// a nil Room to signal removal.
func (s *Store) RemoveRoom(cookie string) {
	s.mu.Lock()
	delete(s.rooms, cookie)
	s.mu.Unlock()
	s.emit(Event{Kind: EventRoomChanged, RoomKey: cookie})
}

func containsFold(list []string, s string) bool {
	n := NormalizeScreenName(s)
	for _, x := range list {
		if NormalizeScreenName(x) == n {
			return true
		}
	}
	return false
}

// Reset clears all state on sign-off.
func (s *Store) Reset() {
	s.mu.Lock()
	s.self = Self{Presence: PresenceOffline}
	s.buddies = make(map[string]*Buddy)
	s.groupOrder = nil
	s.conversations = make(map[string]*Conversation)
	s.rooms = make(map[string]*Room)
	s.mu.Unlock()
	s.emit(Event{Kind: EventBuddyListChanged})
}
