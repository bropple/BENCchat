package client

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// TestRoomSealAndOpen: a member holding the key sends and reads.
func TestRoomSealAndOpen(t *testing.T) {
	c, _ := newTestClient(t)
	key, _ := e2ee.GenerateRoomKey()
	c.SetRoomKey("room-1", key)

	if !c.RoomEncrypted("room-1") {
		t.Fatal("room not reported encrypted after a key was installed")
	}
	wire, encrypted, err := c.sealRoomMessage("room-1", "hello room")
	if err != nil || !encrypted {
		t.Fatalf("sealRoomMessage: encrypted=%v err=%v", encrypted, err)
	}
	if strings.Contains(wire, "hello room") {
		t.Fatal("plaintext went onto the wire")
	}
	got, wasEnc := c.decodeRoomMessage("room-1", wire)
	if !wasEnc || got != "hello room" {
		t.Fatalf("decodeRoomMessage = %q (encrypted=%v)", got, wasEnc)
	}
}

// TestRoomWithoutKeySendsPlaintext: an ordinary unencrypted room is unaffected.
func TestRoomWithoutKeySendsPlaintext(t *testing.T) {
	c, _ := newTestClient(t)
	wire, encrypted, err := c.sealRoomMessage("plain-room", "hi all")
	if err != nil {
		t.Fatal(err)
	}
	if encrypted || wire != "hi all" {
		t.Fatalf("a keyless room encrypted anyway: %q (encrypted=%v)", wire, encrypted)
	}
	got, wasEnc := c.decodeRoomMessage("plain-room", "hi all")
	if wasEnc || got != "hi all" {
		t.Fatalf("plaintext room message mangled: %q", got)
	}
}

// TestRoomMessageWithoutKeyIsExplained: sitting in an encrypted room without
// the key must say so, not show ciphertext or a decrypt error.
func TestRoomMessageWithoutKeyIsExplained(t *testing.T) {
	sender, _ := newTestClient(t)
	key, _ := e2ee.GenerateRoomKey()
	sender.SetRoomKey("room-1", key)
	env, _, _ := sender.sealRoomMessage("room-1", "you can't read this")

	// A client with no key at all for the room.
	outsider, _ := newTestClient(t)
	got, encrypted := outsider.decodeRoomMessage("room-1", env)
	if encrypted {
		t.Error("a message we can't decrypt was flagged as encrypted (i.e. readable)")
	}
	if strings.Contains(got, "you can't read this") {
		t.Fatal("plaintext leaked to someone without the key")
	}
	if !strings.Contains(got, "key") {
		t.Errorf("placeholder %q should explain that a key is missing", got)
	}

	// And a client holding a DIFFERENT key — e.g. invited after a rotation.
	late, _ := newTestClient(t)
	other, _ := e2ee.GenerateRoomKey()
	late.SetRoomKey("room-1", other)
	got, encrypted = late.decodeRoomMessage("room-1", env)
	if encrypted || strings.Contains(got, "you can't read this") {
		t.Fatal("a member with the wrong key read the message")
	}
}

// TestRoomRotationKeepsOldMessagesReadable: rotating for a departing member
// must not blind everyone else to the scrollback.
func TestRoomRotationKeepsOldMessagesReadable(t *testing.T) {
	c, _ := newTestClient(t)
	oldKey, _ := e2ee.GenerateRoomKey()
	c.SetRoomKey("room-1", oldKey)
	before, _, _ := c.sealRoomMessage("room-1", "before rotation")

	newKey, _ := e2ee.GenerateRoomKey()
	c.SetRoomKey("room-1", newKey) // rotate

	if got, _ := c.decodeRoomMessage("room-1", before); got != "before rotation" {
		t.Errorf("after rotating, the earlier message reads %q", got)
	}
	after, encrypted, _ := c.sealRoomMessage("room-1", "after rotation")
	if !encrypted {
		t.Fatal("post-rotation send was not encrypted")
	}
	if id, _ := e2ee.RoomEnvelopeKeyID(after); id != newKey.ID() {
		t.Error("new messages are not using the new key")
	}
}

// TestRoomNonReadersDetected drives the participant split the UI shows.
//
// Capabilities come from the BOS connection (buddy arrivals, locate replies) —
// NOT from the chat roster, which was verified live to carry none. Only a
// client we have actually heard from, advertising capabilities that don't
// include encryption, counts as a non-reader.
func TestRoomNonReadersDetected(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	key, _ := e2ee.GenerateRoomKey()
	store.UpsertRoom("4-0-room", "bencchat-test")
	c.SetRoomKey("4-0-room", key)
	store.RoomUsersJoined("4-0-room", []string{"alice", "bob", "oldaimuser", "mystery"})

	// What the BOS connection told us about each client.
	c.notePeerCapability("bob", true)         // advertises BENCchat
	c.notePeerCapability("oldaimuser", false) // advertises caps, but not ours
	// "mystery" we have heard nothing about.

	got := c.RoomNonReaders("4-0-room")
	if len(got) != 1 || got[0] != "oldaimuser" {
		t.Fatalf("non-readers = %v, want just oldaimuser", got)
	}
}

// TestUnknownParticipantIsNotAccused: someone we know nothing about must not be
// reported as unable to read.
//
// A wrong accusation tells the user their private room is leaking when it
// isn't — worse than a warning that arrives a second late once their info
// comes back.
func TestUnknownParticipantIsNotAccused(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	key, _ := e2ee.GenerateRoomKey()
	store.UpsertRoom("4-0-room", "bencchat-test")
	c.SetRoomKey("4-0-room", key)
	store.RoomUsersJoined("4-0-room", []string{"alice", "stranger"})

	if got := c.RoomNonReaders("4-0-room"); len(got) != 0 {
		t.Errorf("an unknown participant was accused of being unable to read: %v", got)
	}
}

// TestChatRosterDoesNotProveIncapability is the regression guard on the bug
// that made a fully-encrypted room claim a member couldn't read it.
//
// A chat roster arrives with NO capabilities for anyone (verified live against
// open-oscar-server). Concluding "no capabilities means no support" from that
// marks every participant as a non-reader — including people who are perfectly
// able to read, producing a UI that listed the same person as both able and
// unable.
func TestChatRosterDoesNotProveIncapability(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	key, _ := e2ee.GenerateRoomKey()
	store.UpsertRoom("4-0-room", "bencchat-test")
	c.SetRoomKey("4-0-room", key)
	store.RoomUsersJoined("4-0-room", []string{"alice", "bob"})

	// The roster as the server actually sends it: no capabilities at all.
	c.noteRoomCapabilities("4-0-room", []oscar.ChatUser{
		{ScreenName: "bob"},
	})

	if got := c.RoomNonReaders("4-0-room"); len(got) != 0 {
		t.Fatalf("an empty chat roster was treated as proof of incapability: %v", got)
	}

	// A roster that DOES carry capabilities is still a usable positive signal.
	c.noteRoomCapabilities("4-0-room", []oscar.ChatUser{
		{ScreenName: "bob", Capabilities: []oscar.Capability{oscar.CapBENCchat}},
	})
	if capable, known := c.peerCapability("bob"); !known || !capable {
		t.Error("a roster carrying capabilities should still be believed")
	}
}

// TestRoomInviteNeedsAnEncryptedChannel: a group key must never be handed over
// in the clear, or the room is published to anyone watching.
func TestRoomInviteNeedsAnEncryptedChannel(t *testing.T) {
	c, _ := newTestClient(t)
	key, _ := e2ee.GenerateRoomKey()

	// No 1:1 key for this peer, so no encrypted channel exists.
	if err := c.InviteToRoom("stranger", "room", key); err == nil {
		t.Fatal("a room key was sent over an unencrypted channel")
	}
}

// TestRoomInviteIsInterceptedNotDisplayed: an invite is protocol traffic and
// must not appear as a message in the conversation.
func TestRoomInviteIsInterceptedNotDisplayed(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")

	var got e2ee.RoomInvite
	var from string
	c.SetRoomInviteHandler(func(f string, inv e2ee.RoomInvite) { from, got = f, inv })

	key, _ := e2ee.GenerateRoomKey()
	c.handleRoomInvite("bob", e2ee.EncodeRoomInvite(e2ee.RoomInvite{Room: "secret-room", Key: key}))

	if from != "bob" || got.Room != "secret-room" || got.Key != key {
		t.Fatalf("invite not delivered to the handler: from=%q inv=%+v", from, got)
	}
	if convo, ok := store.Conversation("bob"); ok && len(convo.Messages) > 0 {
		t.Error("the invite was stored as a chat message")
	}
}

var _ = state.Message{}

// TestLateRoomInviteIsStillHonored: an invitation that lands before we hold the
// sender's key must be acted on when it's finally decrypted, not dumped into
// the conversation as text. Getting this wrong loses the invitation silently
// and shows the user a wall of base64.
func TestLateRoomInviteIsStillHonored(t *testing.T) {
	alice, alicePub := newE2EEClient(t)
	bob, bobPub := newE2EEClient(t)
	alice.learnPeerKeys("bob", [][32]byte{bobPub})

	var got e2ee.RoomInvite
	bob.SetRoomInviteHandler(func(_ string, inv e2ee.RoomInvite) { got = inv })

	// Alice invites Bob to a room, but Bob doesn't know Alice's key yet.
	roomKey, _ := e2ee.GenerateRoomKey()
	body := e2ee.EncodeRoomInvite(e2ee.RoomInvite{Room: "secret-room", Key: roomKey})
	peerKeys, ourPriv, _ := alice.sealFor("bob")
	env, err := e2ee.SealFor(body, peerKeys, ourPriv)
	if err != nil {
		t.Fatal(err)
	}

	text, encrypted, cipher := bob.decodeIncoming("alice", env)
	if encrypted || cipher == "" {
		t.Fatal("expected the invite to be held as undecryptable ciphertext")
	}
	bob.store.AddMessage(state.Message{From: "alice", To: "bob", Text: text, Cipher: cipher})

	// Alice's key arrives — the invite must now be honored.
	bob.learnPeerKeys("alice", [][32]byte{alicePub})

	if got.Room != "secret-room" || got.Key != roomKey {
		t.Fatalf("late invite was not acted on: %+v", got)
	}
	// The invitation is protocol traffic, not something a person said, so once
	// it has been acted on the message must be GONE — not left as a placeholder
	// sitting in the conversation.
	convo, _ := bob.store.Conversation("alice")
	for _, m := range convo.Messages {
		if strings.Contains(m.Text, "BENCO-ROOMINV") {
			t.Error("raw invite protocol text was shown to the user")
		}
		if strings.Contains(m.Text, "room invitation") {
			t.Error("a placeholder was left in the conversation for a recovered invitation")
		}
	}
	if len(convo.Messages) != 0 {
		t.Errorf("expected the invitation to be removed, %d message(s) remain", len(convo.Messages))
	}
}

// TestJoinRoomIsIdempotent: a rotation delivers a fresh key for a room you are
// already sitting in. Re-running the join dance would open a second chat
// connection and orphan the first, so joining a room you're in must be a no-op.
func TestJoinRoomIsIdempotent(t *testing.T) {
	c, _ := newTestClient(t)
	// Stand in for an established room connection.
	c.chatMu.Lock()
	c.rooms["4-0-secret-room"] = &roomConn{}
	c.chatMu.Unlock()

	if err := c.JoinRoom("secret-room"); err != nil {
		t.Errorf("re-joining a room we're already in should be a no-op, got: %v", err)
	}
	if err := c.JoinRoom("SECRET-ROOM"); err != nil {
		t.Errorf("room names are case-insensitive; got: %v", err)
	}
	c.chatMu.Lock()
	n := len(c.rooms)
	c.chatMu.Unlock()
	if n != 1 {
		t.Errorf("re-joining created %d room connections, want 1", n)
	}

	// A room we are NOT in must still attempt a real join (and fail here, since
	// this client has no session).
	if err := c.JoinRoom("some-other-room"); err == nil {
		t.Error("joining an unjoined room should have attempted a real join")
	}
}

// TestRoomNameFromCookie covers the "{exchange}-{instance}-{name}" parsing,
// including names that themselves contain dashes.
func TestRoomNameFromCookie(t *testing.T) {
	for cookie, want := range map[string]string{
		"4-0-secret":            "secret",
		"4-0-my-room-with-dash": "my-room-with-dash",
		"5-0-BENCcrypted Chat":  "BENCcrypted Chat",
		"malformed":             "malformed",
	} {
		if got := roomNameFromCookie(cookie); got != want {
			t.Errorf("roomNameFromCookie(%q) = %q, want %q", cookie, got, want)
		}
	}
}

// TestRoomCapabilitiesRecordedBeforeArrivalEvent pins the ordering that decides
// whether a new participant is reported as able to read.
//
// The arrival event drives the UI to ask "who can read this room?". If
// capabilities are recorded after it, that question is answered from an empty
// map and every arrival looks like a non-reader — and nothing re-renders later
// to fix it.
func TestRoomCapabilitiesRecordedBeforeArrivalEvent(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	key, _ := e2ee.GenerateRoomKey()
	store.UpsertRoom("4-0-room", "room")
	c.SetRoomKey("4-0-room", key)

	// When the arrival event fires, ask the same question the UI asks.
	var nonReadersAtEventTime []string
	store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventRoomChanged && e.RoomKey == "4-0-room" {
			nonReadersAtEventTime = c.RoomNonReaders("4-0-room")
		}
	})

	body := chatUsersJoinedBody(t, "bob", true)
	c.handleChatSNAC("4-0-room", wire.SNACFrame{FoodGroup: wire.Chat, SubGroup: wire.ChatUsersJoined}, body)

	if len(nonReadersAtEventTime) != 0 {
		t.Errorf("a capable participant was reported unable to read at arrival: %v", nonReadersAtEventTime)
	}
	if got := c.RoomNonReaders("4-0-room"); len(got) != 0 {
		t.Errorf("after arrival, non-readers = %v, want none", got)
	}
}

// chatUsersJoinedBody builds a ChatUsersJoined SNAC for one participant,
// optionally advertising BENCchat's capability.
func chatUsersJoinedBody(t *testing.T, screenName string, capable bool) []byte {
	t.Helper()
	u := wire.TLVUserInfo{ScreenName: screenName}
	if capable {
		blob := append([]byte{}, oscar.CapBENCchat[:]...)
		u.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, blob))
	}
	var buf bytes.Buffer
	if err := wire.MarshalBE(wire.SNAC_0x0E_0x03_ChatUsersJoined{Users: []wire.TLVUserInfo{u}}, &buf); err != nil {
		t.Fatalf("marshal chat users: %v", err)
	}
	return buf.Bytes()
}

// TestEncryptedRoomWithoutKeyRefusesToSend is the guard on the worst failure
// this feature can have.
//
// After a restart (or before an invitation is accepted) a client can be in an
// encrypted room holding no key. Falling back to plaintext there broadcasts
// into a room the user believes is private — and looks exactly like success.
func TestEncryptedRoomWithoutKeyRefusesToSend(t *testing.T) {
	c, _ := newTestClient(t)
	c.MarkRoomEncrypted("4-0-secret")

	if !c.RoomEncrypted("4-0-secret") {
		t.Fatal("room should still be known as encrypted without a key")
	}
	if c.RoomReadable("4-0-secret") {
		t.Fatal("room should not be readable without a key")
	}

	_, encrypted, err := c.sealRoomMessage("4-0-secret", "secret plan")
	if err == nil {
		t.Fatal("an encrypted room with no key sent anyway — plaintext would have gone out")
	}
	if encrypted {
		t.Error("reported success while failing")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error %q should explain the missing key", err)
	}

	// A genuinely unencrypted room is unaffected.
	if _, enc, err := c.sealRoomMessage("4-0-plain", "hello"); err != nil || enc {
		t.Errorf("a normal room was blocked: enc=%v err=%v", enc, err)
	}
}

// TestRestoreRoomKeysRecoversScrollback: retired keys come back too, so
// messages from before a rotation still open after a restart.
func TestRestoreRoomKeysRecoversScrollback(t *testing.T) {
	sender, _ := newTestClient(t)
	oldKey, _ := e2ee.GenerateRoomKey()
	newKey, _ := e2ee.GenerateRoomKey()
	sender.SetRoomKey("4-0-r", oldKey)
	before, _, _ := sender.sealRoomMessage("4-0-r", "old news")
	sender.SetRoomKey("4-0-r", newKey)
	after, _, _ := sender.sealRoomMessage("4-0-r", "new news")

	// Simulate a restart: a fresh client restoring the persisted set.
	restored, _ := newTestClient(t)
	keys, currentID := sender.RoomKeySet("4-0-r")
	if len(keys) != 2 {
		t.Fatalf("expected both keys to be exported, got %d", len(keys))
	}
	restored.RestoreRoomKeys("4-0-r", keys, currentID)

	if got, ok := restored.decodeRoomMessage("4-0-r", before); !ok || got != "old news" {
		t.Errorf("pre-rotation message did not survive the restart: %q", got)
	}
	if got, ok := restored.decodeRoomMessage("4-0-r", after); !ok || got != "new news" {
		t.Errorf("post-rotation message did not survive the restart: %q", got)
	}
	if !restored.RoomReadable("4-0-r") {
		t.Error("restored room is not writable")
	}
}

// TestCatchupMergeIsIdempotent: two members may serve overlapping ranges, and
// we may already hold part of what arrives, so merging must never duplicate.
func TestCatchupMergeIsIdempotent(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.UpsertRoom("4-0-r", "room")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	store.AddRoomMessage("4-0-r", state.Message{From: "bob", Text: "already have", At: base})

	res := e2ee.CatchupResponse{Room: "room", Messages: []e2ee.CatchupMessage{
		{From: "bob", At: base.Unix(), Text: "already have"}, // duplicate
		{From: "bob", At: base.Add(time.Minute).Unix(), Text: "missed this"},
	}}

	if n := c.MergeCatchup("4-0-r", res); n != 1 {
		t.Fatalf("merged %d messages, want 1 (the duplicate should be skipped)", n)
	}
	if n := c.MergeCatchup("4-0-r", res); n != 0 {
		t.Errorf("re-merging the same batch added %d messages, want 0", n)
	}

	room, _ := store.Room("4-0-r")
	if len(room.Messages) != 2 {
		t.Fatalf("room has %d messages, want 2", len(room.Messages))
	}
	// And they must be in time order, not append order.
	if room.Messages[0].Text != "already have" || room.Messages[1].Text != "missed this" {
		t.Errorf("recovered history is out of order: %q then %q",
			room.Messages[0].Text, room.Messages[1].Text)
	}
}

// TestCatchupMarksOwnMessagesOutgoing: history we sent ourselves should render
// as ours, not as though someone else said it.
func TestCatchupMarksOwnMessagesOutgoing(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.UpsertRoom("4-0-r", "room")

	c.MergeCatchup("4-0-r", e2ee.CatchupResponse{Room: "room", Messages: []e2ee.CatchupMessage{
		{From: "ALICE", At: time.Now().Unix(), Text: "mine"},
		{From: "bob", At: time.Now().Add(time.Second).Unix(), Text: "theirs"},
	}})

	room, _ := store.Room("4-0-r")
	if len(room.Messages) != 2 {
		t.Fatalf("want 2 messages, got %d", len(room.Messages))
	}
	if !room.Messages[0].Outgoing {
		t.Error("our own recovered message was not marked outgoing (casing not normalized?)")
	}
	if room.Messages[1].Outgoing {
		t.Error("someone else's message was marked as ours")
	}
}

// TestCatchupNeedsAnEncryptedChannel: room history must not cross the wire in
// the clear — that would leak more than the room already does.
func TestCatchupNeedsAnEncryptedChannel(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.RequestCatchup("stranger", "room", time.Now()); err == nil {
		t.Error("a catch-up request went out over an unencrypted channel")
	}
	if err := c.SendCatchup("stranger", e2ee.CatchupResponse{Room: "room"}); err == nil {
		t.Error("room history was served over an unencrypted channel")
	}
}

// TestRoomHistorySinceWindow: only messages after the requested point are
// served, so a returning member gets what they missed rather than everything.
func TestRoomHistorySinceWindow(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("alice")
	store.UpsertRoom("4-0-r", "room")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	store.AddRoomMessage("4-0-r", state.Message{From: "a", Text: "old", At: t0})
	store.AddRoomMessage("4-0-r", state.Message{From: "a", Text: "new", At: t0.Add(10 * time.Minute)})

	got := c.RoomHistorySince("4-0-r", t0.Add(5*time.Minute))
	if len(got) != 1 || got[0].Text != "new" {
		t.Fatalf("history window = %+v, want just the newer message", got)
	}
	if all := c.RoomHistorySince("4-0-r", t0.Add(-time.Minute)); len(all) != 2 {
		t.Errorf("a wider window returned %d messages, want 2", len(all))
	}
}

// TestRoomMessageIsSignedAndVerified: the normal path — a member's message
// verifies as theirs.
func TestRoomMessageIsSignedAndVerified(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, sstore := newTestClient(t)
	_ = sstore

	key, _ := e2ee.GenerateRoomKey()
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	recipient.store.UpsertRoom("4-0-r", "project")
	sender.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)
	recipient.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	env, encrypted, err := sender.sealRoomMessage("4-0-r", "the real message")
	if err != nil || !encrypted {
		t.Fatalf("seal failed: %v", err)
	}
	got := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if got.Text != "the real message" || !got.Encrypted {
		t.Fatalf("decode = %+v", got)
	}
	if !got.Verified {
		t.Error("a genuinely signed message was not verified")
	}
	if got.Forged {
		t.Error("a genuine message was flagged forged")
	}
}

// TestForgedRoomMessageIsFlagged is the attack this feature exists to stop: a
// member of the room, who therefore holds the group key, publishes a message
// attributed to someone else.
func TestForgedRoomMessageIsFlagged(t *testing.T) {
	mallory, _ := newTestClient(t)
	victimReader, _ := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	malloryKey, _ := e2ee.GenerateSigningKey()
	aliceKey, _ := e2ee.GenerateSigningKey()

	mallory.SetSigningKey(malloryKey, true)
	mallory.store.UpsertRoom("4-0-r", "project")
	victimReader.store.UpsertRoom("4-0-r", "project")
	mallory.SetRoomKey("4-0-r", key)
	victimReader.SetRoomKey("4-0-r", key)
	// The reader knows Alice's real signing key.
	victimReader.learnPeerSigningKeys("alice", []ed25519.PublicKey{aliceKey.Public})

	// Mallory seals a message with the shared group key, signing as herself,
	// and the chat SNAC will claim it came from Alice.
	env, _, err := mallory.sealRoomMessage("4-0-r", "alice says: send money")
	if err != nil {
		t.Fatal(err)
	}

	got := victimReader.decodeRoomMessageFrom("4-0-r", "alice", env)
	if !got.Forged {
		t.Fatal("a forged message was accepted as genuine — attribution is worthless")
	}
	if !strings.Contains(got.Text, "UNVERIFIED") {
		t.Errorf("forged message text %q should be clearly marked", got.Text)
	}
}

// TestUnknownSenderKeysAreNotForgery: before we've fetched someone's profile
// their messages are unverified, but must not be branded impersonation.
func TestUnknownSenderKeysAreNotForgery(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, _ := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	recipient.store.UpsertRoom("4-0-r", "project")
	sender.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)
	// recipient has NOT learned the sender's signing keys.

	env, _, _ := sender.sealRoomMessage("4-0-r", "hello")
	got := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if got.Forged {
		t.Error("an unknown signer was reported as a forgery")
	}
	if got.Verified {
		t.Error("a message from an unknown signer must not be reported verified")
	}
	if got.Text != "hello" {
		t.Errorf("text = %q, want it readable", got.Text)
	}
}

// TestUnsignedSenderStillReadable: a peer on an older BENCchat sends unsigned
// messages, which stay readable but unverified.
func TestUnsignedSenderStillReadable(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, _ := newTestClient(t)
	key, _ := e2ee.GenerateRoomKey()
	sender.store.UpsertRoom("4-0-r", "project")
	recipient.store.UpsertRoom("4-0-r", "project")
	sender.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)
	// sender has NO signing key, as an older client would not.

	env, encrypted, _ := sender.sealRoomMessage("4-0-r", "from an old client")
	if !encrypted {
		t.Fatal("message was not encrypted")
	}
	got := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if got.Forged {
		t.Error("an unsigned message was reported as a forgery")
	}
	if got.Text != "from an old client" {
		t.Errorf("text = %q", got.Text)
	}
}

// TestCatchupForwardsVerifiableEnvelopes: recovered history must arrive
// verifiable, so a member relaying it cannot alter what anyone said.
func TestCatchupForwardsVerifiableEnvelopes(t *testing.T) {
	// Alice says something in the room; Bob was present and archives it.
	alice, _ := newTestClient(t)
	bob, _ := newTestClient(t)
	returning, _ := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	aliceSign, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(aliceSign, true)

	for _, c := range []*Client{alice, bob, returning} {
		c.store.UpsertRoom("4-0-r", "project")
		c.SetRoomKey("4-0-r", key)
	}
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{aliceSign.Public})
	returning.learnPeerSigningKeys("alice", []ed25519.PublicKey{aliceSign.Public})

	env, _, err := alice.sealRoomMessage("4-0-r", "the original words")
	if err != nil {
		t.Fatal(err)
	}
	d := bob.decodeRoomMessageFrom("4-0-r", "alice", env)
	bob.store.AddRoomMessage("4-0-r", state.Message{
		From: "alice", Text: d.Text, At: time.Now(), Encrypted: d.Encrypted,
		SenderVerified: d.Verified, Envelope: env,
	})

	// Bob serves history to the returning member.
	history := bob.RoomHistorySince("4-0-r", time.Now().Add(-time.Hour))
	if len(history) != 1 {
		t.Fatalf("served %d messages, want 1", len(history))
	}
	if history[0].Env == "" {
		t.Fatal("history was served as plaintext — the recipient could not verify it")
	}
	if history[0].Text != "" {
		t.Error("plaintext was included alongside the envelope, which invites trusting it")
	}

	n := returning.MergeCatchup("4-0-r", e2ee.CatchupResponse{Room: "project", Messages: history})
	if n != 1 {
		t.Fatalf("merged %d messages, want 1", n)
	}
	room, _ := returning.store.Room("4-0-r")
	got := room.Messages[0]
	if got.Text != "the original words" {
		t.Errorf("recovered text = %q", got.Text)
	}
	if !got.SenderVerified {
		t.Error("recovered history was not verified as Alice's — the point of forwarding envelopes")
	}
}

// TestCatchupRejectsForgedHistory: a malicious member serving invented history
// must not be believed. The forgery is signed by them, not by the person it
// claims to be from, so it fails verification and is dropped.
func TestCatchupRejectsForgedHistory(t *testing.T) {
	mallory, _ := newTestClient(t)
	returning, _ := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	mallorySign, _ := e2ee.GenerateSigningKey()
	aliceSign, _ := e2ee.GenerateSigningKey()
	mallory.SetSigningKey(mallorySign, true)

	for _, c := range []*Client{mallory, returning} {
		c.store.UpsertRoom("4-0-r", "project")
		c.SetRoomKey("4-0-r", key)
	}
	returning.learnPeerSigningKeys("alice", []ed25519.PublicKey{aliceSign.Public})

	// Mallory fabricates a message and attributes it to Alice.
	forged, _, err := mallory.sealRoomMessage("4-0-r", "alice said: wire the money")
	if err != nil {
		t.Fatal(err)
	}
	n := returning.MergeCatchup("4-0-r", e2ee.CatchupResponse{
		Room: "project",
		Messages: []e2ee.CatchupMessage{
			{From: "alice", At: time.Now().Unix(), Env: forged},
		},
	})
	if n != 0 {
		t.Fatalf("merged %d forged messages, want 0 — invented history was accepted", n)
	}
	room, _ := returning.store.Room("4-0-r")
	for _, m := range room.Messages {
		if strings.Contains(m.Text, "wire the money") {
			t.Fatal("fabricated history made it into the room")
		}
	}
}

// TestCatchupDoesNotRelayForgeries: a member who RECEIVED a forgery must not
// pass it on — relaying would launder it, making it appear to come from a
// member the recipient trusts.
func TestCatchupDoesNotRelayForgeries(t *testing.T) {
	bob, _ := newTestClient(t)
	bob.store.UpsertRoom("4-0-r", "project")
	key, _ := e2ee.GenerateRoomKey()
	bob.SetRoomKey("4-0-r", key)

	bob.store.AddRoomMessage("4-0-r", state.Message{
		From: "alice", Text: "[UNVERIFIED] fake", At: time.Now(),
		Encrypted: true, Forged: true, Envelope: "someenvelope",
	})
	bob.store.AddRoomMessage("4-0-r", state.Message{
		From: "alice", Text: "genuine", At: time.Now(), Encrypted: true,
		SenderVerified: true, Envelope: "genuineenvelope",
	})

	history := bob.RoomHistorySince("4-0-r", time.Now().Add(-time.Hour))
	if len(history) != 1 {
		t.Fatalf("served %d messages, want only the genuine one", len(history))
	}
	if history[0].Env != "genuineenvelope" {
		t.Error("the forged message was relayed onward")
	}
}

// TestProtocolTrafficIsNotStoredAsAMessage: invitations, group keys and
// catch-up frames ride the same channel as chat, but they are not something a
// person said. Storing them puts base64 protocol frames in the chat window —
// which is exactly what happened in testing.
func TestProtocolTrafficIsNotStoredAsAMessage(t *testing.T) {
	c, _ := newE2EEClient(t)
	store := c.store
	store.SetSelf("alice")
	_, bobPub := newE2EEClient(t)
	c.learnPeerKeys("bob", [][32]byte{bobPub})

	// No session, so the send fails at the wire — but the point is that nothing
	// is recorded in the conversation either way.
	key, _ := e2ee.GenerateRoomKey()
	_ = c.InviteToRoom("bob", "secret-room", key)
	_ = c.RequestCatchup("bob", "secret-room", time.Now())
	_ = c.SendCatchup("bob", e2ee.CatchupResponse{Room: "secret-room"})

	if convo, ok := store.Conversation("bob"); ok && len(convo.Messages) > 0 {
		t.Fatalf("protocol traffic was stored as %d chat message(s): %q",
			len(convo.Messages), convo.Messages[0].Text)
	}

	// An ordinary message still is stored, so the guard isn't over-broad.
	store.AddMessage(state.Message{From: "alice", To: "bob", Text: "hello", Outgoing: true, At: time.Now()})
	if convo, _ := store.Conversation("bob"); len(convo.Messages) != 1 {
		t.Error("an ordinary message was not stored")
	}
}

// TestPlaintextInEncryptedRoomIsMarked: a member's BENCchat either seals or
// refuses, so plaintext arriving in an encrypted room was injected downstream.
// The server picks the sender name attached to every chat message and already
// rewrites chat traffic to implement //roll, so this is a live capability, not a
// hypothetical one. Rendering it as an ordinary message would put words in a
// named member's mouth with no marker but an ABSENT lock.
func TestPlaintextInEncryptedRoomIsMarked(t *testing.T) {
	c, _ := newTestClient(t)
	key, _ := e2ee.GenerateRoomKey()
	c.SetRoomKey("room-1", key)

	d := c.decodeRoomMessageFrom("room-1", "alice", "wire the money to this account")
	if !d.Forged {
		t.Error("plaintext injected into an encrypted room was not flagged")
	}
	if d.Encrypted {
		t.Error("injected plaintext was reported as encrypted")
	}
	if !strings.Contains(d.Text, "wire the money to this account") {
		t.Errorf("injected text must still be shown so the user can see what was said: %q", d.Text)
	}
	if !strings.Contains(d.Text, "UNENCRYPTED") {
		t.Errorf("no marker on injected plaintext: %q", d.Text)
	}
}

// TestPlaintextInKeylessEncryptedRoomIsMarked: losing the key must not reopen
// the hole. MarkRoomEncrypted exists precisely so a room stays known-encrypted
// when its key is missing.
func TestPlaintextInKeylessEncryptedRoomIsMarked(t *testing.T) {
	c, _ := newTestClient(t)
	c.MarkRoomEncrypted("room-1")

	if d := c.decodeRoomMessageFrom("room-1", "alice", "hello"); !d.Forged {
		t.Errorf("plaintext in a known-encrypted room with no key went unflagged: %+v", d)
	}
}

// TestPlaintextRoomIsUnaffected: an ordinary unencrypted room must not sprout
// warnings on every message.
func TestPlaintextRoomIsUnaffected(t *testing.T) {
	c, _ := newTestClient(t)
	d := c.decodeRoomMessageFrom("room-plain", "alice", "hello")
	if d.Forged || d.Encrypted || d.Text != "hello" {
		t.Fatalf("ordinary room message was altered: %+v", d)
	}
}
