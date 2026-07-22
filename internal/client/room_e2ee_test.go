package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
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
	// No 1:1 key for this peer, so no encrypted channel exists.
	if err := c.InviteToRoom("stranger", "room", nil, ""); err == nil {
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

	chain, _ := e2ee.NewChain()
	c.handleRoomInvite("bob", e2ee.EncodeRoomInvite(e2ee.RoomInvite{
		Room: "secret-room", Chains: []e2ee.ChainView{chain.View()},
	}))

	if from != "bob" || got.Room != "secret-room" ||
		len(got.Chains) != 1 || got.Chains[0].ID != chain.ID {
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
	chain, _ := e2ee.NewChain()
	body := e2ee.EncodeRoomInvite(e2ee.RoomInvite{
		Room: "secret-room", Chains: []e2ee.ChainView{chain.View()},
	})
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

	if got.Room != "secret-room" || len(got.Chains) != 1 || got.Chains[0].ID != chain.ID {
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
	_ = c.InviteToRoom("bob", "secret-room", nil, "")
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

// TestDuplicateRoomMessageIsDropped: the same signed room message arriving twice
// is the server handing us a copy it kept, not somebody saying it again.
func TestDuplicateRoomMessageIsDropped(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, _ := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	recipient.store.UpsertRoom("4-0-r", "project")
	sender.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)
	recipient.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	env, encrypted, err := sender.sealRoomMessage("4-0-r", "ship it")
	if err != nil || !encrypted {
		t.Fatalf("seal failed: %v", err)
	}

	first := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if first.Duplicate || first.Text != "ship it" || !first.Verified {
		t.Fatalf("first delivery was not accepted: %+v", first)
	}
	if first.SentAt.IsZero() {
		t.Error("no send time, so a replay would render as something said just now")
	}

	if again := recipient.decodeRoomMessageFrom("4-0-r", "alice", env); !again.Duplicate {
		t.Errorf("a replayed room message was accepted a second time: %+v", again)
	}

	// The same words sent again are a new message, not a replay — the check is
	// on identity, not on content.
	env2, _, _ := sender.sealRoomMessage("4-0-r", "ship it")
	if d := recipient.decodeRoomMessageFrom("4-0-r", "alice", env2); d.Duplicate {
		t.Error("an identical-text message was mistaken for a replay")
	}
}

// TestUnknownSignerResolvesWhenKeysArrive is R7.
//
// A signature we cannot check because the sender's keys have not arrived is a
// TIMING GAP, not a verdict — but the badge went up on arrival and stayed for
// the life of the session even after the keys landed. That made a server
// withholding keys indistinguishable from an ordinary delay.
func TestUnknownSignerResolvesWhenKeysArrive(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, rstore := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	rstore.UpsertRoom("4-0-r", "project")
	sender.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)
	// Deliberately NOT learning alice's signing keys yet.

	env, encrypted, err := sender.sealRoomMessage("4-0-r", "ship it")
	if err != nil || !encrypted {
		t.Fatalf("seal failed: %v", err)
	}

	d := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if d.Forged {
		t.Fatal("an uncheckable signature was reported as forged")
	}
	if d.Verified {
		t.Fatal("a signature verified against keys we do not hold")
	}
	if !d.Signed {
		t.Error("a signature was present but not reported as such — this is what made " +
			"a withheld key look like an unsigned message from an old client")
	}

	rstore.AddRoomMessage("4-0-r", state.Message{
		From: "alice", Text: d.Text, Encrypted: true,
		SenderVerified: d.Verified, Signed: d.Signed, Envelope: env,
	})

	// The keys arrive. Everything already shown must be re-checked in place.
	recipient.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	room, ok := rstore.Room("4-0-r")
	if !ok || len(room.Messages) != 1 {
		t.Fatalf("room state lost: ok=%v", ok)
	}
	if !room.Messages[0].SenderVerified {
		t.Error("a message stayed unverified after its sender's keys arrived")
	}
	if room.Messages[0].Forged {
		t.Error("re-verification flagged a genuine message as forged")
	}
}

// TestReverifyLeavesAForgeryFlagged: re-checking must not launder a forgery into
// a verified message just because keys turned up.
func TestReverifyLeavesAForgeryFlagged(t *testing.T) {
	mallory, _ := newTestClient(t)
	recipient, rstore := newTestClient(t)

	key, _ := e2ee.GenerateRoomKey()
	malloryKey, _ := e2ee.GenerateSigningKey()
	aliceKey, _ := e2ee.GenerateSigningKey()
	mallory.SetSigningKey(malloryKey, true)
	mallory.store.UpsertRoom("4-0-r", "project")
	rstore.UpsertRoom("4-0-r", "project")
	mallory.SetRoomKey("4-0-r", key)
	recipient.SetRoomKey("4-0-r", key)

	// Mallory holds the group key and signs as herself, but claims to be alice.
	env, _, err := mallory.sealRoomMessage("4-0-r", "pay mallory 1000")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	rstore.AddRoomMessage("4-0-r", state.Message{
		From: "alice", Text: "pay mallory 1000", Encrypted: true, Signed: true, Envelope: env,
	})

	recipient.learnPeerSigningKeys("alice", []ed25519.PublicKey{aliceKey.Public})

	room, _ := rstore.Room("4-0-r")
	if len(room.Messages) != 1 {
		t.Fatalf("room state lost")
	}
	if room.Messages[0].SenderVerified {
		t.Error("a forgery was marked verified once the real sender's keys arrived")
	}
	if !room.Messages[0].Forged {
		t.Error("a message signed by somebody else was not flagged on re-verification")
	}
}

// TestChainSendAndReceive: the client-level path, chain minted, distributed,
// and read by somebody holding the view.
func TestChainSendAndReceive(t *testing.T) {
	sender, _ := newTestClient(t)
	recipient, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	recipient.store.UpsertRoom("4-0-r", "project")
	recipient.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	view, fresh, err := sender.EnsureOutboundChain("4-0-r")
	if err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}
	if !fresh {
		t.Fatal("the first chain for a room should be reported as fresh")
	}
	recipient.LearnChainView("4-0-r", view)
	sender.MarkChainShared("4-0-r") // stands in for the in-room broadcast

	env, encrypted, err := sender.sealRoomMessage("4-0-r", "ship it")
	if err != nil || !encrypted {
		t.Fatalf("seal: encrypted=%v err=%v", encrypted, err)
	}
	if !e2ee.IsRoomChainEnvelope(env) {
		t.Fatal("a client with a chain still sealed under the shared-key path")
	}
	d := recipient.decodeRoomMessageFrom("4-0-r", "alice", env)
	if d.Text != "ship it" || !d.Verified || !d.Encrypted {
		t.Fatalf("decode = %+v", d)
	}
}

// TestChainHidesPreJoinHistoryAtClientLevel is R5 through the client.
func TestChainHidesPreJoinHistoryAtClientLevel(t *testing.T) {
	sender, _ := newTestClient(t)
	joiner, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	sender.SetSigningKey(signer, true)
	sender.store.UpsertRoom("4-0-r", "project")
	joiner.store.UpsertRoom("4-0-r", "project")
	joiner.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	sender.EnsureOutboundChain("4-0-r")
	sender.MarkChainShared("4-0-r")
	before, _, _ := sender.sealRoomMessage("4-0-r", "said before they joined")

	// They join here and are handed the chain where it currently stands.
	view, _, _ := sender.EnsureOutboundChain("4-0-r")
	joiner.LearnChainView("4-0-r", view)

	if d := joiner.decodeRoomMessageFrom("4-0-r", "alice", before); d.Encrypted {
		t.Errorf("a joiner read a message sent before they arrived: %+v", d)
	} else if !strings.Contains(d.Text, "before you joined") {
		t.Errorf("unhelpful wording for pre-join history: %q", d.Text)
	}

	after, _, _ := sender.sealRoomMessage("4-0-r", "said after they joined")
	if d := joiner.decodeRoomMessageFrom("4-0-r", "alice", after); d.Text != "said after they joined" {
		t.Errorf("a joiner could not read a post-join message: %+v", d)
	}
}

// TestStaleChainIsReplacedBeforeTheNextSend: lazy rotation. A removal marks the
// chain stale rather than re-keying immediately, and the replacement happens at
// the next send — the earliest point at which it matters.
func TestStaleChainIsReplacedBeforeTheNextSend(t *testing.T) {
	c, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	c.SetSigningKey(signer, true)
	c.store.UpsertRoom("4-0-r", "project")

	first, fresh, _ := c.EnsureOutboundChain("4-0-r")
	if !fresh {
		t.Fatal("first chain not reported fresh")
	}
	if again, fresh, _ := c.EnsureOutboundChain("4-0-r"); fresh || again.ID != first.ID {
		t.Error("an unchanged chain was replaced or reported fresh")
	}

	c.MarkChainStale("4-0-r")

	second, fresh, _ := c.EnsureOutboundChain("4-0-r")
	if !fresh {
		t.Error("a stale chain was not reported as needing distribution")
	}
	if second.ID == first.ID {
		t.Error("a stale chain was reused, so a removed member could still read")
	}
	if second.Index != 0 {
		t.Errorf("a fresh chain started at index %d, want 0", second.Index)
	}
}

// TestLearnChainViewKeepsTheFurthestBack: chains only move forward, so a view at
// a LOWER index grants strictly more. Taking the higher one would silently
// discard history we were entitled to.
func TestLearnChainViewKeepsTheFurthestBack(t *testing.T) {
	c, _ := newTestClient(t)
	chain, _ := e2ee.NewChain()

	early := chain.View() // index 0
	for i := 0; i < 5; i++ {
		chain.Next()
	}
	late := chain.View() // index 5

	c.LearnChainView("4-0-r", late)
	c.LearnChainView("4-0-r", early)
	if got := c.ChainViews("4-0-r")[chain.ID]; got.Index != 0 {
		t.Errorf("kept index %d after learning an earlier view, want 0", got.Index)
	}

	c.LearnChainView("4-0-r", late)
	if got := c.ChainViews("4-0-r")[chain.ID]; got.Index != 0 {
		t.Errorf("a later view overwrote an earlier one, losing history (index %d)", got.Index)
	}
}

// TestSealRefusesUntilTheChainIsShared is the ordering guarantee, enforced here
// rather than left to the send path to remember.
//
// A message sealed under a chain nobody has been given is unreadable to the
// entire room, and it looks exactly like success from the sender's side. Making
// the seal refuse means the mistake cannot survive somebody reordering two lines
// on the send path — which is precisely how it was nearly shipped.
func TestSealRefusesUntilTheChainIsShared(t *testing.T) {
	c, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	c.SetSigningKey(signer, true)
	c.store.UpsertRoom("4-0-r", "project")
	// Explicit now: minting a chain no longer makes a room encrypted, so an
	// ordinary room cannot become one just by being sent to.
	c.MarkRoomEncrypted("4-0-r")

	if _, _, err := c.EnsureOutboundChain("4-0-r"); err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}
	if _, _, err := c.sealRoomMessage("4-0-r", "too soon"); err == nil {
		t.Error("sealed under a chain the room has never been given")
	}

	c.MarkChainShared("4-0-r")
	env, encrypted, err := c.sealRoomMessage("4-0-r", "now it is fine")
	if err != nil || !encrypted {
		t.Fatalf("seal after sharing: encrypted=%v err=%v", encrypted, err)
	}
	if !e2ee.IsRoomChainEnvelope(env) {
		t.Error("did not seal under the chain")
	}

	// A replacement is undistributed again, so sealing must refuse until it too
	// has gone out — otherwise a removal silently produces unreadable messages.
	c.MarkChainStale("4-0-r")
	c.EnsureOutboundChain("4-0-r")
	if _, _, err := c.sealRoomMessage("4-0-r", "after a removal"); err == nil {
		t.Error("sealed under a replacement chain nobody has been given")
	}
}

// TestPruneChainViewsBoundsWhatAStolenFileOpens is R8's remaining half, and the
// room half of forward secrecy.
//
// A view kept at the position it was first handed opens the room's entire life.
// Winding it forward is irreversible by construction — the step is a one-way
// hash — so a stolen room file after this opens only the recent past.
func TestPruneChainViewsBoundsWhatAStolenFileOpens(t *testing.T) {
	c, _ := newTestClient(t)
	chain, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	// Handed the chain at the very beginning, then the room runs on well past
	// the retention window.
	c.LearnChainView("4-0-r", chain.View())
	var keys [][32]byte
	for i := 0; i < chainRetention+500; i++ {
		k, _ := chain.Next()
		keys = append(keys, k)
	}
	c.noteChainPosition("4-0-r", chain.ID, uint32(len(keys)-1))

	// Before pruning the earliest message still opens.
	if got, err := c.ChainViews("4-0-r")[chain.ID].MessageKey(0); err != nil || got != keys[0] {
		t.Fatalf("setup: position 0 should be readable (err=%v)", err)
	}

	if moved := c.PruneChainViews("4-0-r"); moved != 1 {
		t.Fatalf("pruned %d chains, want 1", moved)
	}

	view := c.ChainViews("4-0-r")[chain.ID]
	if _, err := view.MessageKey(0); !errors.Is(err, e2ee.ErrChainRewind) {
		t.Error("the oldest message is still readable after pruning")
	}
	// The recent past must survive, or catch-up breaks.
	recent := uint32(len(keys) - 1)
	if got, err := view.MessageKey(recent); err != nil || got != keys[recent] {
		t.Errorf("pruning cost us a recent position (err=%v)", err)
	}
}

// TestPruneChainViewsLeavesShortChainsAlone: a room that has not run past the
// window loses nothing, and a chain we have never seen a position for is not
// wound forward on a guess.
func TestPruneChainViewsLeavesShortChainsAlone(t *testing.T) {
	c, _ := newTestClient(t)

	young, _ := e2ee.NewChain()
	c.LearnChainView("4-0-r", young.View())
	for i := 0; i < 50; i++ {
		young.Next()
	}
	c.noteChainPosition("4-0-r", young.ID, 49)

	unknown, _ := e2ee.NewChain()
	c.LearnChainView("4-0-r", unknown.View()) // no position ever noted

	if moved := c.PruneChainViews("4-0-r"); moved != 0 {
		t.Errorf("pruned %d chains, want none", moved)
	}
	if got := c.ChainViews("4-0-r")[young.ID]; got.Index != 0 {
		t.Errorf("a short chain was wound to %d", got.Index)
	}
	if got := c.ChainViews("4-0-r")[unknown.ID]; got.Index != 0 {
		t.Errorf("a chain with no known position was wound forward on a guess to %d", got.Index)
	}
}

// TestPruneChainViewsSparesOurOwnChain: our own view is regenerated from the
// outbound chain at its current position, so pruning it is pointless — and
// counting it would make the result misleading.
func TestPruneChainViewsSparesOurOwnChain(t *testing.T) {
	c, _ := newTestClient(t)
	c.store.UpsertRoom("4-0-r", "project")

	view, _, err := c.EnsureOutboundChain("4-0-r")
	if err != nil {
		t.Fatalf("EnsureOutboundChain: %v", err)
	}
	c.noteChainPosition("4-0-r", view.ID, chainRetention+100)

	if moved := c.PruneChainViews("4-0-r"); moved != 0 {
		t.Errorf("pruned our own chain (%d moved)", moved)
	}
}

// TestARosterMustBeSignedByWhoeverSentIt.
//
// Room authority turns on WHO signed a roster — only the owner may remove — so
// the binding between the author named inside and the person the message
// actually came from has to hold. Without it a server could take the owner's
// genuine roster from one room and relay it as though somebody else had sent it,
// or replay it into a context where a different author changes the outcome.
func TestARosterMustBeSignedByWhoeverSentIt(t *testing.T) {
	alice, _ := newTestClient(t)
	kp, err := e2ee.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	alice.SetSigningKey(kp, true)

	body, err := alice.SignRosterBody(e2ee.Roster{
		Room: "project", Epoch: 1, Members: []string{"alice", "bob"},
		Owner: "alice", Author: "alice",
	})
	if err != nil {
		t.Fatalf("SignRosterBody: %v", err)
	}

	bob, _ := newTestClient(t)
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{kp.Public})

	if _, ok := bob.VerifiedRoster("alice", body); !ok {
		t.Fatal("a roster signed by its author did not verify")
	}
	// The same bytes, relayed as though Mallory had sent them.
	if r, ok := bob.VerifiedRoster("mallory", body); ok {
		t.Errorf("a relayed roster verified as the relayer's: %+v", r)
	}
	// And an author we hold no keys for is "cannot check", which must not be
	// mistaken for "checked out".
	if _, ok := bob.VerifiedRoster("carol", body); ok {
		t.Error("a roster from someone whose keys we don't have was accepted")
	}
	// A screen name is a display form; the binding must survive its normalized
	// spelling, or every capitalized account would silently fail this check.
	if _, ok := bob.VerifiedRoster("A L I C E", body); !ok {
		t.Error("the sender/author check does not normalize screen names")
	}
}
