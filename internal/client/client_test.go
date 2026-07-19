package client

import (
	"bytes"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// newTestClient builds a Client with no session. handleSNAC only needs the
// store, so inbound dispatch can be exercised without a server.
func newTestClient(t *testing.T) (*Client, *state.Store) {
	t.Helper()
	store := state.NewStore()
	return New(store, slog.New(slog.NewTextHandler(io.Discard, nil))), store
}

// marshal encodes a SNAC body to bytes the way the server would send it.
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(v, buf); err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return buf.Bytes()
}

func arrivalBody(t *testing.T, screenName string, flags uint16, idleMins uint16) []byte {
	t.Helper()
	u := wire.TLVUserInfo{ScreenName: screenName}
	u.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(time.Now().Unix())))
	u.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, flags))
	if idleMins > 0 {
		u.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, idleMins))
	}
	return marshal(t, wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: u})
}

func TestBuddyArrivedSetsOnline(t *testing.T) {
	c, store := newTestClient(t)

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
		arrivalBody(t, "R Triy", wire.OServiceUserFlagOSCARFree, 0),
	)

	b, ok := store.Buddy("rtriy")
	if !ok {
		t.Fatal("buddy not added on arrival")
	}
	if b.Presence != state.PresenceOnline {
		t.Errorf("Presence = %q, want online", b.Presence)
	}
	if b.SignedOnAt.IsZero() {
		t.Error("SignedOnAt should be populated from the signon-time TLV")
	}
}

func TestBuddyArrivedAwayBeatsIdle(t *testing.T) {
	c, store := newTestClient(t)

	// A buddy can be away AND idle at once. Away is the deliberate signal, so it
	// must win the single presence slot.
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
		arrivalBody(t, "rtriy", wire.OServiceUserFlagOSCARFree|wire.OServiceUserFlagUnavailable, 20),
	)

	b, _ := store.Buddy("rtriy")
	if b.Presence != state.PresenceAway {
		t.Fatalf("Presence = %q, want away (away must take precedence over idle)", b.Presence)
	}
	if b.IdleSince.IsZero() {
		t.Error("IdleSince should still be recorded for an away+idle buddy")
	}
}

func TestBuddyArrivedIdle(t *testing.T) {
	c, store := newTestClient(t)

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
		arrivalBody(t, "rtriy", wire.OServiceUserFlagOSCARFree, 15),
	)

	b, _ := store.Buddy("rtriy")
	if b.Presence != state.PresenceIdle {
		t.Fatalf("Presence = %q, want idle", b.Presence)
	}
	// 15 minutes idle → IdleSince roughly 15 minutes ago.
	if d := time.Since(b.IdleSince); d < 14*time.Minute || d > 16*time.Minute {
		t.Errorf("IdleSince implies %v of idleness, want ~15m", d)
	}
}

// TestBuddyDepartedWithEmptyTLVBlock covers the server's real departure body,
// which carries zero TLVs rather than full user info.
func TestBuddyDepartedWithEmptyTLVBlock(t *testing.T) {
	c, store := newTestClient(t)
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
		arrivalBody(t, "rtriy", wire.OServiceUserFlagOSCARFree, 0),
	)

	departed := marshal(t, wire.SNAC_0x03_0x0C_BuddyDeparted{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "rtriy"},
	})
	c.handleSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted}, departed)

	b, _ := store.Buddy("rtriy")
	if b.Presence != state.PresenceOffline {
		t.Fatalf("Presence = %q, want offline", b.Presence)
	}
}

func TestIncomingMessageLandsInStore(t *testing.T) {
	c, store := newTestClient(t)
	store.SetSelf("me")

	text, err := wire.MarshalICBMMessageText("hello there")
	if err != nil {
		t.Fatalf("build message: %v", err)
	}
	msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		Cookie:      1,
		ChannelID:   wire.ICBMChannelIM,
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "R Triy"},
	}
	msg.TLVRestBlock.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, text))

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient},
		marshal(t, msg),
	)

	convo, ok := store.Conversation("rtriy")
	if !ok {
		t.Fatal("no conversation created for inbound message")
	}
	if len(convo.Messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(convo.Messages))
	}
	got := convo.Messages[0]
	if got.Text != "hello there" {
		t.Errorf("Text = %q", got.Text)
	}
	if got.From != "R Triy" {
		t.Errorf("From = %q, want the server's canonical casing", got.From)
	}
	if got.Outgoing {
		t.Error("inbound message must not be marked outgoing")
	}
	if convo.Unread != 1 {
		t.Errorf("Unread = %d, want 1", convo.Unread)
	}
}

func TestIncomingAutoResponseFlagged(t *testing.T) {
	c, store := newTestClient(t)

	text, _ := wire.MarshalICBMMessageText("I am away")
	msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		ChannelID:   wire.ICBMChannelIM,
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "rtriy"},
	}
	msg.TLVRestBlock.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, text))
	msg.TLVRestBlock.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient},
		marshal(t, msg),
	)

	convo, _ := store.Conversation("rtriy")
	if len(convo.Messages) != 1 || !convo.Messages[0].AutoResponse {
		t.Fatal("auto-response TLV should mark the message as an auto-reply")
	}
}

// TestNonIMChannelIgnored ensures a rendezvous (file transfer) request doesn't
// appear as an empty chat message.
func TestNonIMChannelIgnored(t *testing.T) {
	c, store := newTestClient(t)

	msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		ChannelID:   wire.ICBMChannelRendezvous,
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "rtriy"},
	}
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient},
		marshal(t, msg),
	)

	if len(store.Conversations()) != 0 {
		t.Fatal("a non-IM channel message must not create a conversation")
	}
}

func TestTypingEventBroadcast(t *testing.T) {
	c, store := newTestClient(t)

	var got []state.Event
	store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventTyping {
			got = append(got, e)
		}
	})

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent},
		marshal(t, wire.SNAC_0x04_0x14_ICBMClientEvent{
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "R Triy",
			Event:      wire.ICBMEventTyping,
		}),
	)
	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent},
		marshal(t, wire.SNAC_0x04_0x14_ICBMClientEvent{
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "R Triy",
			Event:      wire.ICBMEventTyped,
		}),
	)

	if len(got) != 2 {
		t.Fatalf("typing events = %d, want 2", len(got))
	}
	if !got[0].Typing {
		t.Error("ICBMEventTyping should report typing=true")
	}
	if got[1].Typing {
		t.Error("ICBMEventTyped should report typing=false")
	}
	// The conversation key must be normalized so the UI can match it.
	if got[0].Conversation != "rtriy" {
		t.Errorf("Conversation = %q, want normalized %q", got[0].Conversation, "rtriy")
	}
}

// TestMalformedSNACDoesNotPanic: inbound bytes are attacker-influenced, and the
// read loop must survive garbage rather than take the session down.
func TestMalformedSNACDoesNotPanic(t *testing.T) {
	c, _ := newTestClient(t)

	for _, sub := range []uint16{wire.BuddyArrived, wire.BuddyDeparted} {
		c.handleSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: sub}, []byte{0xFF, 0x01})
	}
	for _, sub := range []uint16{wire.ICBMChannelMsgToClient, wire.ICBMClientEvent} {
		c.handleSNAC(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: sub}, []byte{0xFF, 0x01})
	}
	// An unknown foodgroup is normal traffic, not an error.
	c.handleSNAC(wire.SNACFrame{FoodGroup: 0x9999, SubGroup: 0x0001}, nil)
}

func TestPublishBuddyList(t *testing.T) {
	c, store := newTestClient(t)

	c.publishBuddyList(oscar.BuddyList{
		Buddies: []oscar.BuddyEntry{
			{ScreenName: "rtriy", Group: "BENCO", Alias: "R. Triy"},
			{ScreenName: "someone", Group: "BENCO"},
		},
		Groups: []string{"BENCO"},
	})

	if n := len(store.Buddies()); n != 2 {
		t.Fatalf("buddy count = %d, want 2", n)
	}
	b, _ := store.Buddy("rtriy")
	if b.Alias != "R. Triy" {
		t.Errorf("Alias = %q", b.Alias)
	}
	if b.Presence != state.PresenceOffline {
		t.Errorf("Presence = %q, want offline before any arrival", b.Presence)
	}
	if groups := store.Groups(); len(groups) != 1 || groups[0] != "BENCO" {
		t.Errorf("Groups = %v", groups)
	}
}

func TestSendMessageRequiresSession(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.SendMessage("rtriy", "hi"); err == nil {
		t.Fatal("expected an error when not signed on")
	}
}

func TestSignOffWhenNotSignedOnIsSafe(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.SignOff(); err != nil {
		t.Fatalf("SignOff when signed off should be a no-op, got %v", err)
	}
}

// The server sends its own notifications as ordinary IMs from a reserved
// screen name. They must reach the notice log and never become a conversation
// — a "buddy" you cannot reply to, holding markup nobody would type.
func TestSystemMessageBecomesNoticeNotConversation(t *testing.T) {
	const body = `You just received 2 IM(s) while you were offline. ` +
		`If you do not wish to receive offline messages, please go to ` +
		`<a href="https://example.com/settings">IM Settings</a>.`

	for _, sender := range []string{"OOS System Msg", "AOL System Msg", "oossystemmsg"} {
		t.Run(sender, func(t *testing.T) {
			c, store := newTestClient(t)
			store.SetSelf("me")

			var notices []state.Event
			unsub := store.Subscribe(func(e state.Event) {
				if e.Kind == state.EventNotice {
					notices = append(notices, e)
				}
			})
			defer unsub()

			text, err := wire.MarshalICBMMessageText(body)
			if err != nil {
				t.Fatalf("build message: %v", err)
			}
			msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      1,
				ChannelID:   wire.ICBMChannelIM,
				TLVUserInfo: wire.TLVUserInfo{ScreenName: sender},
			}
			msg.TLVRestBlock.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, text))

			c.handleSNAC(
				wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient},
				marshal(t, msg),
			)

			if len(store.Conversations()) != 0 {
				t.Errorf("server notice created a conversation: %+v", store.Conversations())
			}
			if len(notices) != 1 {
				t.Fatalf("notice count = %d, want 1", len(notices))
			}
			if notices[0].Notice != body {
				t.Errorf("Notice = %q, want the message verbatim", notices[0].Notice)
			}
			// NoticeFrom is what tells the UI this is server markup rather than
			// one of our own plain-text notices.
			if notices[0].NoticeFrom != sender {
				t.Errorf("NoticeFrom = %q, want %q", notices[0].NoticeFrom, sender)
			}
		})
	}
}

// A person whose name merely resembles the reserved one is still a person.
func TestSystemSenderMatchIsExact(t *testing.T) {
	for _, name := range []string{"OOS System Msgs", "Not OOS System Msg", "system msg", "oos"} {
		if isSystemSender(name) {
			t.Errorf("isSystemSender(%q) = true, want false", name)
		}
	}
}
