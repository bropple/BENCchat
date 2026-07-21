package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// roomConn is one joined room's Chat connection.
type roomConn struct {
	session *oscar.Session
	cancel  context.CancelFunc
	info    oscar.RoomInfo
}

// replyTimeout bounds each request/reply step of the join handshake, so a
// silent server can't wedge JoinRoom forever.
const replyTimeout = 20 * time.Second

// JoinRoom joins (creating if needed, on the private exchange) a room by name.
// It performs the full OSCAR chat dance: ensure a ChatNav connection, create/
// look up the room, request a Chat service connection on BOS, dial it, and go
// online. The server then pushes the roster and messages onto the new
// connection, which handleChatSNAC folds into the store. Serialized so two
// joins can't interleave on the shared reply channels.
func (c *Client) JoinRoom(name string) error {
	c.joinMu.Lock()
	defer c.joinMu.Unlock()

	// Already in it: joining again would open a second chat connection and
	// abandon the first without closing it. This matters for key rotation, which
	// delivers a fresh key for a room the member is already sitting in.
	if trimmed := trimRoomName(name); trimmed != "" {
		c.chatMu.Lock()
		for cookie, rc := range c.rooms {
			if rc != nil && strings.EqualFold(roomNameFromCookie(cookie), trimmed) {
				c.chatMu.Unlock()
				return nil
			}
		}
		c.chatMu.Unlock()
	}

	c.mu.Lock()
	bos := c.session
	c.mu.Unlock()
	if bos == nil {
		return errors.New("client: not signed on")
	}
	name = trimRoomName(name)
	if name == "" {
		return errors.New("client: enter a room name")
	}

	nav, err := c.ensureChatNav(bos)
	if err != nil {
		return err
	}

	// Create or look up the room; the reply carries its real cookie.
	drain(c.navReply)
	if _, err := nav.CreateRoom(name); err != nil {
		return fmt.Errorf("client: request room: %w", err)
	}
	navBody, err := await(c.navReply)
	if err != nil {
		return fmt.Errorf("client: room lookup: %w", err)
	}
	room, err := oscar.DecodeNavInfo(navBody)
	if err != nil {
		return err
	}

	// Ask BOS for a Chat connection to that room.
	drain(c.serviceReply)
	if _, err := bos.RequestChatConnection(room); err != nil {
		return fmt.Errorf("client: request chat connection: %w", err)
	}
	grantBody, err := await(c.serviceReply)
	if err != nil {
		return fmt.Errorf("client: chat connect: %w", err)
	}
	grant, err := oscar.DecodeServiceGrant(grantBody)
	if err != nil {
		return err
	}

	// Dial the Chat connection, wire its handler, run it, then go online.
	chatCtx, cancel := context.WithCancel(context.Background())
	sess, err := oscar.DialService(chatCtx, bos.ScreenName(), grant, bos.Transport())
	if err != nil {
		cancel()
		return fmt.Errorf("client: dial chat: %w", err)
	}
	cookie := room.Cookie
	sess.Handler = func(f wire.SNACFrame, b []byte) { c.handleChatSNAC(cookie, f, b) }

	c.chatMu.Lock()
	c.rooms[cookie] = &roomConn{session: sess, cancel: cancel, info: room}
	c.chatMu.Unlock()

	go c.runRoom(chatCtx, cookie, sess)
	if err := sess.GoOnline(); err != nil {
		cancel()
		return fmt.Errorf("client: chat online: %w", err)
	}

	// Register the room and mark it joined; the roster/messages fill in as the
	// server pushes them. If it was a recent (persisted) room, its scrollback is
	// already present and new messages append to it.
	c.store.UpsertRoom(cookie, roomDisplayName(room))
	c.store.SetRoomJoined(cookie, true)
	return nil
}

// ensureChatNav returns the shared ChatNav connection, opening it on first use.
func (c *Client) ensureChatNav(bos *oscar.Session) (*oscar.Session, error) {
	c.chatMu.Lock()
	if c.chatNav != nil {
		nav := c.chatNav
		c.chatMu.Unlock()
		return nav, nil
	}
	c.chatMu.Unlock()

	drain(c.serviceReply)
	if _, err := bos.RequestService(wire.ChatNav, nil); err != nil {
		return nil, fmt.Errorf("client: request chatnav: %w", err)
	}
	grantBody, err := await(c.serviceReply)
	if err != nil {
		return nil, fmt.Errorf("client: chatnav connect: %w", err)
	}
	grant, err := oscar.DecodeServiceGrant(grantBody)
	if err != nil {
		return nil, err
	}

	navCtx, cancel := context.WithCancel(context.Background())
	nav, err := oscar.DialService(navCtx, bos.ScreenName(), grant, bos.Transport())
	if err != nil {
		cancel()
		return nil, fmt.Errorf("client: dial chatnav: %w", err)
	}
	nav.Handler = c.handleChatNavSNAC

	c.chatMu.Lock()
	c.chatNav = nav
	c.chatNavCancel = cancel
	c.chatMu.Unlock()

	go c.runService(navCtx, nav, c.clearChatNav)
	if err := nav.GoOnline(); err != nil {
		cancel()
		return nil, fmt.Errorf("client: chatnav online: %w", err)
	}
	return nav, nil
}

// SendRoomMessage sends to a joined room and echoes it locally (the server
// relays to everyone except the sender, so we add our own copy optimistically).
func (c *Client) SendRoomMessage(cookie, text string) error {
	c.chatMu.Lock()
	rc := c.rooms[cookie]
	c.chatMu.Unlock()
	if rc == nil {
		return errors.New("client: not in that room")
	}
	if text == "" {
		return errors.New("client: message is empty")
	}

	wireText, encrypted, err := c.sealRoomMessage(cookie, text)
	if err != nil {
		return err
	}
	if err := rc.session.SendChatMessage(wireText); err != nil {
		return err
	}
	// Store the plaintext locally — the server relays to everyone except the
	// sender, so this echo is the only copy we get.
	ourEnvelope := ""
	if encrypted {
		ourEnvelope = wireText
	}
	c.store.AddRoomMessage(cookie, state.Message{
		From:      c.store.Self().ScreenName,
		Text:      text,
		At:        time.Now(),
		Outgoing:  true,
		Encrypted: encrypted,
		// Our own messages are signed by us, so they are verified by definition.
		SenderVerified: encrypted && func() bool { _, ok := c.signingKey(); return ok }(),
		Envelope:       ourEnvelope,
	})
	return nil
}

// LeaveRoom closes a room's connection; runRoom removes it from the store.
func (c *Client) LeaveRoom(cookie string) {
	c.chatMu.Lock()
	rc := c.rooms[cookie]
	c.chatMu.Unlock()
	if rc != nil {
		rc.cancel()
	}
}

// handleChatNavSNAC routes the ChatNav connection's replies to the join flow.
func (c *Client) handleChatNavSNAC(frame wire.SNACFrame, body []byte) {
	if frame.FoodGroup == wire.ChatNav && frame.SubGroup == wire.ChatNavNavInfo {
		trySend(c.navReply, body)
	}
}

// handleChatSNAC folds a room's server-pushed roster and messages into the store.
func (c *Client) handleChatSNAC(cookie string, frame wire.SNACFrame, body []byte) {
	if frame.FoodGroup != wire.Chat {
		return
	}
	switch frame.SubGroup {
	case wire.ChatUsersJoined:
		if users, err := oscar.DecodeChatUsers(body); err == nil {
			// Record capabilities BEFORE announcing the arrival. The store event
			// makes the UI ask who in the room can read it, and if the answer is
			// computed from an empty capability map every new arrival is reported
			// as unable to read — with nothing re-rendering to correct it.
			if c.chatProbe != nil {
				c.chatProbe(users)
			}
			c.noteRoomCapabilities(cookie, users)
			c.store.RoomUsersJoined(cookie, oscar.ChatUserNames(users))
		}
	case wire.ChatUsersLeft:
		if users, err := oscar.DecodeChatUsers(body); err == nil {
			c.store.RoomUsersLeft(cookie, oscar.ChatUserNames(users))
		}
	case wire.ChatChannelMsgToClient:
		sender, text, err := oscar.DecodeChatMessage(body)
		if err != nil || text == "" {
			return
		}
		d := c.decodeRoomMessageFrom(cookie, sender, text)
		if d.Duplicate {
			return // already logged; the server handed us a copy it kept
		}
		envelope := ""
		if d.Encrypted {
			envelope = text
		}
		// Prefer the sender's signed claim about when they sent it. Stamping the
		// arrival is what let a replayed message read as something said just now,
		// since the server chooses when to deliver — and unlike the arrival time,
		// this one is covered by the signature and cannot be rewritten in transit.
		at := time.Now()
		if e2ee.PlausibleSendTime(d.SentAt, at) {
			at = d.SentAt
		}
		c.store.AddRoomMessage(cookie, state.Message{
			From: sender, Text: d.Text, At: at,
			Encrypted: d.Encrypted, SenderVerified: d.Verified, Signed: d.Signed, Forged: d.Forged,
			Envelope: envelope,
		})
		if d.Forged {
			c.store.Notify(state.NoticeWarn, "A message in “"+c.roomName(cookie)+
				"” claims to be from "+sender+" but isn't signed by them. Someone in the room may be impersonating them.")
		}
	case wire.ChatRoomInfoUpdate:
		if info, err := oscar.DecodeRoomInfoUpdate(body); err == nil {
			c.store.UpsertRoom(cookie, roomDisplayName(info))
		}
	}
}

// runRoom drives a room's read loop and cleans up when it ends (leave, server
// close, or BOS teardown). It never resets the store — only its own room.
func (c *Client) runRoom(ctx context.Context, cookie string, sess *oscar.Session) {
	_ = sess.Run(ctx)
	_ = sess.Close()
	c.chatMu.Lock()
	delete(c.rooms, cookie)
	c.chatMu.Unlock()
	// Keep the room as a re-joinable "recent" with its scrollback rather than
	// dropping it; a full sign-off clears everything via the store reset anyway.
	c.store.SetRoomJoined(cookie, false)
}

// runService drives a service connection's read loop (e.g. ChatNav) and calls
// onExit when it ends. It never resets the store.
func (c *Client) runService(ctx context.Context, sess *oscar.Session, onExit func()) {
	_ = sess.Run(ctx)
	_ = sess.Close()
	if onExit != nil {
		onExit()
	}
}

func (c *Client) clearChatNav() {
	c.chatMu.Lock()
	c.chatNav = nil
	c.chatNavCancel = nil
	c.chatMu.Unlock()
}

// closeAllChat tears down every chat connection (on sign-off or BOS loss). It
// only cancels contexts; each connection's run goroutine does its own cleanup,
// so no lock is held across the cascade.
func (c *Client) closeAllChat() {
	c.chatMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(c.rooms)+1)
	if c.chatNavCancel != nil {
		cancels = append(cancels, c.chatNavCancel)
	}
	for _, rc := range c.rooms {
		cancels = append(cancels, rc.cancel)
	}
	c.chatMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// --- small helpers for the request/reply channels ---

func trySend(ch chan []byte, body []byte) {
	select {
	case ch <- append([]byte(nil), body...):
	default: // a late/stale reply with nobody waiting is dropped
	}
}

func drain(ch chan []byte) {
	select {
	case <-ch:
	default:
	}
}

func await(ch chan []byte) ([]byte, error) {
	select {
	case b := <-ch:
		return b, nil
	case <-time.After(replyTimeout):
		return nil, errors.New("timed out waiting for the server")
	}
}

func roomDisplayName(r oscar.RoomInfo) string {
	if r.Name != "" {
		return r.Name
	}
	return r.Cookie
}

// trimRoomName normalizes whitespace in a user-entered room name.
func trimRoomName(name string) string {
	return strings.TrimSpace(name)
}

// roomNameFromCookie recovers a room's name from its cookie, which the server
// formats as "{exchange}-{instance}-{name}".
func roomNameFromCookie(cookie string) string {
	parts := strings.SplitN(cookie, "-", 3)
	if len(parts) != 3 {
		return cookie
	}
	return parts[2]
}
