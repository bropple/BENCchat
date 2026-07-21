package oscar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// IncomingMessage is a decoded inbound instant message.
type IncomingMessage struct {
	// From is the sender's screen name, in the server's canonical casing.
	From string
	Text string
	// AutoResponse marks an away-message auto-reply rather than a typed message.
	AutoResponse bool
	// Away reports whether the sender was away when they sent this.
	Away bool
	// SentAt is the original send time for a stored offline message (from the
	// SendTime TLV); zero for a live message.
	SentAt time.Time
}

// TypingEvent is an inbound typing notification.
type TypingEvent struct {
	From string
	// Event is one of wire.ICBMEvent{Gone,Typed,Typing}.
	Event uint16
}

// newICBMCookie generates the per-message cookie the server echoes back in its
// ack. It only has to be unique within a session; randomness is the simplest way
// to get that without tracking state.
func newICBMCookie() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a condition a chat client can meaningfully
		// recover from, and a zero cookie still works — the server treats it as
		// opaque.
		return 0
	}
	return binary.BigEndian.Uint64(b[:])
}

// SendMessage sends a channel-1 instant message to screenName and returns the
// cookie the server will echo in its acknowledgement.
//
// autoResponse marks the message as an away auto-reply. The server never reads
// that flag — it rides through untouched — so it is meaningful only between
// clients that honor it.
// SendMessage sends an instant message. It returns the ICBM cookie (which the
// server echoes in its acknowledgement) and the SNAC request ID (which it echoes
// in an error), so the caller can track whether the message actually landed.
func (s *Session) SendMessage(screenName, text string, autoResponse bool) (uint64, uint32, error) {
	body, err := wire.MarshalICBMMessageText(text)
	if err != nil {
		return 0, 0, err
	}

	cookie := newICBMCookie()
	msg := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     cookie,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: screenName,
	}
	msg.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, body))
	// Ask for an ack so a send can be confirmed rather than assumed. The server
	// only acks when this tag is present.
	msg.Append(wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}))
	// Store-and-forward if the recipient is offline; without this the server
	// rejects the message outright rather than holding it.
	msg.Append(wire.NewTLVBE(wire.ICBMTLVStore, []byte{}))
	if autoResponse {
		msg.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}

	// sendPaced (not Send) so the request ID comes back: the server correlates an
	// ICBM error to it, while an ack correlates by cookie. Tracking both is what
	// lets a caller tell "accepted", "rejected" and "silently dropped" apart.
	reqID, err := s.sendPaced(wire.ICBM, wire.ICBMChannelMsgToHost, msg)
	if err != nil {
		return 0, 0, fmt.Errorf("oscar: send message: %w", err)
	}
	return cookie, reqID, nil
}

// SendTyping sends a typing notification. event is one of
// wire.ICBMEvent{Gone,Typed,Typing}.
func (s *Session) SendTyping(screenName string, event uint16) error {
	return s.Send(wire.ICBM, wire.ICBMClientEvent, wire.SNAC_0x04_0x14_ICBMClientEvent{
		Cookie:     0,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: screenName,
		Event:      event,
	})
}

// DecodeIncomingMessage parses an inbound ICBMChannelMsgToClient body.
//
// Only channel-1 (plain IM) messages carry text; anything else — rendezvous
// file transfers, for instance — returns ok=false rather than an error, since
// receiving one is normal and simply not something we handle yet.
func DecodeIncomingMessage(body []byte) (IncomingMessage, bool, error) {
	var msg wire.SNAC_0x04_0x07_ICBMChannelMsgToClient
	if err := wire.UnmarshalBE(&msg, bytes.NewReader(body)); err != nil {
		return IncomingMessage{}, false, fmt.Errorf("oscar: decode inbound message: %w", err)
	}
	if msg.ChannelID != wire.ICBMChannelIM {
		return IncomingMessage{}, false, nil
	}

	data, ok := msg.TLVRestBlock.Bytes(wire.ICBMTLVAOLIMData)
	if !ok {
		return IncomingMessage{}, false, fmt.Errorf("oscar: inbound message from %q has no message TLV", msg.ScreenName)
	}
	text, err := wire.UnmarshalICBMMessageText(data)
	if err != nil {
		return IncomingMessage{}, false, err
	}

	out := IncomingMessage{
		From:         msg.ScreenName,
		Text:         text,
		AutoResponse: msg.TLVRestBlock.HasTag(wire.ICBMTLVAutoResponse),
		Away:         msg.IsAway(),
	}
	// A SendTime TLV means this is a stored offline message; use the original
	// send time so it doesn't appear to have arrived "just now".
	if secs, ok := msg.TLVRestBlock.Uint32BE(wire.ICBMTLVSendTime); ok {
		out.SentAt = time.Unix(int64(secs), 0)
	}
	return out, true, nil
}

// RetrieveOfflineMessages asks the server to deliver any messages stored while
// we were offline. They arrive as ordinary inbound messages carrying a SendTime.
func (s *Session) RetrieveOfflineMessages() error {
	if err := s.Send(wire.ICBM, wire.ICBMOfflineRetrieve, struct{}{}); err != nil {
		return fmt.Errorf("oscar: retrieve offline messages: %w", err)
	}
	return nil
}

// WarnUser sends a warning ("evil") to screenName. Anonymous warnings apply a
// smaller penalty and don't reveal the sender. The server only permits warning
// someone who has messaged you recently.
func (s *Session) WarnUser(screenName string, anonymous bool) error {
	sendAs := wire.EvilSendAsNamed
	if anonymous {
		sendAs = wire.EvilSendAsAnonymous
	}
	req := wire.SNAC_0x04_0x08_ICBMEvilRequest{SendAs: sendAs, ScreenName: screenName}
	if err := s.Send(wire.ICBM, wire.ICBMEvilRequest, req); err != nil {
		return fmt.Errorf("oscar: warn user: %w", err)
	}
	return nil
}

// WarnResult is a decoded EvilReply: the target's new warning level.
type WarnResult struct {
	DeltaApplied uint16
	NewLevel     uint16
}

// DecodeWarnResult parses an ICBMEvilReply.
func DecodeWarnResult(body []byte) (WarnResult, error) {
	var r wire.SNAC_0x04_0x09_ICBMEvilReply
	if err := wire.UnmarshalBE(&r, bytes.NewReader(body)); err != nil {
		return WarnResult{}, fmt.Errorf("oscar: decode warn reply: %w", err)
	}
	return WarnResult{DeltaApplied: r.EvilDeltaApplied, NewLevel: r.UpdatedEvilValue}, nil
}

// WarnedNotification is a decoded EvilNotification: our new warning level and
// who warned us (empty for an anonymous warning).
type WarnedNotification struct {
	NewLevel uint16
	From     string
}

// DecodeWarnedNotification parses an OServiceEvilNotification.
func DecodeWarnedNotification(body []byte) (WarnedNotification, error) {
	var n wire.SNAC_0x01_0x10_OServiceEvilNotification
	if err := wire.UnmarshalBE(&n, bytes.NewReader(body)); err != nil {
		return WarnedNotification{}, fmt.Errorf("oscar: decode evil notification: %w", err)
	}
	out := WarnedNotification{NewLevel: n.NewEvil}
	if n.Snitcher != nil {
		out.From = n.Snitcher.ScreenName
	}
	return out, nil
}

// DecodeTypingEvent parses an inbound ICBMClientEvent body.
func DecodeTypingEvent(body []byte) (TypingEvent, error) {
	var ev wire.SNAC_0x04_0x14_ICBMClientEvent
	if err := wire.UnmarshalBE(&ev, bytes.NewReader(body)); err != nil {
		return TypingEvent{}, fmt.Errorf("oscar: decode typing event: %w", err)
	}
	return TypingEvent{From: ev.ScreenName, Event: ev.Event}, nil
}
