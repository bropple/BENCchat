package wire

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ICBM (0x0004) — instant messages.

// ICBM message channels.
const (
	ICBMChannelIM         uint16 = 0x01
	ICBMChannelRendezvous uint16 = 0x02
	ICBMChannelMIME       uint16 = 0x03
	ICBMChannelICQ        uint16 = 0x04
)

// ICBM TLV tags.
const (
	// ICBMTLVAOLIMData holds the message itself, as a fragment list.
	ICBMTLVAOLIMData uint16 = 0x02
	// ICBMTLVRequestHostAck asks the server to acknowledge the send. The server
	// strips this before relaying, so inbound messages never carry it.
	ICBMTLVRequestHostAck uint16 = 0x03
	// ICBMTLVAutoResponse marks a message as an away auto-reply. The server never
	// sets or reads it — it rides through untouched, so both ends are ours.
	ICBMTLVAutoResponse uint16 = 0x04
	ICBMTLVData         uint16 = 0x05
	// ICBMTLVStore asks the server to store the message if the recipient is
	// offline. Without it, messaging an offline user is an error.
	ICBMTLVStore uint16 = 0x06
	// ICBMTLVWantEvents is appended by the server when the sender has typing
	// notifications enabled.
	ICBMTLVWantEvents uint16 = 0x0B
	ICBMTLVSendTime   uint16 = 0x16
)

// Message text charsets (the Charset field of ICBMCh1Message).
const (
	ICBMCharsetASCII   uint16 = 0x0000
	ICBMCharsetUnicode uint16 = 0x0002 // UCS-2, big-endian
	ICBMCharsetLatin1  uint16 = 0x0003
)

// Typing notification events (SNAC 0x04,0x14). The server defines no constants
// and never inspects the value; these are the conventional OSCAR ones.
const (
	ICBMEventGone   uint16 = 0x0000
	ICBMEventTyped  uint16 = 0x0001
	ICBMEventTyping uint16 = 0x0002
)

// ICBMCh1Fragment IDs.
const (
	icbmFragmentCapabilities uint8 = 0x05
	icbmFragmentMessage      uint8 = 0x01
)

// ICBMCh1Fragment is one TLV element of a channel-1 message body.
type ICBMCh1Fragment struct {
	ID      uint8
	Version uint8
	Payload []byte `oscar:"len_prefix=uint16"`
}

// ICBMCh1Message is the payload of the message fragment: a charset/language
// pair followed by the text, which runs to the end of the fragment.
type ICBMCh1Message struct {
	Charset  uint16
	Language uint16
	Text     []byte
}

// SNAC_0x04_0x06_ICBMChannelMsgToHost is an outbound instant message.
//
//	uint64 cookie | uint16 channel | uint8 snLen | screen name | TLVs
type SNAC_0x04_0x06_ICBMChannelMsgToHost struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	TLVRestBlock
}

// SNAC_0x04_0x07_ICBMChannelMsgToClient is an inbound instant message. The
// sender is the embedded TLVUserInfo's screen name.
type SNAC_0x04_0x07_ICBMChannelMsgToClient struct {
	Cookie    uint64
	ChannelID uint16
	TLVUserInfo
	TLVRestBlock
}

// SNAC_0x04_0x0C_ICBMHostAck confirms a send. The server only sends it if the
// message carried ICBMTLVRequestHostAck.
type SNAC_0x04_0x0C_ICBMHostAck struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0x04_0x14_ICBMClientEvent is a typing notification, relayed in both
// directions.
type SNAC_0x04_0x14_ICBMClientEvent struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	Event      uint16
}

// SNAC_0x04_0x08_ICBMEvilRequest warns ("evils") a user. SendAs is 1 for an
// anonymous warning, 0 for a named one — note the flag reads inverted from its
// name.
type SNAC_0x04_0x08_ICBMEvilRequest struct {
	SendAs     uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0x04_0x09_ICBMEvilReply confirms a warning: the delta applied and the
// target's resulting warning level. Levels are in tenths of a percent (1000 =
// 100%).
type SNAC_0x04_0x09_ICBMEvilReply struct {
	EvilDeltaApplied uint16
	UpdatedEvilValue uint16
}

// SendAs values for ICBMEvilRequest.
const (
	EvilSendAsNamed     uint16 = 0
	EvilSendAsAnonymous uint16 = 1
)

// SNAC_0x04_0x05_ICBMParameterReply carries messaging limits.
type SNAC_0x04_0x05_ICBMParameterReply struct {
	MaxSlots             uint16
	ICBMFlags            uint32
	MaxIncomingICBMLen   uint16
	MaxSourceEvil        uint16
	MaxDestinationEvil   uint16
	MinInterICBMInterval uint32
}

// MarshalICBMMessageText builds the value of TLV 0x02 for a channel-1 text
// message: a capabilities fragment followed by the message fragment.
//
// Text is sent as ASCII when it is 7-bit clean, and as UCS-2 big-endian
// otherwise. Latin-1 is deliberately never produced: the server does not
// transcode it, so it would push the decoding problem onto the receiver, and it
// cannot represent anything outside its own 256 code points anyway.
func MarshalICBMMessageText(text string) ([]byte, error) {
	charset := ICBMCharsetASCII
	payload := []byte(text)

	if !isASCII(text) {
		charset = ICBMCharsetUnicode
		var err error
		if payload, err = encodeUTF16BE(text); err != nil {
			return nil, err
		}
	}

	msgBody := &bytes.Buffer{}
	if err := MarshalBE(ICBMCh1Message{Charset: charset, Text: payload}, msgBody); err != nil {
		return nil, fmt.Errorf("marshal ICBM message fragment: %w", err)
	}

	buf := &bytes.Buffer{}
	frags := []ICBMCh1Fragment{
		// The capabilities fragment is a fixed preamble every AIM client sends.
		{ID: icbmFragmentCapabilities, Version: 1, Payload: []byte{0x01, 0x01, 0x02}},
		{ID: icbmFragmentMessage, Version: 1, Payload: msgBody.Bytes()},
	}
	for _, f := range frags {
		if err := MarshalBE(f, buf); err != nil {
			return nil, fmt.Errorf("marshal ICBM fragment: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// ErrNoMessageFragment reports a channel-1 message body with no text fragment.
var ErrNoMessageFragment = errors.New("wire: ICBM message has no text fragment")

// UnmarshalICBMMessageText extracts the text from the value of TLV 0x02.
func UnmarshalICBMMessageText(b []byte) (string, error) {
	r := bytes.NewReader(b)

	for r.Len() > 0 {
		var f ICBMCh1Fragment
		if err := UnmarshalBE(&f, r); err != nil {
			return "", fmt.Errorf("decode ICBM fragment: %w", err)
		}
		if f.ID != icbmFragmentMessage {
			continue
		}

		var msg ICBMCh1Message
		if err := UnmarshalBE(&msg, bytes.NewReader(f.Payload)); err != nil {
			return "", fmt.Errorf("decode ICBM message fragment: %w", err)
		}
		return decodeICBMText(msg.Charset, msg.Text)
	}
	return "", ErrNoMessageFragment
}

// decodeICBMText converts message bytes to a Go string per the charset.
func decodeICBMText(charset uint16, b []byte) (string, error) {
	switch charset {
	case ICBMCharsetUnicode:
		return decodeUTF16BE(b)
	case ICBMCharsetLatin1:
		// The server does not transcode Latin-1, so we must: every byte is its own
		// code point. Passing these bytes through as a Go string would produce
		// invalid UTF-8 for anything >= 0x80.
		var sb bytes.Buffer
		for _, c := range b {
			sb.WriteRune(rune(c))
		}
		return sb.String(), nil
	default:
		// ASCII, and anything unrecognized. Invalid UTF-8 is replaced rather than
		// rejected: a mangled message is better than a dropped one.
		if !utf8.Valid(b) {
			return strings.ToValidUTF8(string(b), "�"), nil
		}
		return string(b), nil
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// encodeUTF16BE encodes text as big-endian UTF-16.
//
// The AIM "unicode" charset is UTF-16BE, which — unlike strict UCS-2 — uses
// surrogate pairs for characters outside the Basic Multilingual Plane, so emoji
// and other astral-plane text survive the round trip.
func encodeUTF16BE(s string) ([]byte, error) {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u>>8), byte(u))
	}
	return buf, nil
}

// decodeUTF16BE decodes big-endian UTF-16 (including surrogate pairs) into a Go
// string. Unpaired surrogates decode to U+FFFD.
func decodeUTF16BE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("wire: UTF-16 payload has odd length %d", len(b))
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u := uint16(b[i])<<8 | uint16(b[i+1])
		// Some clients pad with NUL code units; they are not real characters.
		if u == 0 {
			continue
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units)), nil
}
