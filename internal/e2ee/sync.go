package e2ee

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Sent-message sync.
//
// A message you send reaches the person you sent it to and nobody else — which
// means your OWN other devices never see it. Open the conversation on the laptop
// and half of it is missing: their side, none of yours. That is not a subtle
// failure to notice, it is the thing that makes "link a device" read as a
// promise BENCchat does not keep.
//
// The fix is the one Signal uses, and it needs no new infrastructure: address a
// copy to YOURSELF. The server relays an inbound message to every instance of
// the recipient, so a message to your own screen name lands on all your devices
// and nowhere else.
//
// What this deliberately is NOT: escrow. The copy is sealed to your own device
// keys, so the server carries ciphertext it cannot open, exactly like every
// other message. Nothing is stored anywhere a key could later be handed over —
// which matters, because choosing not to have server-side key backup is what
// created this gap in the first place, and closing it by reintroducing one would
// be a bad trade.
//
// What it does not solve: a device that was offline when the copy went out gets
// nothing, because the server relays rather than stores whenever ANY instance is
// online. Catch-up for that is the export/LAN transfer problem, not this one.

// SyncPrefix marks a sent-message copy. Machine-to-machine, and it must never be
// rendered as chat text — the whole envelope is one of ours from end to end.
const SyncPrefix = "\x1bBENCO-SYNC:v1:"

// maxSyncText bounds the message a sync copy may carry. An ICBM is bounded
// anyway; this is here so a malformed length cannot make us allocate on the
// strength of a number that arrived from the wire.
const maxSyncText = 64 * 1024

// SentCopy is a message we sent, addressed to our own other devices.
type SentCopy struct {
	// Origin names the device that sent the original, by its signing key ID.
	//
	// It is here for one job: recognising our own copy coming back. Whether the
	// server relays a self-addressed message to the instance that sent it is not
	// a property worth depending on either way — this makes the answer not
	// matter, at the cost of eight bytes.
	Origin string
	// Peer is who the original went to.
	Peer string
	// Text is what was said.
	Text string
	// SentAt is when, as Unix seconds. Advisory: it is the sending device's
	// clock, and it is inside the sealed body so nobody but us can have touched
	// it, but it is still a clock.
	SentAt int64
}

// EncodeSentCopy renders a sync copy for sealing.
//
// Length-prefixed throughout, for the reason recorded in roomsign.go: a screen
// name and a message body are both arbitrary text, and a delimiter only
// delimits if it cannot occur in what it separates.
func EncodeSentCopy(c SentCopy) (string, error) {
	if len(c.Text) > maxSyncText {
		return "", fmt.Errorf("e2ee: sync copy is %d bytes, limit is %d", len(c.Text), maxSyncText)
	}
	buf := make([]byte, 0, 32+len(c.Peer)+len(c.Text))
	buf = appendLenPrefixed(buf, c.Origin)
	buf = appendLenPrefixed(buf, c.Peer)
	buf = appendLenPrefixed(buf, c.Text)
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(c.SentAt))
	buf = append(buf, at[:]...)
	return SyncPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

// SentCopyID is a stable identifier for a sync copy.
//
// Derived from the copy rather than assigned, so the same one arriving twice —
// over two connections, or after a reconnect — is recognisably the same message
// instead of appearing in the conversation a second time.
func SentCopyID(c SentCopy) string {
	h := sha256.New()
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(c.SentAt))
	h.Write(at[:])
	h.Write([]byte(c.Origin))
	h.Write([]byte{0x00})
	h.Write([]byte(c.Peer))
	h.Write([]byte{0x00})
	h.Write([]byte(c.Text))
	return "sync-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// IsSentCopy reports whether a decrypted 1:1 body is a sync copy.
func IsSentCopy(body string) bool { return strings.HasPrefix(body, SyncPrefix) }

// DecodeSentCopy parses one.
func DecodeSentCopy(body string) (SentCopy, error) {
	var c SentCopy
	if !IsSentCopy(body) {
		return c, errors.New("e2ee: not a sync copy")
	}
	raw, err := base64.StdEncoding.DecodeString(body[len(SyncPrefix):])
	if err != nil {
		return c, fmt.Errorf("e2ee: decode sync copy: %w", err)
	}

	take := func() (string, bool) {
		if len(raw) < 4 {
			return "", false
		}
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-4) {
			return "", false
		}
		s := string(raw[4 : 4+n])
		raw = raw[4+n:]
		return s, true
	}

	var ok bool
	if c.Origin, ok = take(); !ok {
		return SentCopy{}, errors.New("e2ee: truncated sync copy")
	}
	if c.Peer, ok = take(); !ok {
		return SentCopy{}, errors.New("e2ee: truncated sync copy")
	}
	if c.Text, ok = take(); !ok {
		return SentCopy{}, errors.New("e2ee: truncated sync copy")
	}
	if len(raw) < 8 {
		return SentCopy{}, errors.New("e2ee: truncated sync copy")
	}
	c.SentAt = int64(binary.BigEndian.Uint64(raw[:8]))
	if c.Peer == "" {
		return SentCopy{}, errors.New("e2ee: sync copy names no peer")
	}
	return c, nil
}
