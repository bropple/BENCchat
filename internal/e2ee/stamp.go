package e2ee

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Replay metadata.
//
// Neither envelope used to bind a message to a moment or an identity: a 1:1
// envelope was nonce plus ciphertext, and a room signature covered the room name
// and the text. Nothing else. So the server could take any message it had seen
// and deliver it again, whenever it liked, as many times as it liked, and every
// copy decrypted and authenticated as genuinely from the sender. Receive-side
// timestamps were assigned locally on arrival, so a replay looked like something
// said just now. Pulling a "yes, go ahead" out of last month and redelivering it
// today was the whole attack.
//
// Two things fix that, and the cheap one does most of the work:
//
//   - The sender stamps the message with WHEN THEY SENT IT, inside the sealed
//     and signed bytes. A replay then renders with its original timestamp, which
//     is the tell — a month-old "yes" that displays as a month old is not much of
//     an attack. This cannot be forged without the sending key.
//   - A random ID makes exact duplicates detectable, so an immediate replay is
//     dropped rather than merely looking odd.
//
// What this deliberately does NOT do is reject old messages. OSCAR stores
// offline messages server-side and delivers them at sign-on, which can be days
// later, so "too old" is indistinguishable from "you were away". Rejecting on
// age would break offline delivery to fix a problem the timestamp already
// surfaces.

// Stamped is a message together with the replay metadata sealed alongside it.
type Stamped struct {
	// SentAt is when the SENDER says they sent it. Zero for a legacy envelope
	// that carried no stamp, in which case the receiver has nothing better than
	// its own clock.
	SentAt time.Time
	// ID is random per message, for duplicate detection.
	ID [16]byte
	// Text is the message itself.
	Text string
}

// stampLen is the fixed header: 8 bytes of unix milliseconds, then the ID.
const stampLen = 8 + 16

// NewStamp returns the metadata for a message about to be sent.
func NewStamp() (Stamped, error) {
	var s Stamped
	if _, err := rand.Read(s.ID[:]); err != nil {
		return Stamped{}, fmt.Errorf("e2ee: message id: %w", err)
	}
	s.SentAt = time.Now()
	return s, nil
}

// encodeStamped frames a message with its metadata, for sealing.
//
// Fixed-width and length-prefix-free on purpose: the text is whatever remains,
// so there is no length field to disagree with reality.
func encodeStamped(s Stamped, message string) []byte {
	out := make([]byte, stampLen, stampLen+len(message))
	binary.BigEndian.PutUint64(out[:8], uint64(s.SentAt.UnixMilli()))
	copy(out[8:stampLen], s.ID[:])
	return append(out, message...)
}

// decodeStamped parses a framed message.
func decodeStamped(raw []byte) (Stamped, error) {
	if len(raw) < stampLen {
		return Stamped{}, errors.New("e2ee: message is too short to carry its stamp")
	}
	var s Stamped
	s.SentAt = time.UnixMilli(int64(binary.BigEndian.Uint64(raw[:8])))
	copy(s.ID[:], raw[8:stampLen])
	s.Text = string(raw[stampLen:])
	return s, nil
}

// PlausibleSendTime reports whether a claimed send time is one a receiver should
// show as-is.
//
// Only the future is bounded. A message from well ahead of our clock would sort
// to the top of a conversation and stay there, which is a nuisance an attacker
// (or a badly set clock) could inflict deliberately. Age is NOT bounded: an
// offline message legitimately arrives days after it was sent, and treating that
// as suspicious would break the case OSCAR's offline store exists for.
func PlausibleSendTime(sentAt, now time.Time) bool {
	if sentAt.IsZero() {
		return false
	}
	return !sentAt.After(now.Add(clockSkewAllowance))
}

// clockSkewAllowance is how far ahead of us a sender's clock may be before their
// timestamp stops being believable. Generous: unsynchronised clocks drift by
// minutes and that is not an attack.
const clockSkewAllowance = 15 * time.Minute
