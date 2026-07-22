package e2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// Handing a chain to the people who need it.
//
// Two shapes, because there are two situations and they are not the same one.
//
// A BROADCAST goes into the room itself: one message carrying the sender's new
// chain sealed once per recipient device. It reaches everybody present in a
// single send instead of one send each, and the member being removed receives it
// like everybody else and can open nothing — which is exactly what a rotation
// needs. It only reaches people who are IN the room, which is why the second
// shape exists.
//
// A BUNDLE travels 1:1 to somebody who is not in the room yet. It carries every
// chain the sender can read, each wound forward to where the conversation has
// got to, so a newcomer can read everyone from now on and nobody from before.
// Winding forward is the whole point: handing over the views as held would grant
// the sender's own read-back, which is the history the newcomer is not entitled
// to.

const (
	// ChainBroadcastPrefix marks an in-room chain distribution. Like the room
	// envelope it is ESC-prefixed base64, so the server's HTML tokenizer and its
	// "^//roll" match cannot mistake it for markup or a command.
	ChainBroadcastPrefix = "\x1bBENCO-CHAINDIST:v1:"

	chainSlotLabelLen = 8
	// sealedStateLen is a 32-byte chain state under NaCl box.
	sealedStateLen = 32 + box.Overhead
	chainSlotLen   = chainSlotLabelLen + 24 + sealedStateLen

	// maxChainSlots bounds one broadcast. A slot is 80 bytes and the body is
	// base64 inside a 65,535-byte FLAP payload, so this is what fits with room
	// to spare; past it the caller chunks.
	maxChainSlots = 580
)

// ErrNoSlotForUs means a broadcast carried no slot any of our devices can open.
// For a rotation that excluded us this is the intended outcome, not a fault.
var ErrNoSlotForUs = errors.New("e2ee: no chain slot for this device")

// ChainSlotLabel names the device a slot belongs to, so a recipient can find
// theirs without trial-opening every slot in the message.
//
// Labelling normally leaks the recipient set. It does not here: this rides in a
// room, and the server already knows who is in it.
func ChainSlotLabel(devicePub [32]byte) string {
	sum := sha256.Sum256(devicePub[:])
	return hex.EncodeToString(sum[:chainSlotLabelLen])
}

// IsChainBroadcast reports whether a room message body is a chain distribution.
// These are machine-to-machine and must never be shown as chat text.
func IsChainBroadcast(body string) bool {
	return strings.HasPrefix(body, ChainBroadcastPrefix)
}

// EncodeChainBroadcast seals a chain view once per recipient device.
//
// The index rides once outside the slots rather than inside each: it is the same
// for every recipient, and repeating it 580 times would be 2 KB of nothing.
func EncodeChainBroadcast(v ChainView, recipients [][32]byte, senderPriv [32]byte) (string, error) {
	// NOT dedupeKeys: that clamps to maxRecipients, which is a policy for how
	// many DEVICES one account may have and is far below a room's population.
	// Passing a room through it would silently drop most of the members and
	// leave them unable to read, with nothing to indicate it happened.
	recipients = distinctKeys(recipients)
	if len(recipients) == 0 {
		return "", errors.New("e2ee: no recipients for a chain broadcast")
	}
	if len(recipients) > maxChainSlots {
		return "", fmt.Errorf("e2ee: %d recipients exceeds %d per broadcast", len(recipients), maxChainSlots)
	}
	id, err := hex.DecodeString(v.ID)
	if err != nil || len(id) != chainIDLen {
		return "", errors.New("e2ee: malformed chain id")
	}

	buf := make([]byte, 0, 1+chainIDLen+4+2+len(recipients)*chainSlotLen)
	buf = append(buf, 1) // version
	buf = append(buf, id...)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], v.Index)
	buf = append(buf, idx[:]...)
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(recipients)))
	buf = append(buf, count[:]...)

	for _, pub := range recipients {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", fmt.Errorf("e2ee: chain slot nonce: %w", err)
		}
		label, err := hex.DecodeString(ChainSlotLabel(pub))
		if err != nil {
			return "", fmt.Errorf("e2ee: chain slot label: %w", err)
		}
		sealed := box.Seal(nil, v.state[:], &nonce, &pub, &senderPriv)
		if len(sealed) != sealedStateLen {
			return "", fmt.Errorf("e2ee: sealed state is %d bytes, want %d", len(sealed), sealedStateLen)
		}
		buf = append(buf, label...)
		buf = append(buf, nonce[:]...)
		buf = append(buf, sealed...)
	}
	return ChainBroadcastPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

// DecodeChainBroadcast opens the slot belonging to one of our devices.
//
// ourKeys is every device keypair we hold; senderPubs is every device key the
// claimed sender publishes, since we do not know which of their machines sent
// it. ErrNoSlotForUs means there was nothing here for us — the ordinary result
// of a rotation that left us out.
func DecodeChainBroadcast(body string, ourKeys []KeyPair, senderPubs [][32]byte) (ChainView, error) {
	var out ChainView
	if !IsChainBroadcast(body) {
		return out, errors.New("e2ee: not a chain broadcast")
	}
	raw, err := base64.StdEncoding.DecodeString(body[len(ChainBroadcastPrefix):])
	if err != nil {
		return out, fmt.Errorf("e2ee: decode chain broadcast: %w", err)
	}
	const header = 1 + chainIDLen + 4 + 2
	if len(raw) < header || raw[0] != 1 {
		return out, errors.New("e2ee: malformed chain broadcast")
	}
	chainID := hex.EncodeToString(raw[1 : 1+chainIDLen])
	index := binary.BigEndian.Uint32(raw[1+chainIDLen : 1+chainIDLen+4])
	count := int(binary.BigEndian.Uint16(raw[1+chainIDLen+4 : header]))
	if count == 0 || count > maxChainSlots || len(raw) < header+count*chainSlotLen {
		return out, errors.New("e2ee: truncated chain broadcast")
	}

	// Index our own labels once, then walk the slots. The other way round is
	// devices x slots box operations for no reason.
	mine := make(map[string]KeyPair, len(ourKeys))
	for _, kp := range ourKeys {
		mine[ChainSlotLabel(kp.Public)] = kp
	}

	for i := 0; i < count; i++ {
		off := header + i*chainSlotLen
		label := hex.EncodeToString(raw[off : off+chainSlotLabelLen])
		kp, ours := mine[label]
		if !ours {
			continue
		}
		var nonce [24]byte
		copy(nonce[:], raw[off+chainSlotLabelLen:off+chainSlotLabelLen+24])
		sealed := raw[off+chainSlotLabelLen+24 : off+chainSlotLen]
		for _, sp := range senderPubs {
			state, ok := box.Open(nil, sealed, &nonce, &sp, &kp.Private)
			if !ok || len(state) != 32 {
				continue
			}
			out.ID = chainID
			out.Index = index
			copy(out.state[:], state)
			return out, nil
		}
		// A slot addressed to us that will not open is worth reporting rather
		// than skipping: it means the sender used a key we no longer hold, or
		// somebody built the message wrong.
		return out, errors.New("e2ee: our chain slot failed to open")
	}
	return out, ErrNoSlotForUs
}

// distinctKeys removes duplicates without imposing any cap. A recipient set
// bigger than one message can hold is the caller's problem to chunk, and is
// refused loudly rather than trimmed.
func distinctKeys(keys [][32]byte) [][32]byte {
	seen := make(map[[32]byte]bool, len(keys))
	out := make([][32]byte, 0, len(keys))
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// MaxChainSlotsPerBroadcast is how many device slots fit in one message, so
// callers can chunk a large room.
func MaxChainSlotsPerBroadcast() int { return maxChainSlots }

// EncodeChainBundle renders every chain a newcomer needs, for an invite.
//
// Each view must already be wound forward by the caller — this layer cannot know
// where the conversation has got to, and quietly advancing here would hide the
// single most important decision in the whole exchange.
func EncodeChainBundle(views []ChainView) (string, error) {
	buf := make([]byte, 0, 2+len(views)*(chainIDLen+4+32))
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(views)))
	buf = append(buf, count[:]...)
	for _, v := range views {
		id, err := hex.DecodeString(v.ID)
		if err != nil || len(id) != chainIDLen {
			return "", errors.New("e2ee: malformed chain id in bundle")
		}
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], v.Index)
		buf = append(buf, id...)
		buf = append(buf, idx[:]...)
		buf = append(buf, v.state[:]...)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// DecodeChainBundle parses one.
func DecodeChainBundle(s string) ([]ChainView, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode chain bundle: %w", err)
	}
	if len(raw) < 2 {
		return nil, errors.New("e2ee: truncated chain bundle")
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	const entry = chainIDLen + 4 + 32
	if count > maxChainSlots || len(raw) != 2+count*entry {
		return nil, errors.New("e2ee: malformed chain bundle")
	}
	out := make([]ChainView, 0, count)
	for i := 0; i < count; i++ {
		off := 2 + i*entry
		var v ChainView
		v.ID = hex.EncodeToString(raw[off : off+chainIDLen])
		v.Index = binary.BigEndian.Uint32(raw[off+chainIDLen : off+chainIDLen+4])
		copy(v.state[:], raw[off+chainIDLen+4:off+entry])
		out = append(out, v)
	}
	return out, nil
}
