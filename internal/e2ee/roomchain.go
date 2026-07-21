package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

// Room messages sealed under a per-sender chain.
//
// The v1 and v2 envelopes name a shared room KEY; this one names the sender's
// CHAIN and the position within it, and the key is derived rather than shared.
// Both remain readable — a room that has not migrated, and scrollback from
// before one that has, still open under the old path.
//
// What the position buys is in ratchet.go: somebody handed the chain at position
// N cannot derive keys before N, so a newcomer reads nothing said before they
// arrived without anybody re-keying.
//
// The index rides outside the sealed part because the recipient needs it to
// derive the key before there is anything to open. It does not need separate
// authentication: a tampered index yields a different message key and the
// secretbox simply fails to authenticate, so a flipped index is indistinguishable
// from corruption and is rejected the same way.

const roomEnvelopePrefixV3 = "\x1bBENCO-ROOM:v3:"

// ErrUnknownChain means the message names a chain we hold no view of — the
// sender started a new one and we have not been given it yet, or we were never a
// member when it began. A "you can't read this" condition, not corruption.
var ErrUnknownChain = errors.New("e2ee: message uses a chain we don't have")

// IsRoomChainEnvelope reports whether a body is a chain-sealed room message.
func IsRoomChainEnvelope(body string) bool {
	return strings.HasPrefix(body, roomEnvelopePrefixV3)
}

// RoomEnvelopeChain returns which chain and position a message names, so a
// client can tell "encrypted and readable" from "encrypted under a chain I don't
// have" without attempting decryption.
func RoomEnvelopeChain(body string) (chainID string, index uint32, ok bool) {
	if !IsRoomChainEnvelope(body) {
		return "", 0, false
	}
	rest := body[len(roomEnvelopePrefixV3):]
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 || len(parts[0]) != chainIDLen*2 {
		return "", 0, false
	}
	n, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	return parts[0], uint32(n), true
}

// SealRoomChain encrypts and signs a room message under the sender's own chain,
// advancing it past the position used.
func SealRoomChain(room, message string, c *Chain, signer SigningKeyPair) (string, error) {
	if c == nil {
		return "", errors.New("e2ee: no outbound chain for this room")
	}
	payload, err := signPayload(room, message, signer)
	if err != nil {
		return "", err
	}
	key, index := c.Next()

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("e2ee: room nonce: %w", err)
	}
	sealed := secretbox.Seal(nonce[:], payload, &nonce, &key)

	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], index)
	return roomEnvelopePrefixV3 + c.ID + ":" +
		strconv.FormatUint(uint64(index), 16) + ":" +
		base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenRoomChain decrypts a chain-sealed room message and checks its signature.
//
// views is every sender chain we hold for the room. A message naming one we do
// not have returns ErrUnknownChain; one naming a position EARLIER than our view
// returns ErrChainRewind, which is the ratchet doing its job rather than a
// failure — we joined partway through and cannot read what came before.
func OpenRoomChain(room, envelope string, views map[string]ChainView, senderKeys []ed25519.PublicKey) (SignedMessage, error) {
	var out SignedMessage

	chainID, index, ok := RoomEnvelopeChain(envelope)
	if !ok {
		return out, errors.New("e2ee: not a chain room envelope")
	}
	view, have := views[chainID]
	if !have {
		return out, ErrUnknownChain
	}
	key, err := view.MessageKey(index)
	if err != nil {
		return out, err // ErrChainRewind or ErrChainSkipTooLarge, both meaningful
	}

	rest := envelope[len(roomEnvelopePrefixV3):]
	parts := strings.SplitN(rest, ":", 3)
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return out, fmt.Errorf("e2ee: decode room envelope: %w", err)
	}
	if len(raw) < 24+secretbox.Overhead {
		return out, errors.New("e2ee: truncated room envelope")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	plain, opened := secretbox.Open(nil, raw[24:], &nonce, &key)
	if !opened {
		// Also what a tampered index looks like: a different position derives a
		// different key, and the wrong key fails to authenticate.
		return out, errors.New("e2ee: room message failed authentication")
	}

	text, signerID, sig, stamp, signed := parseSignedPayload(plain)
	out = SignedMessage{Text: text, SignerID: signerID, Signed: signed}
	if stamp != nil {
		if st, derr := decodeStamped(stamp); derr == nil {
			out.SentAt, out.ID = st.SentAt, st.ID
		}
	}
	if !signed {
		return out, nil
	}
	verified, verr := VerifySigned(room, text, signerID, sig, stamp, senderKeys)
	if verr != nil {
		return out, verr
	}
	out.Verified = verified
	return out, nil
}
