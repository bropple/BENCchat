package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

// Encrypted chat rooms.
//
// A room has a symmetric group key that every member holds. Messages are sealed
// with it; the key itself is delivered out of band over the 1:1 E2EE channel,
// which means inviting someone is just sending them one encrypted IM.
//
// Two server behaviours shape this format, both verified against
// open-oscar-server:
//
//   - Chat messages keep ONLY their text, encoding and language TLVs; any
//     custom TLV is stripped before relay. So the key ID and version have to
//     live in-band, inside the message text. (The 1:1 ICBM path does not have
//     this restriction — the two are deliberately not symmetric.)
//   - The server runs an HTML tokenizer over chat text and regex-matches
//     "^//roll" to implement dice commands, REPLACING the message when it hits.
//     The envelope therefore starts with an ESC byte and carries only base64
//     after it, so it can neither match that pattern nor be mistaken for markup.
//
// Rooms are relay-only server-side — nothing is stored — so this protects
// messages in flight and from other room members, not history at rest.
//
// No forward secrecy: a leaked group key opens every message sealed under it.
// Rotation on membership change bounds the damage but does not eliminate it.

const (
	roomEnvelopePrefix   = "\x1bBENCO-ROOM:v1:"
	roomEnvelopePrefixV2 = "\x1bBENCO-ROOM:v2:"
	roomInvitePrefix     = "\x1bBENCO-ROOMINV:v1:"
	roomInvitePrefixV2   = "\x1bBENCO-ROOMINV:v2:"
	// v3 carries a BUNDLE of chains instead of a shared key.
	roomInvitePrefixV3 = "\x1bBENCO-ROOMINV:v3:"

	// roomKeyIDLen is how many bytes of the key's hash identify it. Eight is
	// ample to tell a handful of keys apart and keeps the envelope short.
	roomKeyIDLen = 8
)

// ErrUnknownRoomKey means the message was sealed with a key we don't hold —
// typically one from before we were invited, or after a rotation we missed. It
// is a "you can't read this" condition, not corruption.
var ErrUnknownRoomKey = errors.New("e2ee: message uses a room key we don't have")

// RoomKey is a chat room's symmetric group key.
type RoomKey [32]byte

// GenerateRoomKey mints a new group key.
func GenerateRoomKey() (RoomKey, error) {
	var k RoomKey
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("e2ee: generate room key: %w", err)
	}
	return k, nil
}

// RoomKeyID is the short identifier carried on every message sealed with a key.
//
// It exists so rotation doesn't strand history: a client keeps old keys, and
// each message says which one opens it. Without an ID, a rotated room would
// either lose its scrollback or have to trial-decrypt against every key.
func (k RoomKey) ID() string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:roomKeyIDLen])
}

// EncodeRoomKey renders a key for transport in an invite.
func EncodeRoomKey(k RoomKey) string { return base64.StdEncoding.EncodeToString(k[:]) }

// DecodeRoomKey parses one.
func DecodeRoomKey(s string) (RoomKey, error) {
	var k RoomKey
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, fmt.Errorf("e2ee: decode room key: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("e2ee: room key is %d bytes, want %d", len(b), len(k))
	}
	copy(k[:], b)
	return k, nil
}

// IsRoomEnvelope reports whether a chat message body is an encrypted one, of
// either version. v2 carries a per-sender signature inside the sealed payload;
// v1 is the original unsigned form, still readable so an older BENCchat in the
// room keeps working.
func IsRoomEnvelope(body string) bool {
	return strings.HasPrefix(body, roomEnvelopePrefix) ||
		strings.HasPrefix(body, roomEnvelopePrefixV2) ||
		strings.HasPrefix(body, roomEnvelopePrefixV3)
}

func roomEnvelopeParts(body string) (prefix, rest string, ok bool) {
	switch {
	case strings.HasPrefix(body, roomEnvelopePrefixV2):
		return roomEnvelopePrefixV2, body[len(roomEnvelopePrefixV2):], true
	case strings.HasPrefix(body, roomEnvelopePrefix):
		return roomEnvelopePrefix, body[len(roomEnvelopePrefix):], true
	}
	return "", "", false
}

// RoomEnvelopeKeyID returns which key a message was sealed with, so a client
// can distinguish "not encrypted", "encrypted and I can read it", and
// "encrypted with a key I don't have" without attempting decryption.
func RoomEnvelopeKeyID(body string) (string, bool) {
	_, rest, ok := roomEnvelopeParts(body)
	if !ok {
		return "", false
	}
	i := strings.Index(rest, ":")
	if i <= 0 {
		return "", false
	}
	return rest[:i], true
}

// SealRoom encrypts a room message under the group key, without a signature.
// Kept for tests and for talking to an older BENCchat; new sends should use
// SealRoomSigned so the message is attributable.
func SealRoom(message string, k RoomKey) (string, error) {
	return sealRoomPayload([]byte(message), k, roomEnvelopePrefix)
}

// SealRoomSigned encrypts a room message and signs it as this device.
//
// The signature covers the room name as well as the text, so the message cannot
// be replayed into a different room, and it sits inside the sealed payload so
// the server learns nothing about which device sent what.
func SealRoomSigned(room, message string, k RoomKey, signer SigningKeyPair) (string, error) {
	payload, err := signPayload(room, message, signer)
	if err != nil {
		return "", err
	}
	return sealRoomPayload(payload, k, roomEnvelopePrefixV2)
}

func sealRoomPayload(payload []byte, k RoomKey, prefix string) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("e2ee: room nonce: %w", err)
	}
	sealed := secretbox.Seal(nonce[:], payload, &nonce, (*[32]byte)(&k))
	return prefix + k.ID() + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenRoom decrypts a room message using whichever of our keys it names.
//
// keys is every key we hold for the room, current and retired, so scrollback
// from before a rotation still opens.
func OpenRoom(envelope string, keys map[string]RoomKey) (string, error) {
	msg, err := OpenRoomSigned("", envelope, keys, nil)
	return msg.Text, err
}

// OpenRoomSigned decrypts a room message and, when it carries a signature,
// checks it against the signing keys the claimed sender publishes.
//
// senderKeys may be empty — we may not have fetched their profile yet — in
// which case the message opens as unverified rather than being rejected. A
// signature that is present and WRONG returns ErrForgedSignature.
func OpenRoomSigned(room, envelope string, keys map[string]RoomKey, senderKeys []ed25519.PublicKey) (SignedMessage, error) {
	var out SignedMessage
	prefix, rest, isEnvelope := roomEnvelopeParts(envelope)
	if !isEnvelope {
		return out, errors.New("e2ee: not a room envelope")
	}
	id, ok := RoomEnvelopeKeyID(envelope)
	if !ok {
		return out, errors.New("e2ee: not a room envelope")
	}
	k, have := keys[id]
	if !have {
		return out, ErrUnknownRoomKey
	}
	_ = prefix
	rest = rest[len(id)+1:]
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return out, fmt.Errorf("e2ee: decode room envelope: %w", err)
	}
	if len(raw) < 24+secretbox.Overhead {
		return out, errors.New("e2ee: truncated room envelope")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	plain, opened := secretbox.Open(nil, raw[24:], &nonce, (*[32]byte)(&k))
	if !opened {
		return out, errors.New("e2ee: room message failed authentication")
	}

	text, signerID, sig, stamp, signed := parseSignedPayload(plain)
	out = SignedMessage{Text: text, SignerID: signerID, Signed: signed}
	if stamp != nil {
		// Decoded for the caller's convenience; verification uses the raw bytes.
		if st, derr := decodeStamped(stamp); derr == nil {
			out.SentAt, out.ID = st.SentAt, st.ID
		}
	}
	if !signed {
		return out, nil
	}
	verified, verr := VerifySigned(room, text, signerID, sig, stamp, senderKeys)
	if verr != nil {
		// Return the text alongside the error so a caller can show WHAT was
		// forged if it wants to, but the error makes ignoring it hard.
		return out, verr
	}
	out.Verified = verified
	return out, nil
}

// RoomInvite is an offer of a room's group key, carried over the 1:1 encrypted
// channel. The room name is base64'd so a name containing ':' can't split the
// message.
type RoomInvite struct {
	Room string
	// Chains is every chain the sender can read, each already wound forward to
	// where the conversation has got to. This is what a newcomer needs: one
	// chain would let them read only its owner, and views as the sender holds
	// them would grant the sender's own read-back.
	Chains []ChainView
	// Key is the legacy shared room key, zero on a v3 invite.
	Key RoomKey
	// Roster is a signed roster (see roster.go), carried verbatim.
	//
	// This is the newcomer's bootstrap: who is in the room, who owns it, and at
	// which epoch — all of it signed, so what they pin on arrival is a statement
	// somebody made rather than an assertion the invite happens to contain. Every
	// LATER membership change travels as a roster in its own right; the invite is
	// only the way to learn one before you are in the room to receive them.
	//
	// A bare name list used to live here, and the difference is the point: the
	// old one was unsigned, so a member relaying a rotation could rewrite anyone's
	// idea of who belonged, and had no epoch, so an old list could be replayed
	// over a new one.
	Roster string
}

// EncodeRoomInvite builds the invite body.
//
// Always emits v2. Both ends of an invite are BENCchat, and a client too old to
// parse v2 fails visibly (the invite does not arrive) rather than quietly, so a
// flag day is the right trade for a deployment this size — see CLAUDE.md.
func EncodeRoomInvite(inv RoomInvite) string {
	// base64 again, over the already-base64 roster body: it carries colons of
	// its own, and this field is parsed by position.
	bundle, err := EncodeChainBundle(inv.Chains)
	if err != nil {
		bundle = ""
	}
	return roomInvitePrefixV3 +
		base64.StdEncoding.EncodeToString([]byte(inv.Room)) + ":" +
		bundle + ":" +
		base64.StdEncoding.EncodeToString([]byte(inv.Roster))
}

// IsRoomInvite reports whether a 1:1 message body is a room invite. These are
// machine-to-machine and must never be shown as chat text.
func IsRoomInvite(body string) bool {
	return strings.HasPrefix(body, roomInvitePrefix) ||
		strings.HasPrefix(body, roomInvitePrefixV2) ||
		strings.HasPrefix(body, roomInvitePrefixV3)
}

// DecodeRoomInvite parses either version. v1 yields no roster, which callers
// must treat as "this client told us nothing about who is here" rather than as
// "the room is empty".
func DecodeRoomInvite(body string) (RoomInvite, bool) {
	var rest string
	v3 := strings.HasPrefix(body, roomInvitePrefixV3)
	v2 := v3 || strings.HasPrefix(body, roomInvitePrefixV2)
	switch {
	case v3:
		rest = body[len(roomInvitePrefixV3):]
	case v2:
		rest = body[len(roomInvitePrefixV2):]
	case strings.HasPrefix(body, roomInvitePrefix):
		rest = body[len(roomInvitePrefix):]
	default:
		return RoomInvite{}, false
	}

	i := strings.Index(rest, ":")
	if i <= 0 {
		return RoomInvite{}, false
	}
	nameRaw, err := base64.StdEncoding.DecodeString(rest[:i])
	if err != nil || len(nameRaw) == 0 {
		return RoomInvite{}, false
	}
	keyPart := rest[i+1:]

	var roster string
	if v2 {
		j := strings.Index(keyPart, ":")
		if j < 0 {
			return RoomInvite{}, false
		}
		raw, derr := base64.StdEncoding.DecodeString(keyPart[j+1:])
		if derr != nil {
			return RoomInvite{}, false
		}
		roster = string(raw)
		keyPart = keyPart[:j]
	}

	if v3 {
		// The middle field is a chain bundle rather than a key. Empty is legal —
		// a room whose members have not started chains yet.
		chains, cerr := DecodeChainBundle(keyPart)
		if cerr != nil {
			return RoomInvite{}, false
		}
		return RoomInvite{Room: string(nameRaw), Chains: chains, Roster: roster}, true
	}
	key, err := DecodeRoomKey(keyPart)
	if err != nil {
		return RoomInvite{}, false
	}
	return RoomInvite{Room: string(nameRaw), Key: key, Roster: roster}, true
}

// --- Room catch-up ----------------------------------------------------------
//
// Chat rooms are relay-only: open-oscar-server never stores a room message, so
// anything said while you were away is gone from the server's point of view.
// The only copies are held by the people who were present.
//
// Catch-up asks one of them to forward what you missed. It travels over the 1:1
// end-to-end encrypted channel — the same path room invitations use — so the
// history is protected in transit by the requester's own key, and the server
// sees only ciphertext.
//
// Note what this does NOT provide: a shared group key means any member can
// forge a message attributed to anyone, so a catch-up batch is only as
// trustworthy as the member who served it. That is inherent to symmetric group
// encryption, not something introduced here.

const catchupPrefix = "\x1bBENCO-CATCHUP:v1:"

// CatchupLimits bound a response so it fits an ICBM and cannot be used to make
// a peer serialize an unbounded history.
const (
	CatchupMaxMessages = 100
	CatchupMaxBytes    = 16 * 1024
)

// CatchupMessage is one archived room message.
//
// It carries the ORIGINAL sealed envelope rather than plaintext, so a member
// relaying history cannot alter what anyone said: the recipient decrypts and
// checks the sender's signature exactly as it would for a live message. A
// relaying member can still omit or reorder messages, but not invent them.
//
// Text is used only for messages that were never encrypted (a plaintext room),
// where there is nothing to verify anyway.
type CatchupMessage struct {
	From string `json:"f"`
	At   int64  `json:"t"` // unix seconds
	Text string `json:"m,omitempty"`
	Env  string `json:"e,omitempty"`
}

// CatchupRequest asks a peer what we missed in a room since a point in time.
type CatchupRequest struct {
	Room  string
	Since time.Time
}

// CatchupResponse carries the messages back.
type CatchupResponse struct {
	Room     string
	Messages []CatchupMessage
	// Truncated reports that older messages were dropped to fit the limits, so
	// the requester can say so rather than implying it has the full history.
	Truncated bool
}

// IsCatchup reports whether a 1:1 body is catch-up traffic. Like invites, these
// are machine-to-machine and must never be shown as chat text.
func IsCatchup(body string) bool { return strings.HasPrefix(body, catchupPrefix) }

// EncodeCatchupRequest builds a request body.
func EncodeCatchupRequest(req CatchupRequest) string {
	return catchupPrefix + "req:" +
		base64.StdEncoding.EncodeToString([]byte(req.Room)) + ":" +
		strconv.FormatInt(req.Since.Unix(), 10)
}

// EncodeCatchupResponse builds a response body, trimming to the limits by
// dropping the OLDEST messages first — the recent ones are what a returning
// member most needs.
func EncodeCatchupResponse(res CatchupResponse) (string, error) {
	msgs := res.Messages
	truncated := res.Truncated
	if len(msgs) > CatchupMaxMessages {
		msgs = msgs[len(msgs)-CatchupMaxMessages:]
		truncated = true
	}
	for {
		payload, err := json.Marshal(struct {
			T bool             `json:"tr,omitempty"`
			M []CatchupMessage `json:"m"`
		}{T: truncated, M: msgs})
		if err != nil {
			return "", fmt.Errorf("e2ee: encode catch-up: %w", err)
		}
		if len(payload) <= CatchupMaxBytes || len(msgs) == 0 {
			return catchupPrefix + "res:" +
				base64.StdEncoding.EncodeToString([]byte(res.Room)) + ":" +
				base64.StdEncoding.EncodeToString(payload), nil
		}
		// Still too big: drop the oldest quarter and try again.
		drop := len(msgs) / 4
		if drop == 0 {
			drop = 1
		}
		msgs = msgs[drop:]
		truncated = true
	}
}

// DecodeCatchup parses either kind of catch-up body. isRequest distinguishes
// them; ok is false for anything malformed.
func DecodeCatchup(body string) (isRequest bool, req CatchupRequest, res CatchupResponse, ok bool) {
	if !IsCatchup(body) {
		return false, req, res, false
	}
	rest := body[len(catchupPrefix):]
	kind, rest, found := strings.Cut(rest, ":")
	if !found {
		return false, req, res, false
	}
	roomB64, payload, found := strings.Cut(rest, ":")
	if !found {
		return false, req, res, false
	}
	roomRaw, err := base64.StdEncoding.DecodeString(roomB64)
	if err != nil || len(roomRaw) == 0 {
		return false, req, res, false
	}
	room := string(roomRaw)

	switch kind {
	case "req":
		secs, perr := strconv.ParseInt(payload, 10, 64)
		if perr != nil {
			return false, req, res, false
		}
		return true, CatchupRequest{Room: room, Since: time.Unix(secs, 0)}, res, true
	case "res":
		raw, derr := base64.StdEncoding.DecodeString(payload)
		if derr != nil {
			return false, req, res, false
		}
		var parsed struct {
			T bool             `json:"tr"`
			M []CatchupMessage `json:"m"`
		}
		if jerr := json.Unmarshal(raw, &parsed); jerr != nil {
			return false, req, res, false
		}
		if len(parsed.M) > CatchupMaxMessages {
			// A peer claiming more than the protocol allows gets trimmed rather
			// than trusted.
			parsed.M = parsed.M[:CatchupMaxMessages]
			parsed.T = true
		}
		return false, req, CatchupResponse{Room: room, Messages: parsed.M, Truncated: parsed.T}, true
	}
	return false, req, res, false
}
