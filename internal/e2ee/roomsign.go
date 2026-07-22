package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Per-sender signatures for room messages.
//
// A room's group key is symmetric, so it proves only that SOMEONE with the key
// sealed a message — any member can produce one attributed to any other member.
// That also means a member serving catch-up history could invent it wholesale.
//
// Each device therefore has an Ed25519 signing key alongside its X25519
// encryption key, both named by the same entry in the account's signed device
// manifest and served from the key directory. Every room message
// carries a signature over the room name and the plaintext, made with the
// sender's signing key, and recipients check it against the keys the claimed
// sender publishes.
//
// The room name is part of what's signed so a message cannot be lifted from one
// room and replayed into another where the forger is also a member.
//
// The signature lives INSIDE the sealed payload: putting it outside would tell
// the server which device sent each message, handing it a per-device activity
// trace it currently cannot see.

const (
	signerIDLen = 8
	// signedPayloadV1 prefixes the plaintext inside a sealed room message.
	signedPayloadV1 = 1
	// signedPayloadV2 adds a stamp — when the sender sent it, and a message ID —
	// between the signature and the text, and BINDS both into what is signed.
	// Without that a room message said nothing about when it was said, so the
	// server could replay any message it had seen, whenever it liked, and every
	// copy verified as genuinely the sender's. See stamp.go.
	signedPayloadV2 = 2
)

// ErrForgedSignature means a room message carried a signature that does NOT
// verify against the claimed sender's keys. Unlike an unknown signer, this is
// positive evidence of tampering or impersonation and must never be shown as an
// ordinary message.
var ErrForgedSignature = errors.New("e2ee: room message signature does not verify")

// SigningKeyPair is a device's Ed25519 identity for signing room messages.
type SigningKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateSigningKey creates a device signing key.
func GenerateSigningKey() (SigningKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKeyPair{}, fmt.Errorf("e2ee: generate signing key: %w", err)
	}
	return SigningKeyPair{Public: pub, Private: priv}, nil
}

// SigningKeyFromSeed rebuilds a signing key from its stored seed.
func SigningKeyFromSeed(seed []byte) (SigningKeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return SigningKeyPair{}, fmt.Errorf("e2ee: signing seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return SigningKeyPair{Public: priv.Public().(ed25519.PublicKey), Private: priv}, nil
}

// EncodeSigningSeed renders the private seed for the secret store. Only the
// seed is kept — the rest of the private key derives from it.
func EncodeSigningSeed(kp SigningKeyPair) string {
	return base64.StdEncoding.EncodeToString(kp.Private.Seed())
}

// DecodeSigningSeed parses a stored seed.
func DecodeSigningSeed(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode signing seed: %w", err)
	}
	return b, nil
}

// EncodeSigningKey renders a public signing key for publication.
func EncodeSigningKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodeSigningKey parses a published public signing key.
func DecodeSigningKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode signing key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("e2ee: signing key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// SignerID identifies which device signed, so a recipient can pick the right
// key out of a multi-device set without trying all of them.
func SignerID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:signerIDLen])
}

// signingContext is what a v1 payload signed: the room name and the message,
// separated by a byte that cannot occur in either, so a room named "a" with
// message "b:c" cannot collide with room "a:b" and message "c".
//
// Kept because v1 messages still have to verify.
func signingContext(room, message string) []byte {
	out := make([]byte, 0, len(room)+len(message)+1)
	out = append(out, room...)
	out = append(out, 0x00)
	out = append(out, message...)
	return out
}

// signingContextV2 additionally covers the stamp, which is the entire point of
// carrying one: a timestamp the sender does not sign is a timestamp anybody
// downstream can rewrite, and the attack it defends against is precisely a
// downstream party choosing when a message appears to have been sent.
func signingContextV2(room string, stamp []byte, message string) []byte {
	out := make([]byte, 0, len(room)+1+len(stamp)+len(message))
	out = append(out, room...)
	out = append(out, 0x00)
	out = append(out, stamp...)
	out = append(out, message...)
	return out
}

// signPayload wraps a message with its signature, ready to be sealed.
//
//	[1] version
//	[8] signer key ID
//	[64] signature
//	[24] stamp — sent-at millis, then message ID
//	[..] message
func signPayload(room, message string, kp SigningKeyPair) ([]byte, error) {
	st, err := NewStamp()
	if err != nil {
		return nil, err
	}
	stamp := encodeStamped(st, "") // header only; the text is appended separately

	sig := ed25519.Sign(kp.Private, signingContextV2(room, stamp, message))
	id, _ := hex.DecodeString(SignerID(kp.Public))

	out := make([]byte, 0, 1+signerIDLen+ed25519.SignatureSize+stampLen+len(message))
	out = append(out, signedPayloadV2)
	out = append(out, id...)
	out = append(out, sig...)
	out = append(out, stamp...)
	out = append(out, message...)
	return out, nil
}

// SignedMessage is the result of opening a signed room payload.
type SignedMessage struct {
	Text string
	// SignerID names the device that signed, empty for an unsigned message.
	SignerID string
	// Signed reports whether a signature was present at all. An older BENCchat
	// sends unsigned messages, which are readable but not attributable.
	Signed bool
	// Verified reports that the signature checked out against a key the claimed
	// sender publishes.
	Verified bool
	// SentAt is when the sender says they sent it, covered by the signature.
	// Zero for a v1 payload, which carried no stamp.
	SentAt time.Time
	// ID is random per message, for spotting a duplicate.
	ID [16]byte
}

// parseSignedPayload splits a decrypted payload back into message and
// signature. A payload that isn't in the signed format is returned as a plain
// unsigned message — that is what an older client sends.
func parseSignedPayload(raw []byte) (message string, signerID string, sig []byte, stamp []byte, signed bool) {
	const header = 1 + signerIDLen + ed25519.SignatureSize
	if len(raw) < header {
		return string(raw), "", nil, nil, false
	}
	switch raw[0] {
	case signedPayloadV1:
		id := hex.EncodeToString(raw[1 : 1+signerIDLen])
		return string(raw[header:]), id, raw[1+signerIDLen : header], nil, true
	case signedPayloadV2:
		if len(raw) < header+stampLen {
			return string(raw), "", nil, nil, false
		}
		id := hex.EncodeToString(raw[1 : 1+signerIDLen])
		return string(raw[header+stampLen:]), id, raw[1+signerIDLen : header],
			raw[header : header+stampLen], true
	}
	// Not the signed format at all — that is what an older client sends.
	return string(raw), "", nil, nil, false
}

// VerifySigned checks a parsed payload against the signing keys the claimed
// sender publishes.
//
// senderKeys is every signing key that sender advertises (they may have several
// devices). An empty set means we haven't learned their keys yet, which is
// "unknown", not "forged" — the two must not be conflated, since one is a
// routine timing gap and the other is an attack.
// stamp is the raw stamp bytes for a v2 payload, or nil for v1. It is passed as
// bytes rather than a parsed struct so the context is rebuilt from exactly what
// arrived, never from a re-encoding of it — a signature covers bytes, and any
// round trip through a struct is a chance to produce different ones.
func VerifySigned(room, message, signerID string, sig, stamp []byte, senderKeys []ed25519.PublicKey) (bool, error) {
	if len(senderKeys) == 0 {
		return false, nil // unknown signer; caller re-checks once keys arrive
	}
	ctx := signingContext(room, message)
	if stamp != nil {
		ctx = signingContextV2(room, stamp, message)
	}
	var sawSigner bool
	for _, k := range senderKeys {
		if SignerID(k) != signerID {
			continue
		}
		sawSigner = true
		if ed25519.Verify(k, ctx, sig) {
			return true, nil
		}
	}
	if sawSigner {
		// The device is theirs but the signature doesn't check out: the message
		// was altered, or someone is replaying it into another room.
		return false, ErrForgedSignature
	}
	// The signer isn't a device this sender publishes. That is what forging
	// someone else's messages looks like — the forger can seal with the group
	// key but can only sign as themselves.
	return false, ErrForgedSignature
}

// attestContext is what a device signs to prove which device it is: a domain
// tag, the account name and the server's nonce, separated by a byte that cannot
// occur in a screen name.
//
// The account is in there so a signature collected on one account cannot be
// replayed onto another that enrols the same device key — and, more usefully, so
// an attestation can never be mistaken for a signature over anything else this
// key signs. Room messages use their own context for the same reason.
func attestContext(screenName string, nonce []byte) []byte {
	out := make([]byte, 0, len(attestDomain)+1+len(screenName)+1+len(nonce))
	out = append(out, attestDomain...)
	out = append(out, 0x00)
	out = append(out, screenName...)
	out = append(out, 0x00)
	out = append(out, nonce...)
	return out
}

// attestDomain separates an attestation from everything else this key signs.
//
// Without it the two constructions collide outright: a room signature covers
// `room || 0x00 || message` and an attestation covered `account || 0x00 ||
// nonce`, which are the same bytes when a room is named after an account and
// carries the nonce as its text. Contrived to exploit, trivial to prevent, and
// exactly what domain separation is for — a test fails if they ever line up
// again.
const attestDomain = "BENCO-ATTEST-v1"

// SignAttestation answers a server device challenge.
func SignAttestation(screenName string, nonce []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, attestContext(screenName, nonce))
}

// VerifyAttestation checks one, for tests and for anybody reimplementing the
// client half.
func VerifyAttestation(screenName string, nonce []byte, pub ed25519.PublicKey, sig []byte) bool {
	return ed25519.Verify(pub, attestContext(screenName, nonce), sig)
}
