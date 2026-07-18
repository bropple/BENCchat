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
)

// Per-sender signatures for room messages.
//
// A room's group key is symmetric, so it proves only that SOMEONE with the key
// sealed a message — any member can produce one attributed to any other member.
// That also means a member serving catch-up history could invent it wholesale.
//
// Each device therefore has an Ed25519 signing key alongside its X25519
// encryption key, published in the same profile marker. Every room message
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

// signingContext is what actually gets signed: the room name and the message,
// separated by a byte that cannot occur in either, so a room named "a" with
// message "b:c" cannot collide with room "a:b" and message "c".
func signingContext(room, message string) []byte {
	out := make([]byte, 0, len(room)+len(message)+1)
	out = append(out, room...)
	out = append(out, 0x00)
	out = append(out, message...)
	return out
}

// signPayload wraps a message with its signature, ready to be sealed.
//
//	[1] version
//	[8] signer key ID
//	[64] signature
//	[..] message
func signPayload(room, message string, kp SigningKeyPair) []byte {
	sig := ed25519.Sign(kp.Private, signingContext(room, message))
	id, _ := hex.DecodeString(SignerID(kp.Public))

	out := make([]byte, 0, 1+signerIDLen+ed25519.SignatureSize+len(message))
	out = append(out, signedPayloadV1)
	out = append(out, id...)
	out = append(out, sig...)
	out = append(out, message...)
	return out
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
}

// parseSignedPayload splits a decrypted payload back into message and
// signature. A payload that isn't in the signed format is returned as a plain
// unsigned message — that is what an older client sends.
func parseSignedPayload(raw []byte) (message string, signerID string, sig []byte, signed bool) {
	const header = 1 + signerIDLen + ed25519.SignatureSize
	if len(raw) < header || raw[0] != signedPayloadV1 {
		return string(raw), "", nil, false
	}
	id := hex.EncodeToString(raw[1 : 1+signerIDLen])
	sig = raw[1+signerIDLen : header]
	return string(raw[header:]), id, sig, true
}

// VerifySigned checks a parsed payload against the signing keys the claimed
// sender publishes.
//
// senderKeys is every signing key that sender advertises (they may have several
// devices). An empty set means we haven't learned their keys yet, which is
// "unknown", not "forged" — the two must not be conflated, since one is a
// routine timing gap and the other is an attack.
func VerifySigned(room, message, signerID string, sig []byte, senderKeys []ed25519.PublicKey) (bool, error) {
	if len(senderKeys) == 0 {
		return false, nil // unknown signer; caller re-checks once keys arrive
	}
	ctx := signingContext(room, message)
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
