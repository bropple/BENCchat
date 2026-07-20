// Package e2ee provides opt-in end-to-end encryption for 1:1 messages using
// NaCl box (X25519 key agreement + XSalsa20-Poly1305 authenticated encryption).
//
// Public keys are published to the server's device key directory, foodgroup
// 0xBE00 (see the client layer); the server only ever relays the resulting
// ciphertext, so it never sees plaintext. This is
// deliberately simple: static keys (no forward secrecy) and trust-on-first-use
// key discovery. It protects message content from the server and the network,
// not metadata (who talks to whom, when).
package e2ee

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// KeyPair is an X25519 keypair. Public is published (in the profile); Private is
// secret (kept in the OS secret store).
type KeyPair struct {
	Public  [32]byte
	Private [32]byte
}

// GenerateKeyPair creates a fresh X25519 keypair.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("e2ee: generate key: %w", err)
	}
	return KeyPair{Public: *pub, Private: *priv}, nil
}

// KeyPairFromPrivate reconstructs a full keypair from a stored private key by
// deriving the matching public key.
func KeyPairFromPrivate(priv [32]byte) (KeyPair, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("e2ee: derive public: %w", err)
	}
	kp := KeyPair{Private: priv}
	copy(kp.Public[:], pub)
	return kp, nil
}

// EncodeKey base64-encodes a 32-byte key (public or private).
func EncodeKey(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

// DecodeKey parses a base64-encoded 32-byte key.
func DecodeKey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, fmt.Errorf("e2ee: decode key: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("e2ee: key is %d bytes, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// envelopePrefix marks an encrypted message body. The leading ESC byte makes an
// accidental collision with a message a user actually typed essentially
// impossible, and it survives the ASCII message-text path unchanged.
const envelopePrefix = "\x1bBENCO-E2EE:v1:"

// IsEnvelope reports whether a message body is an E2EE envelope.
func IsEnvelope(body string) bool { return strings.HasPrefix(body, envelopePrefix) }

// Seal encrypts message for recipientPub, signed with senderPriv. The result is
// an envelope string safe to carry in a normal (ASCII) message body: the marker
// prefix followed by base64(nonce || ciphertext).
func Seal(message string, recipientPub, senderPriv [32]byte) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("e2ee: nonce: %w", err)
	}
	// Prepend the nonce so the recipient can recover it; box.Seal appends the
	// ciphertext to whatever is passed as the output prefix.
	sealed := box.Seal(nonce[:], []byte(message), &nonce, &recipientPub, &senderPriv)
	return envelopePrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// BENCchat used to publish device keys inside the Locate profile, hidden in an
// HTML comment. That path is gone — keys live in the server's key directory now
// — but accounts that signed on under the old scheme still carry a marker in
// their bio, so the markers must still be recognized well enough to strip them
// before a profile is shown.
const (
	profileMarkerOpen  = "<!--BENCO-E2EE:v1:"
	profileMarkerClose = "-->"
)

// StripMarker removes the E2EE marker (and any surrounding whitespace) from a
// profile so it isn't shown to the user.
func StripMarker(profile string) string {
	i := strings.Index(profile, profileMarkerOpen)
	if i < 0 {
		return profile
	}
	rest := profile[i:]
	j := strings.Index(rest, profileMarkerClose)
	if j < 0 {
		return strings.TrimRight(profile[:i], " \n\r\t")
	}
	return strings.TrimRight(profile[:i], " \n\r\t") + rest[j+len(profileMarkerClose):]
}

// Open decrypts an envelope from senderPub using recipientPriv. It fails if the
// envelope is malformed or authentication doesn't verify (wrong key / tampered).
func Open(envelope string, senderPub, recipientPriv [32]byte) (string, error) {
	if !IsEnvelope(envelope) {
		return "", errors.New("e2ee: not an envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(envelope, envelopePrefix))
	if err != nil {
		return "", fmt.Errorf("e2ee: decode envelope: %w", err)
	}
	if len(raw) < 24 {
		return "", errors.New("e2ee: envelope too short")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	msg, ok := box.Open(nil, raw[24:], &nonce, &senderPub, &recipientPriv)
	if !ok {
		return "", errors.New("e2ee: decryption failed (wrong key or tampered)")
	}
	return string(msg), nil
}
