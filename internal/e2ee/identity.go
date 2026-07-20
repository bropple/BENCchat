package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// The account identity key, and cross-signing.
//
// Every device already has its own X25519 box key and Ed25519 signing key
// (see multidevice.go and roomsign.go). Those are per-machine and never leave
// the machine that made them. This file adds the key ABOVE them: one Ed25519
// keypair per ACCOUNT, whose only job is to sign the manifest listing which
// devices belong to that account.
//
// Signing the whole manifest — rather than each device key individually — is
// what closes the omission and rollback attacks; see docs/keydir-v2-proposal.md
// §3. This package does not know what a manifest looks like: it signs and
// verifies opaque bytes, because the encoding lives in the wire layer and the
// signature must cover exactly the bytes that travel.
//
// # Custody: transient, and the type is shaped to enforce it
//
// Per §5 of the proposal, the identity private key is NOT stored anywhere on
// the device. It is unwrapped from the server-side backup with the recovery
// key, used to sign one manifest, and destroyed. That is the whole point of
// cross-signing here: a stolen laptop yields that laptop's device key and
// nothing more, because the identity key was never on it.
//
// The obvious failure mode is someone deciding later that re-prompting for ten
// words is annoying and quietly caching the key in the keyring — which silently
// converts this design into the account-key model it was chosen over. So
// IdentityKey carries that contract in its name and doc, has no encoder for its
// private half other than the one that seals it into a backup, and offers Zero()
// so the correct thing to do when finished is also the easy thing.

// ErrIdentityKeyZeroed means an IdentityKey was used after Zero() destroyed it.
// It is a bug, not a user-facing condition: it means some caller held the key
// past the point it discarded it.
var ErrIdentityKeyZeroed = errors.New("e2ee: identity key has been zeroed")

// IdentityKey is an account's cross-signing keypair.
//
// DO NOT PERSIST THE PRIVATE HALF. Custody is transient by design (proposal
// §5): the only durable copy is the argon2id+secretbox backup produced by
// SealIdentityBackup, which lives on the server and can only be opened with the
// user's recovery key. Nothing in BENCchat may write Private to the keyring, to
// disk, to a log line, or into any structure that outlives the signing
// operation that needed it.
//
// The lifecycle a caller should follow is:
//
//	kp, err := OpenIdentityBackup(backup, recoveryKey)
//	defer kp.Zero()
//	sig, err := SignManifest(kp, manifestBytes)
//
// Zero() is deferred immediately on the line after acquisition so that no
// return path — including a panic — leaves the key sitting in memory.
type IdentityKey struct {
	// Public is the account identity public key. This one is fine to store: it
	// is what peers pin, and what a device compares against to notice that the
	// account's identity was replaced (proposal §6).
	Public ed25519.PublicKey

	// Private is the signing half. Transient. See the type doc.
	Private ed25519.PrivateKey
}

// GenerateIdentityKey creates a fresh account identity keypair, in memory only.
//
// Per proposal §12 this happens at step 1 of first run, BEFORE anything is
// written anywhere: the recovery key is generated and shown, and only once the
// user has acknowledged it does the key get sealed and uploaded. A crash before
// that point must leave no trace, which is only true if generation itself
// writes nothing.
func GenerateIdentityKey() (IdentityKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return IdentityKey{}, fmt.Errorf("e2ee: generate identity key: %w", err)
	}
	return IdentityKey{Public: pub, Private: priv}, nil
}

// IdentityKeyFromSeed rebuilds an identity keypair from its 32-byte seed.
//
// The seed is what the backup blob contains — see SealIdentityBackup for why
// the seed rather than the full 64-byte private key.
func IdentityKeyFromSeed(seed []byte) (IdentityKey, error) {
	if len(seed) != ed25519.SeedSize {
		return IdentityKey{}, fmt.Errorf("e2ee: identity seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return IdentityKey{Public: priv.Public().(ed25519.PublicKey), Private: priv}, nil
}

// Zero destroys the private half in place and marks the key unusable.
//
// Go's garbage collector may still have copied the bytes elsewhere, so this is
// a best effort rather than a guarantee — but it removes the copy that would
// otherwise sit in a live heap object for as long as the caller's struct does,
// which is the copy that actually matters when custody is supposed to last one
// signing operation.
//
// Zero is safe to call more than once, so `defer kp.Zero()` alongside an
// explicit call at the end of a happy path is fine.
func (k *IdentityKey) Zero() {
	for i := range k.Private {
		k.Private[i] = 0
	}
	k.Private = nil
}

// Zeroed reports whether the private half has been discarded.
func (k IdentityKey) Zeroed() bool { return len(k.Private) == 0 }

// seed returns the 32-byte seed the private key derives from. Unexported
// deliberately: the only legitimate consumer is SealIdentityBackup, and an
// exported accessor would be an invitation to write it somewhere.
func (k IdentityKey) seed() ([]byte, error) {
	if k.Zeroed() {
		return nil, ErrIdentityKeyZeroed
	}
	if len(k.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("e2ee: identity private key is %d bytes, want %d", len(k.Private), ed25519.PrivateKeySize)
	}
	return k.Private.Seed(), nil
}

// EncodeIdentityPublic renders an identity public key for storage or display.
// Only the public half has an encoder; see the IdentityKey doc.
func EncodeIdentityPublic(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodeIdentityPublic parses an identity public key.
func DecodeIdentityPublic(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode identity key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("e2ee: identity key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// --- Manifest signing -----------------------------------------------------
//
// These are byte-oriented on purpose. The proposal calls this out as "the
// single most important implementation note in this document" (§3): the
// manifest travels as opaque bytes and nothing may decode and re-encode it,
// because any encoding difference — a different integer width, a reordered
// field, a trailing pad byte — breaks every signature over it.
//
// So this package never sees a manifest struct. The caller encodes once, signs
// those exact bytes, and sends those exact bytes. On receipt the caller
// verifies the bytes AS RECEIVED and only then decodes them for display. A
// helper that took a struct and encoded it internally would look friendlier and
// would make the round-trip bug easy to write by accident, which is why there
// isn't one.

// ErrBadManifestSignature means a manifest's signature did not verify against
// the identity key that claimed to sign it. Treat it as hostile: it is either
// tampering in transit or a server serving something it forged.
var ErrBadManifestSignature = errors.New("e2ee: manifest signature does not verify")

// SignManifest produces a detached Ed25519 signature over already-encoded
// manifest bytes.
//
// It takes bytes, not a manifest, and returns a detached signature rather than
// a combined blob, so there is no encoding step anywhere between what was
// signed and what goes on the wire.
func SignManifest(kp IdentityKey, manifest []byte) ([]byte, error) {
	if kp.Zeroed() {
		return nil, ErrIdentityKeyZeroed
	}
	if len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("e2ee: identity private key is %d bytes, want %d", len(kp.Private), ed25519.PrivateKeySize)
	}
	if len(manifest) == 0 {
		// An empty manifest is never legitimate and signing one would produce a
		// perfectly valid signature over nothing, which is worse than an error.
		return nil, errors.New("e2ee: refusing to sign an empty manifest")
	}
	return ed25519.Sign(kp.Private, manifest), nil
}

// VerifyManifest checks a detached signature over manifest bytes exactly as
// they were received.
//
// Callers must pass the bytes the server returned, untouched. Decoding them
// into a struct and re-encoding before verification would verify a
// reconstruction rather than the statement that was actually signed.
func VerifyManifest(pub ed25519.PublicKey, manifest, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("e2ee: identity key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		// Checked explicitly rather than left to ed25519.Verify, which returns a
		// plain false and would make a truncated signature indistinguishable from
		// a forged one in the logs.
		return fmt.Errorf("e2ee: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if len(manifest) == 0 {
		return errors.New("e2ee: empty manifest")
	}
	if !ed25519.Verify(pub, manifest, sig) {
		return ErrBadManifestSignature
	}
	return nil
}

// --- Safety numbers derived from the identity key --------------------------
//
// BENCchat previously derived the safety number by hashing both sides' device
// key SETS, which necessarily changed it whenever anyone added or removed a
// machine. That churn is the reason people stop reading safety-number alerts,
// and the reason the alert is not believed on the one occasion it means
// something.
//
// Under cross-signing there is finally something stable underneath: the account
// identity key. Devices come and go beneath it, all signed by the same
// identity, and the number moves for exactly one event — the identity itself
// being replaced. Which, per proposal §6, is the one event that genuinely is
// either "they lost everything" or "someone took the account over", and is
// worth interrupting a human for.

// identitySafetyDomain domain-separates this digest, so it cannot collide with
// a bare hash of two 32-byte key blobs.
//
// The device-set rendering it originally guarded against is gone, but the
// prefix stays: removing it would change every safety number already shown to
// and recorded by users, which is precisely the churn this scheme exists to
// prevent.
const identitySafetyDomain = "BENCO-E2EE:identity-safety:v1\x00"

// identitySafetyDigest is the value both identity-based renderings derive from.
//
// The two keys are ordered against each other rather than by role, so both
// parties compute the same digest without having to agree on who is "first".
// Rendering the digits and the emoji from ONE digest is what makes
// them provably the same number shown two ways rather than two codes of
// different strength.
func identitySafetyDigest(ours, theirs ed25519.PublicKey) [32]byte {
	x, y := []byte(ours), []byte(theirs)
	if bytes.Compare(x, y) > 0 {
		x, y = y, x
	}
	h := sha256.New()
	h.Write([]byte(identitySafetyDomain))
	h.Write(x)
	h.Write(y)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// IdentitySafetyNumber renders the identity-based safety number as digits, in
// six space-separated groups of five.
//
// Returns "" when either key is missing — there is nothing to compare until
// both sides have published an identity, and an empty string is easier for a UI
// to treat as "not available yet" than a number derived from a zero key would
// be.
func IdentitySafetyNumber(ours, theirs ed25519.PublicKey) string {
	if len(ours) != ed25519.PublicKeySize || len(theirs) != ed25519.PublicKeySize {
		return ""
	}
	sum := identitySafetyDigest(ours, theirs)
	groups := make([]string, 6)
	for i := range groups {
		n := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % 100000
		groups[i] = fmt.Sprintf("%05d", n)
	}
	return strings.Join(groups, " ")
}

// IdentitySafetyEmoji renders the same identity safety number as emoji, through
// the existing 64-entry alphabet and the existing eighteen positions.
//
// The alphabet and count are untouched: they are a security parameter argued
// out in safetyemoji.go, and the only thing changing here is what gets hashed.
func IdentitySafetyEmoji(ours, theirs ed25519.PublicKey) []SafetyEmoji {
	if len(ours) != ed25519.PublicKeySize || len(theirs) != ed25519.PublicKeySize {
		return nil
	}
	return emojiFromDigest(identitySafetyDigest(ours, theirs))
}
