package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// The identity-key backup: argon2id over the recovery key, secretbox over the
// identity seed.
//
// This blob is what makes transient custody (proposal §5) survivable. The
// identity private key lives nowhere durable except in here, and this lives on
// the server — which never sees the recovery key and so cannot open it.
//
// # The threat model this is tuned for
//
// Anyone who learns the account password can fetch this blob, and from then on
// they attack it OFFLINE: no server in the loop, no rate limit, no lockout, no
// way for anyone to notice they are trying. That is the opposite of a login
// hash, where the server is present and can throttle, and it is why the
// parameters below are far heavier than a login KDF would justify. The only
// thing costing an attacker anything is the KDF itself, so the KDF is the
// entire defence and is priced accordingly.
//
// It is also why the recovery key is generated rather than chosen
// (recoverykey.go): 110 bits behind even a weak KDF is unbreakable, whereas a
// human passphrase behind even a strong one often is not.

const (
	// Argon2id parameters.
	//
	// Measured on the development machine (8-core desktop, x86-64): ~0.64s.
	// Expect roughly 1-2s on a more ordinary laptop, which is the target — this
	// runs when linking a device or verifying possession, both rare and both
	// moments where the user is already waiting on a deliberate action. Nothing
	// on a hot path pays this.
	//
	// The memory cost is the important number, not the time cost. Argon2's
	// resistance to GPU and ASIC attack comes almost entirely from memory
	// hardness: at 512 MiB per guess an attacker's parallelism is bounded by
	// their RAM rather than by their core count, which is what turns a card with
	// thousands of shaders into a handful of concurrent guesses. Trading memory
	// down for more passes would keep the wall-clock time and give most of the
	// defence away.
	//
	// 512 MiB is the largest figure that is still unremarkable to allocate
	// briefly on a desktop, which is the only platform BENCchat targets. It
	// would be the wrong number for a mobile client, and if one is ever built
	// these parameters travel with the blob (see BackupParams) so that client
	// can read backups written under them without anything being re-keyed.
	//
	// argon2id rather than argon2i or argon2d: it is the variant the RFC 9106
	// authors recommend when there is no specific reason to prefer another, and
	// the hybrid gives side-channel resistance on the first pass plus
	// time-memory-tradeoff resistance after it. This blob is decrypted on the
	// user's own machine, where a side-channel attacker is already in a strong
	// position, so the argon2d half is doing the work that matters here.
	backupArgonTime    uint32 = 4
	backupArgonMemory  uint32 = 512 * 1024 // KiB
	backupArgonThreads uint8  = 4

	// backupSaltLen is 16 bytes. The salt's job is to stop one precomputed table
	// covering every account's backup; 128 bits makes a collision between two
	// accounts irrelevant in practice, and RFC 9106 names 16 as the recommended
	// length.
	backupSaltLen = 16

	// backupKeyLen is secretbox's key size.
	backupKeyLen = 32

	// backupParamsLen is the encoded length of BackupParams: two uint32 and a
	// uint8.
	backupParamsLen = 4 + 4 + 1
)

// ErrBackupOpen means the backup did not decrypt. The overwhelmingly likely
// cause is the wrong recovery key, and that is what a UI should say — but it is
// deliberately not distinguishable from a corrupted or tampered blob, because
// secretbox authenticates and cannot tell us which it was.
var ErrBackupOpen = errors.New("e2ee: could not open identity backup (wrong recovery key, or the backup is damaged)")

// BackupParams are the argon2id cost parameters a particular backup was written
// under.
//
// They travel WITH the blob rather than being compiled in, which is the whole
// reason the parameters above can be raised later without stranding backups
// written under the old ones: an old blob is opened with its own parameters and
// re-sealed under the current ones the next time the user re-keys (proposal
// §10). A client that assumed the current constants would simply fail to open
// anything older, silently and unrecoverably.
type BackupParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultBackupParams returns the parameters new backups are written under.
func DefaultBackupParams() BackupParams {
	return BackupParams{Time: backupArgonTime, Memory: backupArgonMemory, Threads: backupArgonThreads}
}

// Encode renders the parameters as the opaque byte string the wire layer
// carries in the backup's Params field. Big-endian, fixed width: this is a
// stored format, so it cannot depend on host byte order.
func (p BackupParams) Encode() []byte {
	out := make([]byte, backupParamsLen)
	binary.BigEndian.PutUint32(out[0:4], p.Time)
	binary.BigEndian.PutUint32(out[4:8], p.Memory)
	out[8] = p.Threads
	return out
}

// DecodeBackupParams parses what Encode wrote.
func DecodeBackupParams(b []byte) (BackupParams, error) {
	if len(b) != backupParamsLen {
		return BackupParams{}, fmt.Errorf("e2ee: backup params are %d bytes, want %d", len(b), backupParamsLen)
	}
	p := BackupParams{
		Time:    binary.BigEndian.Uint32(b[0:4]),
		Memory:  binary.BigEndian.Uint32(b[4:8]),
		Threads: b[8],
	}
	return p, p.validate()
}

// validate rejects parameters that argon2.IDKey would panic on, and ones that
// would make opening a backup a denial of service against the machine doing it.
//
// The parameters come off the wire from a server that is not trusted (proposal
// §7), so a hostile one could otherwise return Memory = 4 TiB and hang or kill
// the client. Zero values are refused for the same reason argon2 refuses them:
// they are not a weak KDF, they are not a KDF.
func (p BackupParams) validate() error {
	switch {
	case p.Time == 0:
		return errors.New("e2ee: backup params: time cost is zero")
	case p.Threads == 0:
		return errors.New("e2ee: backup params: parallelism is zero")
	case p.Memory < 8*uint32(p.Threads):
		// argon2's own lower bound; below it the implementation misbehaves.
		return fmt.Errorf("e2ee: backup params: memory %d KiB too low for parallelism %d", p.Memory, p.Threads)
	case p.Memory > 4*1024*1024:
		// 4 GiB. Well above anything this code writes, and low enough that a
		// hostile value fails fast instead of swapping the machine to death.
		return fmt.Errorf("e2ee: backup params: memory %d KiB is implausible", p.Memory)
	case p.Time > 64:
		return fmt.Errorf("e2ee: backup params: time cost %d is implausible", p.Time)
	}
	return nil
}

// IdentityBackup is the encrypted identity key as it is stored and transmitted.
//
// The fields map one-to-one onto the backup SNACs in proposal §4; the wire
// layer carries them as opaque byte strings and does not interpret any of them.
type IdentityBackup struct {
	Params BackupParams
	Salt   []byte
	// Blob is nonce || secretbox(identity seed). The nonce is prepended rather
	// than carried separately because it has no independent meaning and a field
	// that can be lost or mismatched separately from its ciphertext is a bug
	// waiting to happen.
	Blob []byte
}

// deriveBackupKey stretches a recovery key into a secretbox key.
//
// The salt is passed rather than derived from anything account-related: binding
// it to the screen name would be a small privacy leak (the server could confirm
// a guessed name from the blob alone) and would buy nothing, since a random
// per-backup salt already gives the uniqueness that matters.
func deriveBackupKey(recoveryKey string, salt []byte, p BackupParams) ([32]byte, error) {
	var key [32]byte
	if err := p.validate(); err != nil {
		return key, err
	}
	if len(salt) == 0 {
		return key, errors.New("e2ee: backup salt is empty")
	}
	// The recovery key is normalised first so that the same key typed with
	// spaces, in capitals, or with a stray double hyphen derives the SAME
	// wrapping key. Skipping this would make a perfectly correct recovery key
	// fail to open a backup purely because of how it was typed, which is the
	// most infuriating possible bug in this area.
	canonical, err := ParseRecoveryKey(recoveryKey)
	if err != nil {
		return key, err
	}
	out := argon2.IDKey([]byte(canonical), salt, p.Time, p.Memory, p.Threads, backupKeyLen)
	copy(key[:], out)
	return key, nil
}

// SealIdentityBackup encrypts an identity key under a recovery key, using the
// current default parameters and a fresh random salt.
//
// Only the 32-byte seed is sealed, not the 64-byte private key: the rest is the
// public key appended, which is derivable and already public. Sealing it too
// would add nothing except a second copy of a value that must agree with the
// first, and a mismatch between them is a class of bug not worth making
// possible.
//
// Per proposal §12 this must not be called until the user has acknowledged
// seeing their recovery key. Sealing and uploading first, then showing the key,
// leaves a crash window in which the server holds an identity encrypted under a
// key nobody ever saw — and the account is then dead with no indication why.
func SealIdentityBackup(kp IdentityKey, recoveryKey string) (IdentityBackup, error) {
	return sealIdentityBackup(kp, recoveryKey, DefaultBackupParams())
}

// sealIdentityBackup is the parameterised form. Unexported because production
// code should always write the current defaults — the parameters are on the
// wire so that OLD blobs can still be read, not so that new ones can be written
// weaker.
func sealIdentityBackup(kp IdentityKey, recoveryKey string, p BackupParams) (IdentityBackup, error) {
	seed, err := kp.seed()
	if err != nil {
		return IdentityBackup{}, err
	}
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return IdentityBackup{}, fmt.Errorf("e2ee: backup salt: %w", err)
	}
	key, err := deriveBackupKey(recoveryKey, salt, p)
	if err != nil {
		return IdentityBackup{}, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return IdentityBackup{}, fmt.Errorf("e2ee: backup nonce: %w", err)
	}
	// secretbox.Seal appends to its first argument, so passing the nonce there
	// produces nonce || ciphertext in one step.
	blob := secretbox.Seal(nonce[:], seed, &nonce, &key)
	return IdentityBackup{Params: p, Salt: salt, Blob: blob}, nil
}

// OpenIdentityBackup decrypts a backup with a recovery key.
//
// The returned key is transient — see the IdentityKey doc. Callers should
// `defer kp.Zero()` on the line after this returns.
func OpenIdentityBackup(b IdentityBackup, recoveryKey string) (IdentityKey, error) {
	if len(b.Blob) < 24+ed25519.SeedSize+secretbox.Overhead {
		return IdentityKey{}, errors.New("e2ee: identity backup is truncated")
	}
	key, err := deriveBackupKey(recoveryKey, b.Salt, b.Params)
	if err != nil {
		return IdentityKey{}, err
	}
	var nonce [24]byte
	copy(nonce[:], b.Blob[:24])
	seed, ok := secretbox.Open(nil, b.Blob[24:], &nonce, &key)
	if !ok {
		return IdentityKey{}, ErrBackupOpen
	}
	if len(seed) != ed25519.SeedSize {
		// Authenticated, so this is not an attack — it is a backup written by
		// something that disagreed about the format.
		return IdentityKey{}, fmt.Errorf("e2ee: identity backup holds %d bytes, want a %d-byte seed", len(seed), ed25519.SeedSize)
	}
	return IdentityKeyFromSeed(seed)
}

// RekeyIdentityBackup re-encrypts an already-opened identity under a new
// recovery key, at the current default parameters.
//
// This is the operation from proposal §10: the identity itself is unchanged, so
// every device stays signed and NOBODY's safety number moves. It is only
// possible at the one moment the plaintext identity key exists — immediately
// after the user supplied the current recovery key — which is also exactly the
// right bar, since it requires proving possession of the key being replaced.
//
// It is a thin wrapper over SealIdentityBackup and exists mainly to give that
// operation a name, so a reader of the calling code can see that re-keying is a
// distinct thing from bootstrapping a new identity. Confusing the two is the
// mistake §10 is written to prevent.
func RekeyIdentityBackup(kp IdentityKey, newRecoveryKey string) (IdentityBackup, error) {
	return SealIdentityBackup(kp, newRecoveryKey)
}
