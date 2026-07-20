package wire

import (
	"bytes"
	"fmt"
)

// The BENCO device key directory, foodgroup 0xBE00.
//
// This mirrors BENCoscar's wire/benco_keydir.go byte for byte. Where that file
// and docs/keydir-v2-proposal.md disagree, the server wins — it is the running
// contract, and a client that follows the document instead simply gets errors.
//
// The directory replaced publishing device keys inside the Locate profile,
// which only worked for peers who were ONLINE, could not see this account's own
// other devices, and let a removed machine silently republish itself.
//
// # v2: the client is the authority, not the server
//
// v1 sent a bare list of device keys and let the server arbitrate it, with
// revocation as a server-side tombstone. That left the server able to insert a
// device, drop one, or serve a stale list with no way for a client to tell.
//
// v2 sends a MANIFEST instead: the whole device set signed as one statement by
// an account identity key the server never holds. Per-device signatures would
// not have been enough — they stop a forged device but not an omitted one, and
// not an older list replayed, since each individual signature still verifies.
//
// Revocation is therefore no longer a protocol operation. Removing a device
// means publishing a manifest without it at counter+1, and a client that
// remembers the highest counter it has seen refuses the older manifest that
// still contains it. v1's Revoke/Restore subgroups are deleted, not deprecated.
const BENCOKeyDir uint16 = 0xBE00

// BENCOKeyDir subgroups.
//
// These are v2's numbers. They restart at 0x0002 rather than continuing past
// v1's range because v1 was deleted outright — nothing on the wire can still be
// using the old assignments.
//
// Note this is where the server and the proposal document diverge: the document
// put the backup pairs at 0x000A–0x000D, on the assumption v1 would keep
// 0x0006–0x0009. The server reused them. The server wins.
const (
	BENCOKeyDirErr              uint16 = 0x0001
	BENCOKeyDirPublishRequest   uint16 = 0x0002
	BENCOKeyDirPublishReply     uint16 = 0x0003
	BENCOKeyDirQueryRequest     uint16 = 0x0004
	BENCOKeyDirQueryReply       uint16 = 0x0005
	BENCOKeyDirPutBackupRequest uint16 = 0x0006
	BENCOKeyDirPutBackupReply   uint16 = 0x0007
	BENCOKeyDirGetBackupRequest uint16 = 0x0008
	BENCOKeyDirGetBackupReply   uint16 = 0x0009
)

// BENCOKeyDirVersion is the payload version we send.
//
// The foodgroup sits above wire.MDir, which on the server bounds a fixed array
// used for foodgroup version negotiation — so this foodgroup deliberately takes
// no part in that, and BENCchat must NOT list it in OServiceClientVersions.
// Support is discovered from the HostOnline foodgroup list instead, and the
// payload carries its own version.
//
// Nothing on either side branches on the value: v1 is gone, and the server
// rejects anything that is not 2 rather than routing it. The field is what the
// NEXT format change gets signalled with.
const BENCOKeyDirVersion uint16 = 2

// Key algorithm identifiers.
//
// Every key and signature on the wire carries one, which is what makes a
// post-quantum migration a version bump rather than a flag day.
//
// The ML-* values are RESERVED and unimplemented on both sides. The server
// REFUSES a request carrying one rather than ignoring it — accepting a
// signature it cannot verify, while reporting that it verified one, would be
// worse than an error — so a client must never send them speculatively.
const (
	BENCOAlgX25519   uint8 = 0x01 // message key agreement
	BENCOAlgEd25519  uint8 = 0x02 // signatures
	BENCOAlgMLKEM768 uint8 = 0x03 // reserved — post-quantum key agreement
	BENCOAlgMLDSA65  uint8 = 0x04 // reserved — post-quantum signatures
)

// Key lengths for the algorithms that are actually implemented.
//
// The reserved algorithms deliberately have no length constant: inventing one
// for a scheme nothing here implements would be a claim about a format nobody
// has committed to.
const (
	BENCOX25519KeyLen  = 32
	BENCOEd25519KeyLen = 32
	BENCOEd25519SigLen = 64
)

// BENCOKeyDirMaxManifestLen bounds a manifest, matching the server's cap.
//
// Worth knowing on the client side too: a manifest that exceeds this is
// rejected at publish time, so a caller adding devices without bound gets a
// refusal rather than a truncation.
const BENCOKeyDirMaxManifestLen = 16384

// BENCOKeyDirMaxBackupLen bounds each variable-length field of a backup.
const BENCOKeyDirMaxBackupLen = 4096

// BENCOKDFArgon2id is the only key derivation function defined for a backup.
//
// The server does not run it and could not check that a client did; it travels
// so a client knows how to derive the unwrapping key.
const BENCOKDFArgon2id uint8 = 0x01

// BENCOKey is a public key plus the algorithm it belongs to.
//
// The key is length-prefixed rather than fixed-size for the same reason the
// algorithm is explicit: an ML-KEM encapsulation key is 1184 bytes and an
// Ed25519 key is 32, and a layout that assumed either could not carry the other.
type BENCOKey struct {
	Alg uint8
	Key []byte `oscar:"len_prefix=uint16"`
}

// BENCODeviceV2 is one machine belonging to an account.
//
// Box is the X25519 public key messages are sealed to, and is the device's
// identity. Sign is the Ed25519 key that attributes chat-room messages.
//
// Label is a human name for the machine ("desktop", "thinkpad") so a device
// list stops being a wall of fingerprints. It is optional and may be empty, and
// clients should ship it empty and let the user opt in: it sits inside the
// signed manifest so the server cannot FORGE it, but nothing hides it from the
// server, and it tells anyone holding the account password what hardware exists.
type BENCODeviceV2 struct {
	Box   BENCOKey
	Sign  BENCOKey
	Label string `oscar:"len_prefix=uint8"`
}

// BENCOManifest is the signed statement of who an account's devices are.
//
// This type exists to BUILD a manifest before signing it and to INSPECT one
// after verifying it. It is never how a manifest travels. The bytes that were
// signed are what gets sent, stored and returned, and re-encoding a received
// manifest through this struct would break its signature the moment the
// encoder's output differed by a byte — a failure that looks like a crypto bug
// and is really an encoding one. See the Manifest field on the publish request.
//
// ScreenName is inside the signature deliberately: without it, a manifest
// lifted from one account could be replayed onto another and still verify.
//
// Counter and IssuedAt do different jobs and only one is authoritative. Counter
// orders manifests and is the rollback defence — it is the only field that may
// be used to reject a manifest as stale, it is monotonic within an identity,
// and 0 is reserved so that "no manifest" and "the first manifest" stay
// distinguishable. IssuedAt is advisory: it bounds how old a served manifest
// can plausibly be and gives a UI something to show, but a client must never
// reject on timestamp alone. A wrong clock is far likelier than an attack, and
// hard-rejecting on time would brick a conversation over a dead CMOS battery.
// Always UTC seconds, never local time, never a formatted string.
type BENCOManifest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	Counter    uint64
	IssuedAt   uint64
	Identity   BENCOKey
	Devices    []BENCODeviceV2 `oscar:"count_prefix=uint16"`
}

// EncodeManifest serialises a manifest to the bytes that get signed and sent.
//
// This lives here rather than in the signing code so that there is exactly one
// encoder, and so the layer that signs never has an opportunity to produce a
// second encoding of the same manifest. The output of this function is the
// message; the struct that went in is only how it was described.
func EncodeManifest(m BENCOManifest) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := MarshalBE(m, buf); err != nil {
		return nil, fmt.Errorf("wire: encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeManifest parses manifest bytes for inspection.
//
// Callers must verify the signature over the bytes AS RECEIVED before calling
// this, and must never re-encode the result and treat that as the signed
// message — the round trip is not guaranteed to be byte-identical, and any
// difference silently invalidates the signature.
func DecodeManifest(b []byte) (BENCOManifest, error) {
	var m BENCOManifest
	if err := UnmarshalBE(&m, bytes.NewReader(b)); err != nil {
		return m, fmt.Errorf("wire: decode manifest: %w", err)
	}
	return m, nil
}

// SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest publishes this account's signed
// device manifest, replacing whatever was stored.
//
// Manifest is an encoded BENCOManifest and is OPAQUE BYTES to everything that
// is not verifying it. The client encodes it once, signs it, and sends exactly
// those bytes; the server stores and returns exactly those bytes.
//
// Signature is detached and covers Manifest exactly as sent, made by the
// private half of the Identity key inside it. That the identity vouches for
// itself is not circular: it proves who ISSUED the manifest, and whether to
// trust that identity is a separate question answered by the client's own trust
// store.
//
// There is no screen name field. The server takes it from the session and
// compares it against the one inside the manifest, so a client can only publish
// for itself — and putting it out here, unsigned, would defeat the point.
type SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest struct {
	Version   uint16
	Manifest  []byte `oscar:"len_prefix=uint16"`
	SigAlg    uint8
	Signature []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply reports what the server now holds.
//
// Counter is the stored counter after the call, which is what makes a lost race
// detectable: a publish rejected as stale tells the client the value it needs
// to beat, instead of forcing a re-query to find out.
type SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply struct {
	Accepted uint8 // 1 = stored
	Counter  uint64
}

// SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest asks for an account's manifest.
//
// Answered from storage, so unlike the profile it replaced it works for a user
// who is offline and for our own screen name.
type SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply carries an account's signed manifest.
//
// Present is 0 for an account that has published nothing. That is a normal
// answer, not an error: "this user has not bootstrapped an identity" is a state
// a client must handle anyway.
//
// Manifest is byte-for-byte what was published, and must be verified as
// received before being decoded.
type SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Present    uint8
	Manifest   []byte `oscar:"len_prefix=uint16"`
	SigAlg     uint8
	Signature  []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest stores this account's
// encrypted identity key.
//
// The identity private key signs manifests and is held only transiently by a
// client — fetched, used, discarded — so it has to live somewhere between uses.
// It lives here, encrypted under a key derived from a recovery phrase the
// server never sees and cannot derive.
//
// KDF, Params and Salt travel with the blob so the work factor can be raised
// later without stranding backups made under the old one.
//
// Scoped to the sending account: the screen name comes from the session.
type SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest struct {
	Version uint16
	KDF     uint8  // BENCOKDFArgon2id
	Params  []byte `oscar:"len_prefix=uint16"` // time, memory, parallelism
	Salt    []byte `oscar:"len_prefix=uint16"`
	Blob    []byte `oscar:"len_prefix=uint16"` // secretbox(identity private key)
}

// SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply acknowledges a stored backup.
type SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply struct {
	Stored uint8 // 1 = stored
}

// SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest fetches the SENDING account's
// encrypted identity key.
//
// There is no screen name field, and that is a security boundary rather than a
// convenience. The blob is encrypted but attackable offline with no rate
// limiting once someone holds it, so serving one account's backup to another
// would reduce a takeover to an unhurried dictionary attack.
type SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest struct {
	Version uint16
}

// SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply carries the encrypted identity
// key, if one has been stored.
//
// Present = 0 means the account has never bootstrapped an identity, and it is
// what tells a client which first-run flow it is in: no backup means generate
// an identity and show a recovery phrase, a backup means prompt for the phrase
// to link this device.
type SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply struct {
	Present uint8
	KDF     uint8
	Params  []byte `oscar:"len_prefix=uint16"`
	Salt    []byte `oscar:"len_prefix=uint16"`
	Blob    []byte `oscar:"len_prefix=uint16"`
}
