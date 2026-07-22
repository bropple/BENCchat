package e2ee

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// Device-to-device transfer.
//
// A newly linked device arrives empty. It has an account, an identity, and a
// place in the manifest — and no history, and no room chains, so every encrypted
// room reads as ciphertext and every conversation starts blank. "Link a device"
// promises rather more than that.
//
// Nothing on the server can fix it, deliberately. Room chains are held only by
// the devices that hold them and history is stored only where it was received;
// the server has no copy of either, which is the property the whole design is
// for. So the only thing that can furnish a new device is an old one, directly.
//
// # What authenticates it
//
// The devices are already cross-signed. Both appear in the account's manifest,
// signed by the identity key, so "is this really my other device" is answerable
// from what is already on disk — no pairing ceremony to invent, no fingerprint
// to compare, no server to ask. A transfer is sealed to the recipient's box key
// AS PUBLISHED IN THE MANIFEST and signed by the sender's published signing key.
// A device that is not in the manifest cannot be a party to one in either
// direction.
//
// That is a stronger check than it first looks. Publishing a device requires
// signing a manifest with the account's identity key, which is held only
// transiently and unwrapped with the recovery key — so a device in the manifest
// is one somebody deliberately put there.
//
// # What is transferred, and what is deliberately not
//
// Chain VIEWS travel. The outbound chain does NOT, and this is the constraint
// that shapes the format: a chain is a position counter, and two devices sending
// on one would seal two different messages at the same position under the same
// key. The receiving device mints its own and broadcasts it like any other. So a
// transfer grants the ability to READ what others send, never the ability to
// speak as the device that sent it.
//
// # What it does not protect against
//
// A device you no longer control that is still in the manifest. Removal is the
// answer to that, and it is the answer everywhere else too.

// TransferPrefix marks a transfer bundle.
const TransferPrefix = "\x1bBENCO-XFER:v1:"

// transferDomain separates a transfer signature from everything else a device
// signing key signs. Length-prefixed fields throughout, for the reason recorded
// in roomsign.go.
const transferDomain = "BENCO-XFER-v1"

// maxTransferPayload bounds a bundle. History is the bulk of it and there is no
// useful ceiling on how much of that an account has, so this is generous — but
// it is present, because the length arrives from outside.
const maxTransferPayload = 64 * 1024 * 1024

// ErrTransferSignature means a bundle did not verify against the sender's
// published signing keys.
var ErrTransferSignature = errors.New("e2ee: transfer signature does not verify")

// ErrTransferNotForUs means a bundle was sealed to a different device.
var ErrTransferNotForUs = errors.New("e2ee: transfer is sealed to another device")

// Transfer is one device's furnishing of another.
type Transfer struct {
	// Account is the screen name both devices belong to. Signed, so a bundle
	// cannot be replayed into a different account's client.
	Account string
	// Recipient is the signing key ID of the device this is for. Signed as well
	// as sealed: sealing already makes it unreadable by anyone else, and naming
	// the recipient makes a misdirected bundle a clear refusal rather than a
	// decryption failure nobody can interpret.
	Recipient string
	// Payload is the sealed content — history and room chain views. Opaque here;
	// the app layer owns its shape.
	Payload []byte
	// IssuedAt is when the bundle was made, Unix seconds. Advisory.
	IssuedAt int64

	// SignerID names the sending device's signing key.
	SignerID  string
	Signature []byte
}

// transferSigningContext is what gets signed.
func transferSigningContext(t Transfer) []byte {
	out := make([]byte, 0, 64+len(t.Account)+len(t.Recipient)+len(t.Payload))
	out = append(out, transferDomain...)
	out = append(out, 0x00)
	out = appendLenPrefixed(out, t.Account)
	out = appendLenPrefixed(out, t.Recipient)

	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(t.Payload)))
	out = append(out, n[:]...)
	out = append(out, t.Payload...)

	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(t.IssuedAt))
	out = append(out, at[:]...)
	return out
}

// SealTransfer builds a bundle for one device, sealed to its box key and signed
// with ours.
//
// recipientBox and recipientID must both come from the account's VERIFIED
// manifest. Taking either from anywhere else — a hostname, a handshake, a code
// somebody typed — is what would turn this into a way to hand an account's
// history to whoever asked for it.
func SealTransfer(account, recipientID string, recipientBox [32]byte, payload []byte, ourPriv [32]byte, signer SigningKeyPair, issuedAt int64) (Transfer, error) {
	if len(payload) > maxTransferPayload {
		return Transfer{}, fmt.Errorf("e2ee: transfer payload is %d bytes, limit is %d", len(payload), maxTransferPayload)
	}
	if account == "" || recipientID == "" {
		return Transfer{}, errors.New("e2ee: a transfer must name an account and a recipient")
	}
	sealed, err := SealFor(string(payload), [][32]byte{recipientBox}, ourPriv)
	if err != nil {
		return Transfer{}, fmt.Errorf("e2ee: seal transfer: %w", err)
	}

	t := Transfer{
		Account:   account,
		Recipient: recipientID,
		Payload:   []byte(sealed),
		IssuedAt:  issuedAt,
		SignerID:  SignerID(signer.Public),
	}
	t.Signature = ed25519.Sign(signer.Private, transferSigningContext(t))
	return t, nil
}

// OpenTransfer verifies a bundle and returns its contents.
//
// senderKeys are the signing keys of the account's OTHER devices, from the
// verified manifest. ourID is this device's signing key ID, and ourPriv its box
// private key.
//
// An empty senderKeys set means "we have not verified the manifest yet", which
// is not the same as a bad signature and must not be treated as one — a caller
// that cannot check should refuse and retry, not accept.
func OpenTransfer(t Transfer, account, ourID string, senderKeys []ed25519.PublicKey, senderBoxes [][32]byte, ourPriv [32]byte) ([]byte, error) {
	if t.Account != account {
		return nil, fmt.Errorf("e2ee: transfer is for account %q, not %q", t.Account, account)
	}
	if t.Recipient != ourID {
		return nil, ErrTransferNotForUs
	}
	if len(senderKeys) == 0 || len(t.Signature) != ed25519.SignatureSize {
		return nil, ErrTransferSignature
	}

	ctx := transferSigningContext(t)
	var verified bool
	for _, k := range senderKeys {
		if SignerID(k) != t.SignerID {
			continue
		}
		if ed25519.Verify(k, ctx, t.Signature) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrTransferSignature
	}

	// The sender's box key is not labelled anywhere, so each candidate from the
	// manifest is tried. Only one can work: the signature above already fixed
	// WHICH device sent this, and a device that could open it with a different
	// key would be one whose box and signing keys disagree with the manifest.
	for _, box := range senderBoxes {
		if plain, err := OpenAny(string(t.Payload), box, ourPriv); err == nil {
			return []byte(plain.Text), nil
		}
	}
	// Signature verified but nothing opened it. Not a forgery — the sender is
	// who they claim to be — so the likely cause is a device set that has moved
	// on since the bundle was made.
	return nil, errors.New("e2ee: transfer could not be decrypted with this device's key")
}

// EncodeTransfer renders a bundle for the wire or for a file.
func EncodeTransfer(t Transfer) (string, error) {
	if len(t.Payload) > maxTransferPayload {
		return "", fmt.Errorf("e2ee: transfer payload is %d bytes, limit is %d", len(t.Payload), maxTransferPayload)
	}
	buf := make([]byte, 0, 128+len(t.Payload))
	buf = appendLenPrefixed(buf, t.Account)
	buf = appendLenPrefixed(buf, t.Recipient)
	buf = appendLenPrefixed(buf, t.SignerID)

	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(t.Payload)))
	buf = append(buf, n[:]...)
	buf = append(buf, t.Payload...)

	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(t.IssuedAt))
	buf = append(buf, at[:]...)

	buf = appendLenPrefixed(buf, string(t.Signature))
	return TransferPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

// IsTransfer reports whether a body is a transfer bundle.
func IsTransfer(body string) bool {
	return len(body) > len(TransferPrefix) && body[:len(TransferPrefix)] == TransferPrefix
}

// DecodeTransfer parses one.
func DecodeTransfer(body string) (Transfer, error) {
	var t Transfer
	if !IsTransfer(body) {
		return t, errors.New("e2ee: not a transfer bundle")
	}
	raw, err := base64.StdEncoding.DecodeString(body[len(TransferPrefix):])
	if err != nil {
		return t, fmt.Errorf("e2ee: decode transfer: %w", err)
	}

	take := func() ([]byte, bool) {
		if len(raw) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-4) {
			return nil, false
		}
		b := raw[4 : 4+n]
		raw = raw[4+n:]
		return b, true
	}

	account, ok := take()
	if !ok {
		return Transfer{}, errors.New("e2ee: truncated transfer")
	}
	recipient, ok := take()
	if !ok {
		return Transfer{}, errors.New("e2ee: truncated transfer")
	}
	signerID, ok := take()
	if !ok {
		return Transfer{}, errors.New("e2ee: truncated transfer")
	}
	payload, ok := take()
	if !ok {
		return Transfer{}, errors.New("e2ee: truncated transfer payload")
	}
	if len(raw) < 8 {
		return Transfer{}, errors.New("e2ee: truncated transfer")
	}
	t.IssuedAt = int64(binary.BigEndian.Uint64(raw[:8]))
	raw = raw[8:]
	sig, ok := take()
	if !ok {
		return Transfer{}, errors.New("e2ee: truncated transfer signature")
	}

	t.Account = string(account)
	t.Recipient = string(recipient)
	t.SignerID = string(signerID)
	t.Payload = payload
	t.Signature = sig
	return t, nil
}
