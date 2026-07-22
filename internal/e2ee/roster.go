package e2ee

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Signed room rosters.
//
// Removal used to work by accident. Under a shared room key the rotation message
// CARRIED the new key, and holding new key material was taken as proof of
// authority — so a roster arriving with a key replaced the recipient's member
// list, and a roster arriving without one merely added to it. When chains
// replaced the key, the proof went with it and nothing took its place: the
// removal path sent a shrunken roster with no key material, recipients unioned
// it back to full size, and everybody except the person who clicked Remove
// carried on sending on chains the removed member still held.
//
// The accident was also a hole. "I have new key material" is not the same claim
// as "I am telling the truth about who is in this room", and conflating them
// meant ANY member's rotation could rewrite anyone's roster.
//
// So the authority is explicit now: a roster is signed, carries an epoch that
// only moves forward, and — for REMOVALS — must come from the room's owner.
// Additions stay open to any member, because adding is self-limiting: you can
// only add somebody you can already reach, and they would learn the room name
// anyway. Removal is the operation worth gating, because a flat model where any
// member may evict any other is not a security control, it is a griefing
// surface.

// RosterPrefix marks a signed roster. ESC-prefixed base64 like every other
// in-band room payload, so the server's HTML tokenizer and its "^//roll" match
// cannot mistake it for markup or a command.
const RosterPrefix = "\x1bBENCO-ROSTER:v1:"

// rosterDomain separates a roster signature from every other thing a device
// signing key signs. Length-prefixed fields throughout, for the reason recorded
// in roomsign.go: a delimiter only delimits if it cannot occur in what it
// separates, and nothing enforces that for a room name or a screen name.
const rosterDomain = "BENCO-ROSTER-v1"

// maxRosterMembers bounds a roster. Generous against any plausible room, and
// present so a malformed length cannot make us allocate without limit.
const maxRosterMembers = 1024

// ErrRosterSignature means a roster did not verify against the claimed author's
// keys.
var ErrRosterSignature = errors.New("e2ee: roster signature does not verify")

// Roster is a signed statement about who is in a room.
type Roster struct {
	Room string
	// Epoch only ever increases. It is the replay defence, and it is the same
	// shape as the manifest counter high-water mark in internal/trust — the
	// resemblance is deliberate, so a reader recognises what it is for.
	Epoch uint64
	// Members is the complete list, not a delta. A complete list is what makes
	// a removal expressible at all: a delta of "remove X" is indistinguishable
	// from a delta somebody dropped.
	Members []string
	// Owner is the room's owner, and it is signed like everything else. A
	// recipient pins it the first time it sees the room and requires every later
	// roster to name the same person — which makes handing ownership on an act
	// the current owner has to sign, rather than something anyone can assert.
	Owner string
	// Author is who signed it. Checked against the signature, and separately
	// against the room's owner when the roster shrinks.
	Author string
	// SignerID names the device key, so a recipient can pick the right one out
	// of the author's published set rather than trying all of them.
	SignerID  string
	Signature []byte
}

// rosterSigningContext is what actually gets signed.
func rosterSigningContext(r Roster) []byte {
	out := make([]byte, 0, 64+len(r.Room)+len(r.Author))
	out = append(out, rosterDomain...)
	out = append(out, 0x00)
	out = appendLenPrefixed(out, r.Room)
	out = appendLenPrefixed(out, r.Owner)
	out = appendLenPrefixed(out, r.Author)

	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], r.Epoch)
	out = append(out, epoch[:]...)

	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(r.Members)))
	out = append(out, count[:]...)
	for _, m := range r.Members {
		out = appendLenPrefixed(out, m)
	}
	return out
}

// SignRoster produces a signed roster ready to send.
func SignRoster(r Roster, kp SigningKeyPair) (Roster, error) {
	if len(r.Members) > maxRosterMembers {
		return Roster{}, fmt.Errorf("e2ee: roster has %d members, limit is %d", len(r.Members), maxRosterMembers)
	}
	r.SignerID = SignerID(kp.Public)
	r.Signature = ed25519.Sign(kp.Private, rosterSigningContext(r))
	return r, nil
}

// VerifyRoster checks a roster against the signing keys its claimed author
// publishes.
//
// An empty key set is "we have not learned their keys yet", which is not the
// same as a bad signature and must not be treated as one — the caller retries
// once the keys arrive rather than acting on a roster it could not check.
func VerifyRoster(r Roster, authorKeys []ed25519.PublicKey) error {
	if len(authorKeys) == 0 {
		return ErrRosterSignature
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return ErrRosterSignature
	}
	ctx := rosterSigningContext(r)
	for _, k := range authorKeys {
		if SignerID(k) != r.SignerID {
			continue
		}
		if ed25519.Verify(k, ctx, r.Signature) {
			return nil
		}
	}
	return ErrRosterSignature
}

// IsRoster reports whether a body is a signed roster. Machine-to-machine, and
// must never be shown as chat text.
func IsRoster(body string) bool { return strings.HasPrefix(body, RosterPrefix) }

// EncodeRoster renders a roster for the wire.
func EncodeRoster(r Roster) (string, error) {
	if len(r.Members) > maxRosterMembers {
		return "", fmt.Errorf("e2ee: roster has %d members, limit is %d", len(r.Members), maxRosterMembers)
	}
	buf := make([]byte, 0, 128)
	buf = appendLenPrefixed(buf, r.Room)
	buf = appendLenPrefixed(buf, r.Owner)
	buf = appendLenPrefixed(buf, r.Author)
	buf = appendLenPrefixed(buf, r.SignerID)

	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], r.Epoch)
	buf = append(buf, epoch[:]...)

	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(r.Members)))
	buf = append(buf, count[:]...)
	for _, m := range r.Members {
		buf = appendLenPrefixed(buf, m)
	}
	buf = appendLenPrefixed(buf, string(r.Signature))
	return RosterPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

// DecodeRoster parses one.
func DecodeRoster(body string) (Roster, error) {
	var r Roster
	if !IsRoster(body) {
		return r, errors.New("e2ee: not a roster")
	}
	raw, err := base64.StdEncoding.DecodeString(body[len(RosterPrefix):])
	if err != nil {
		return r, fmt.Errorf("e2ee: decode roster: %w", err)
	}

	take := func() (string, bool) {
		if len(raw) < 4 {
			return "", false
		}
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-4) {
			return "", false
		}
		s := string(raw[4 : 4+n])
		raw = raw[4+n:]
		return s, true
	}

	var ok bool
	if r.Room, ok = take(); !ok {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	if r.Owner, ok = take(); !ok {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	if r.Author, ok = take(); !ok {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	if r.SignerID, ok = take(); !ok {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	if len(raw) < 12 {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	r.Epoch = binary.BigEndian.Uint64(raw[:8])
	count := binary.BigEndian.Uint32(raw[8:12])
	raw = raw[12:]
	if count > maxRosterMembers {
		return Roster{}, fmt.Errorf("e2ee: roster claims %d members, limit is %d", count, maxRosterMembers)
	}
	for i := uint32(0); i < count; i++ {
		m, got := take()
		if !got {
			return Roster{}, errors.New("e2ee: truncated roster members")
		}
		r.Members = append(r.Members, m)
	}
	sig, got := take()
	if !got {
		return Roster{}, errors.New("e2ee: truncated roster signature")
	}
	r.Signature = []byte(sig)
	return r, nil
}
