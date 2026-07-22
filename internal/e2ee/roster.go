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
const RosterPrefix = "\x1bBENCO-ROSTER:v2:"

// legacyRosterPrefix is v1, which could not state who a roster REMOVED — a
// recipient inferred that from its own member list, and a list that never named
// the removed person produced a removal nobody rotated for. Still recognized by
// IsRoster so a stray v1 body is intercepted as protocol traffic rather than
// rendered as chat, but DecodeRoster refuses it: acting on a v1 roster would
// reopen exactly the gap v2 closes.
const legacyRosterPrefix = "\x1bBENCO-ROSTER:v1:"

// rosterDomain separates a roster signature from every other thing a device
// signing key signs — including a v1 roster, whose signature must not verify as
// a v2 one. Length-prefixed fields throughout, for the reason recorded in
// roomsign.go: a delimiter only delimits if it cannot occur in what it
// separates, and nothing enforces that for a room name or a screen name.
const rosterDomain = "BENCO-ROSTER-v2"

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
	// Removed is everyone the owner has taken out of the room, by name, and it
	// is the statement a recipient ROTATES on. Only meaningful when the author
	// is the owner; anybody else's is ignored.
	//
	// It exists because omission cannot carry the message. Members replaces the
	// recipient's list, but a recipient who never learned somebody existed —
	// because the roster announcing them failed to arrive — sees no shrink when
	// they are removed, and that recipient may hold exactly the chains the
	// removed person can read. Naming the removed makes the trigger part of the
	// signed statement instead of a diff against whatever each recipient
	// happened to know.
	//
	// The full tombstone set, not a delta, for the same reason Members is: it
	// makes applying one idempotent, and a member who missed the removal roster
	// itself still learns of it from any later one.
	Removed []string
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

	out = appendNameList(out, r.Members)
	out = appendNameList(out, r.Removed)
	return out
}

// appendNameList appends a counted, length-prefixed list of names. The count is
// always present — even for an empty list — so the Members and Removed lists
// can never be misread as one another's tail.
func appendNameList(out []byte, names []string) []byte {
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(names)))
	out = append(out, count[:]...)
	for _, n := range names {
		out = appendLenPrefixed(out, n)
	}
	return out
}

// SignRoster produces a signed roster ready to send.
func SignRoster(r Roster, kp SigningKeyPair) (Roster, error) {
	if err := checkRosterBounds(r); err != nil {
		return Roster{}, err
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

// checkRosterBounds refuses a roster either list of which is implausibly large,
// so a malformed count can never make us allocate — or sign — without limit.
func checkRosterBounds(r Roster) error {
	if len(r.Members) > maxRosterMembers {
		return fmt.Errorf("e2ee: roster has %d members, limit is %d", len(r.Members), maxRosterMembers)
	}
	if len(r.Removed) > maxRosterMembers {
		return fmt.Errorf("e2ee: roster removes %d names, limit is %d", len(r.Removed), maxRosterMembers)
	}
	return nil
}

// IsRoster reports whether a body is a signed roster. Machine-to-machine, and
// must never be shown as chat text.
func IsRoster(body string) bool {
	return strings.HasPrefix(body, RosterPrefix) || strings.HasPrefix(body, legacyRosterPrefix)
}

// EncodeRoster renders a roster for the wire.
func EncodeRoster(r Roster) (string, error) {
	if err := checkRosterBounds(r); err != nil {
		return "", err
	}
	buf := make([]byte, 0, 128)
	buf = appendLenPrefixed(buf, r.Room)
	buf = appendLenPrefixed(buf, r.Owner)
	buf = appendLenPrefixed(buf, r.Author)
	buf = appendLenPrefixed(buf, r.SignerID)

	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], r.Epoch)
	buf = append(buf, epoch[:]...)

	buf = appendNameList(buf, r.Members)
	buf = appendNameList(buf, r.Removed)
	buf = appendLenPrefixed(buf, string(r.Signature))
	return RosterPrefix + base64.StdEncoding.EncodeToString(buf), nil
}

// DecodeRoster parses one.
func DecodeRoster(body string) (Roster, error) {
	var r Roster
	if strings.HasPrefix(body, legacyRosterPrefix) {
		return r, errors.New("e2ee: v1 roster; it cannot state removals and is no longer accepted")
	}
	if !strings.HasPrefix(body, RosterPrefix) {
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
	if len(raw) < 8 {
		return Roster{}, errors.New("e2ee: truncated roster")
	}
	r.Epoch = binary.BigEndian.Uint64(raw[:8])
	raw = raw[8:]

	takeList := func(what string) ([]string, error) {
		if len(raw) < 4 {
			return nil, fmt.Errorf("e2ee: truncated roster %s", what)
		}
		count := binary.BigEndian.Uint32(raw[:4])
		raw = raw[4:]
		if count > maxRosterMembers {
			return nil, fmt.Errorf("e2ee: roster claims %d %s, limit is %d", count, what, maxRosterMembers)
		}
		var names []string
		for i := uint32(0); i < count; i++ {
			n, got := take()
			if !got {
				return nil, fmt.Errorf("e2ee: truncated roster %s", what)
			}
			names = append(names, n)
		}
		return names, nil
	}
	if r.Members, err = takeList("members"); err != nil {
		return Roster{}, err
	}
	if r.Removed, err = takeList("removals"); err != nil {
		return Roster{}, err
	}
	sig, got := take()
	if !got {
		return Roster{}, errors.New("e2ee: truncated roster signature")
	}
	r.Signature = []byte(sig)
	return r, nil
}
