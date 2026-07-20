// Package trust persists what a signed-on account believes about its peers'
// keys, and about its own account identity.
//
// It does two jobs. The first is the original one: remembering which peer keys
// the user confirmed out of band by comparing safety numbers, so that a later
// change is detectable. The stored value is the key itself rather than a
// "verified" flag, because a flag would be inherited by whatever key was
// swapped in underneath it.
//
// The second arrived with key directory v2 and is a security control rather
// than a convenience: this is where the manifest counter high-water marks live.
// A signed manifest cannot be forged, but an old one can be REPLAYED — and the
// only thing standing between a hostile or rolled-back server and a resurrected
// device is a client remembering the highest counter it has already accepted
// from that identity (proposal §3, §6). Lose this file and that defence resets
// to trust-on-first-use.
//
// Like history, this is LOCAL and per-account: nothing is sent to the server,
// and two screen names on one machine never share verification state.
package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/benco-holdings/benchat/internal/state"
)

// Identity is an account identity key we have pinned, and how far its manifests
// have counted.
//
// Key and Counter belong together and must never be updated separately. The
// rollback defence in proposal §6 is a high-water mark scoped to an IDENTITY:
// a manifest signed by the identity we already pinned may not carry a counter
// at or below Counter, but a manifest signed by a DIFFERENT identity starts its
// own sequence at whatever value it likes. Storing the counter on its own would
// make a freshly bootstrapped account (which restarts at 1) look like a
// rollback, and re-pinning without resetting the counter would carry one
// identity's high-water mark onto another's numbering.
type Identity struct {
	// Key is the Ed25519 account identity public key, base64.
	Key string `json:"key,omitempty"`
	// Counter is the highest manifest counter accepted under Key.
	Counter uint64 `json:"counter,omitempty"`
	// Digest is the SHA-256 of the manifest bytes accepted at Counter, hex.
	//
	// It is here so that re-seeing the CURRENT manifest is distinguishable from
	// a rollback. The high-water mark is the counter of the manifest we
	// accepted, so on the next sign-on the directory legitimately returns that
	// same counter — and a rule of "reject counter <= stored" refuses it,
	// silently learning no keys and leaving every conversation unencrypted with
	// nothing reported. Equality alone is not safe either: two DIFFERENT
	// manifests at one counter is a fork, which a well-behaved publisher never
	// produces. Comparing the digest separates the two.
	Digest string `json:"digest,omitempty"`
}

// Entry is what we remember about one peer.
//
// Verified is what the user confirmed out of band by comparing safety numbers;
// empty means they never did. Since key directory v2 that value is the peer's
// account IDENTITY key, not a device key set — the identity is what a safety
// number is now derived from, and it is stable across the peer adding and
// removing machines. A record written by an older BENCchat holds a device key
// set here, which can never equal an identity key, so such a peer shows as
// "changed" once and is re-verified. That is expected: proposal §8 says safety
// numbers move exactly once, when everyone re-bootstraps onto v2.
//
// Seen is the peer's most recently observed DEVICE key set, recorded
// automatically. It is not a trust anchor any more — Identity is — but it is
// what distinguishes "they added a machine" from "their keys were replaced"
// for the informational notice.
type Entry struct {
	Verified string `json:"verified,omitempty"`
	Seen     string `json:"seen,omitempty"`
	// Identity is the account identity key pinned for this peer, and its
	// counter high-water mark.
	Identity Identity `json:"identity,omitempty"`
}

// UnmarshalJSON accepts the original on-disk shape, where each peer mapped to a
// bare verified-key string. Such a key was both verified and last-seen, so it
// migrates to an Entry with the value in both fields.
func (e *Entry) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		e.Verified, e.Seen = s, s
		return nil
	}
	type plain Entry // avoid recursing into this method
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*e = Entry(p)
	return nil
}

// Store maps a normalized peer screen name to what we know about their key.
type Store map[string]Entry

// File is an account's whole trust record: what we know about peers, plus our
// own account identity.
//
// The locally remembered device list that used to live here is gone with key
// directory v1. It existed because the profile the server served only listed
// devices that were signed on, so an offline machine had to be remembered or it
// would be dropped from the published set. A v2 manifest is answered from server
// storage and signed as a whole, so it already names every device including the
// ones that are switched off — and merging a local memory into it would
// republish devices another machine deliberately removed.
type File struct {
	Peers Store
	// Self is this account's own identity pin: the identity key this device
	// believes the account has, and the highest counter it has seen from it.
	//
	// It is kept apart from Peers rather than filed under our own screen name
	// because it answers a different question. A peer's pin decides whether to
	// believe their device list; ours decides whether THIS DEVICE is still part
	// of the account at all (proposal §6) — an identity here that we do not
	// recognise means the account was re-bootstrapped without us.
	Self Identity
}

// fileFormat is the versioned on-disk envelope.
type fileFormat struct {
	Version int      `json:"version"`
	Peers   Store    `json:"peers"`
	Self    Identity `json:"self,omitempty"`
}

// currentVersion 3 dropped the device list and added identity pins. A version 2
// file still loads: its peer entries survive (their Verified value is a device
// key set, which v2 treats as a stale verification — see Entry), and the device
// fields are simply not read.
const currentVersion = 3

// safeName turns an account into a filesystem-safe file stem, matching the
// history package's convention so both stores name files the same way.
func safeName(account string) string {
	n := state.NormalizeScreenName(account)
	out := make([]rune, 0, len(n))
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "account"
	}
	return string(out)
}

// path returns the trust file for an account, creating the parent directory.
func path(account string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	trustDir := filepath.Join(dir, "BENCchat", "trust")
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(trustDir, safeName(account)+".json"), nil
}

// LoadFile reads an account's whole trust record. A missing file is the
// first-run case and returns an empty record, not an error.
func LoadFile(account string) (File, error) {
	p, err := path(account)
	if err != nil {
		return File{Peers: Store{}}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return File{Peers: Store{}}, nil
		}
		return File{Peers: Store{}}, err
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return File{Peers: Store{}}, fmt.Errorf("trust: parse %s: %w", p, err)
	}
	if f.Peers == nil {
		f.Peers = Store{}
	}
	return File{Peers: f.Peers, Self: f.Self}, nil
}

// SaveFile writes an account's trust record atomically (temp file then rename).
func SaveFile(account string, file File) error {
	p, err := path(account)
	if err != nil {
		return err
	}
	if file.Peers == nil {
		file.Peers = Store{}
	}
	raw, err := json.MarshalIndent(fileFormat{
		Version: currentVersion,
		Peers:   file.Peers,
		Self:    file.Self,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Load reads an account's peer trust entries.
func Load(account string) (Store, error) {
	f, err := LoadFile(account)
	return f.Peers, err
}

// Save writes an account's peer trust entries, preserving the identity pin.
func Save(account string, s Store) error {
	existing, err := LoadFile(account)
	if err != nil {
		// A parse failure shouldn't block saving peer trust.
		existing = File{}
	}
	existing.Peers = s
	return SaveFile(account, existing)
}

// LoadSelfIdentity returns this account's own identity pin.
//
// An empty Key means this device has never seen a manifest for its own account
// — a first run, or a device that has not been linked yet. It is NOT the same
// as the account having no identity, which only GetIdentityBackup can answer.
func LoadSelfIdentity(account string) (Identity, error) {
	f, err := LoadFile(account)
	return f.Self, err
}

// SaveSelfIdentity records this account's identity pin, preserving peer trust.
//
// Key and Counter are written together on purpose; see Identity.
func SaveSelfIdentity(account string, id Identity) error {
	existing, err := LoadFile(account)
	if err != nil {
		existing = File{}
	}
	existing.Self = id
	return SaveFile(account, existing)
}
