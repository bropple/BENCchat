// Package trust persists which peer E2EE keys a signed-on account has manually
// verified (by comparing safety numbers out of band). It closes the gap in
// trust-on-first-use key discovery: once a user confirms a peer's key, we
// remember it and can warn if that key ever changes underneath them.
//
// Like history, this is LOCAL and per-account: nothing is sent to the server,
// and two screen names on one machine never share verification state. The stored
// value is the verified public key itself (base64), so a later key change is
// detectable — not just a "verified" flag that a swapped key would inherit.
package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/benco-holdings/benchat/internal/state"
)

// Entry is what we remember about one peer's key.
//
// Verified is the key the user confirmed out of band by comparing safety
// numbers; empty means they never did. Seen is the most recent key we observed
// for them, recorded automatically. Keeping both means a key swap is detectable
// even for a peer the user never verified — which is the majority case, and the
// one where a silent substitution would otherwise go entirely unannounced.
type Entry struct {
	Verified string `json:"verified,omitempty"`
	Seen     string `json:"seen,omitempty"`
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

// File is an account's whole trust record: what we know about peers, plus the
// set of our own devices.
type File struct {
	Peers Store
	// Devices is every device key we know this account has published, base64,
	// including ones that are currently offline.
	//
	// It has to be remembered locally because open-oscar-server keeps a BUCP
	// client's profile on the live session and discards it at sign-off: an
	// offline machine's key is simply not in the published set for us to merge.
	// Without this, signing in on a laptop while the desktop is off would drop
	// the desktop's key, and messages sent meanwhile would be unreadable there.
	Devices []string
}

// fileFormat is the versioned on-disk envelope.
type fileFormat struct {
	Version int      `json:"version"`
	Peers   Store    `json:"peers"`
	Devices []string `json:"devices,omitempty"`
}

const currentVersion = 1

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
	return File{Peers: f.Peers, Devices: f.Devices}, nil
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
		Devices: file.Devices,
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

// Save writes an account's peer trust entries, preserving the device list.
func Save(account string, s Store) error {
	existing, err := LoadFile(account)
	if err != nil {
		// A parse failure shouldn't block saving peer trust; start the device
		// list over rather than refusing to persist a verification.
		existing = File{}
	}
	existing.Peers = s
	return SaveFile(account, existing)
}

// LoadDevices returns the account's remembered device key set.
func LoadDevices(account string) ([]string, error) {
	f, err := LoadFile(account)
	return f.Devices, err
}

// SaveDevices records the account's device key set, preserving peer trust.
func SaveDevices(account string, devices []string) error {
	existing, err := LoadFile(account)
	if err != nil {
		existing = File{}
	}
	existing.Devices = devices
	return SaveFile(account, existing)
}
