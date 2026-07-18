// Package roomkeys persists the group keys for encrypted chat rooms, per
// account, on this machine only.
//
// Two things are stored, and the second matters as much as the first:
//
//   - the keys themselves, so a restart doesn't lock the user out of their own
//     rooms;
//   - the fact that a room IS encrypted, independent of whether we currently
//     hold a key for it.
//
// Without that second record, "no key" and "not an encrypted room" are
// indistinguishable, and the client silently sends plaintext into a room the
// user believes is private. Keeping the marker lets a missing key fail closed.
package roomkeys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/benco-holdings/benchat/internal/state"
)

// Room is what we remember about one encrypted room.
type Room struct {
	// Name is the room's OSCAR name, needed to rejoin it.
	Name string `json:"name"`
	// Keys maps key ID to base64 key. Retired keys are kept so scrollback from
	// before a rotation still opens.
	Keys map[string]string `json:"keys"`
	// CurrentID is the key new messages are sealed with. Empty means the room is
	// known to be encrypted but we hold no usable key — sending must refuse.
	CurrentID string `json:"currentId"`
	// Members are the people we deliberately gave the key to, so a rotation
	// redistributes to exactly them and not to whoever wandered in.
	Members []string `json:"members,omitempty"`
	// Updated is when this room was last touched.
	Updated time.Time `json:"updated"`
}

// Store maps a room cookie to what we know about it.
type Store map[string]Room

type fileFormat struct {
	Version int   `json:"version"`
	Rooms   Store `json:"rooms"`
}

const currentVersion = 1

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

func path(account string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, "BENCchat", "rooms")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(d, safeName(account)+".json"), nil
}

// Load reads an account's encrypted rooms. A missing file is the first-run case
// and returns an empty (non-nil) store, not an error.
func Load(account string) (Store, error) {
	p, err := path(account)
	if err != nil {
		return Store{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Store{}, nil
		}
		return Store{}, err
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return Store{}, fmt.Errorf("roomkeys: parse %s: %w", p, err)
	}
	if f.Rooms == nil {
		f.Rooms = Store{}
	}
	return f.Rooms, nil
}

// Save writes an account's encrypted rooms atomically. The file holds live
// message keys, so it is written 0600 under a 0700 directory.
func Save(account string, s Store) error {
	p, err := path(account)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(fileFormat{Version: currentVersion, Rooms: s}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Forget drops one room, e.g. when the user leaves it for good.
func Forget(account, cookie string) error {
	s, err := Load(account)
	if err != nil {
		return err
	}
	delete(s, cookie)
	return Save(account, s)
}
