// Package roomkeys persists the key material for encrypted chat rooms, per
// account, on this machine only.
//
// Three things are stored, and the third matters as much as the first two:
//
//   - our own outbound CHAIN for each room, so a restart resumes sealing where
//     it left off rather than starting over — restarting at an earlier position
//     would reuse message keys, which is the one thing a chain must never do;
//   - the sender chains we can READ, so scrollback and catch-up still open;
//   - the fact that a room IS encrypted, independent of whether we currently
//     hold anything usable for it.
//
// Without that last record, "no key" and "not an encrypted room" are
// indistinguishable, and the client silently sends plaintext into a room the
// user believes is private. Keeping the marker lets a missing key fail closed.
//
// The file is encrypted at rest under a key in the OS keyring. It holds live
// message keys — a plaintext copy is worth the whole history of every room the
// account is in — and it fails closed: no key means no save, never a save in the
// clear.
package roomkeys

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/benco-holdings/benchat/internal/state"
)

// Room is what we remember about one encrypted room.
type Room struct {
	// Name is the room's OSCAR name, needed to rejoin it.
	Name string `json:"name"`
	// Out is our own outbound chain, encoded. Empty before we have sent
	// anything, which is a normal state for a room we have only listened to.
	Out string `json:"out,omitempty"`
	// Views are the sender chains we can read, by chain ID. Each is stored at
	// the EARLIEST position we are entitled to, which is what makes scrollback
	// work; winding one forward is a deliberate act, not something a save does.
	Views map[string]string `json:"views,omitempty"`
	// Seen is the highest position observed on each chain.
	//
	// Kept separately from Views because they answer different questions: a view
	// says how far back we may read, and this says where the conversation has
	// got to. Handing a newcomer a bundle needs the second — a view wound
	// forward to "now" — and deriving it from the first would hand over the
	// whole history instead.
	Seen map[string]uint32 `json:"seen,omitempty"`
	// Members are the people we deliberately gave keys to, so a rotation
	// redistributes to exactly them and not to whoever wandered in.
	Members []string `json:"members,omitempty"`
	// JoinedAt is when we first entered this room.
	//
	// It bounds catch-up. Everything before it was sealed at chain positions we
	// cannot derive, so asking for it returns a screenful of messages that only
	// say "sent before you joined" — the ratchet working correctly, rendered as
	// though something had gone wrong.
	JoinedAt time.Time `json:"joinedAt,omitempty"`
	// Updated is when this room was last touched.
	Updated time.Time `json:"updated"`
}

// Store maps a room cookie to what we know about it.
type Store map[string]Room

type fileFormat struct {
	Version int   `json:"version"`
	Rooms   Store `json:"rooms"`
}

const currentVersion = 2

// sealedMagic prefixes an encrypted room file.
const sealedMagic = "BENCROOM1"

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

// NewKey mints a room-file encryption key.
func NewKey() (*[32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return nil, fmt.Errorf("roomkeys: key: %w", err)
	}
	return &k, nil
}

// Load reads an account's encrypted rooms. A missing file is the first-run case
// and returns an empty (non-nil) store, not an error.
func Load(account string, key *[32]byte) (Store, error) {
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

	if sealed, ok := parseSealed(raw); ok {
		if key == nil {
			return Store{}, errors.New("roomkeys: file is encrypted but no key is available")
		}
		var nonce [24]byte
		copy(nonce[:], sealed[:24])
		plain, opened := secretbox.Open(nil, sealed[24:], &nonce, key)
		if !opened {
			// Refusing is the only safe answer: returning empty would look like
			// "no rooms yet", and the next save would overwrite real keys with
			// nothing — locking the account out of every room it is in.
			return Store{}, fmt.Errorf("roomkeys: could not decrypt %s (wrong key or corrupt file)", p)
		}
		raw = plain
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

// Save writes an account's encrypted rooms atomically.
//
// A nil key is a programming error rather than a licence to write plaintext.
// This file holds live message keys; a copy in the clear is worth every room the
// account is in. Callers that cannot obtain a key must not persist.
func Save(account string, s Store, key *[32]byte) error {
	if key == nil {
		return errors.New("roomkeys: refusing to save without an encryption key")
	}
	p, err := path(account)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(fileFormat{Version: currentVersion, Rooms: s})
	if err != nil {
		return err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("roomkeys: nonce: %w", err)
	}
	out := append([]byte(sealedMagic), nonce[:]...)
	out = secretbox.Seal(out, raw, &nonce, key)

	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// parseSealed returns the nonce+ciphertext body if raw is a sealed file.
func parseSealed(raw []byte) ([]byte, bool) {
	if len(raw) < len(sealedMagic)+24+secretbox.Overhead {
		return nil, false
	}
	if string(raw[:len(sealedMagic)]) != sealedMagic {
		return nil, false
	}
	return raw[len(sealedMagic):], true
}

// Forget drops one room, e.g. when the user leaves it for good.
func Forget(account, cookie string, key *[32]byte) error {
	s, err := Load(account, key)
	if err != nil {
		return err
	}
	delete(s, cookie)
	return Save(account, s, key)
}
