// Package history persists a signed-on account's conversation scrollback to
// local disk, so BENCchat keeps message history across restarts the way an AIM
// client with logging enabled did.
//
// It is deliberately LOCAL and single-device: nothing is sent to the server
// (OSCAR has no notion of stored history), and files are per-account so two
// screen names on one machine never share logs. The on-disk shape is the same
// state.Conversation the store already uses, keyed by conversation key — so a
// future group-chat room, which is just another conversation key, persists here
// without a format change.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/benco-holdings/benchat/internal/state"
)

// Data is an account's persisted scrollback: 1:1 conversations and chat-room
// history. Room participants are not persisted (they are live/ephemeral); only
// the messages and room identity survive a restart, for re-join.
type Data struct {
	Conversations []state.Conversation `json:"conversations"`
	Rooms         []state.Room         `json:"rooms,omitempty"`
}

// fileFormat is the versioned on-disk envelope, so the schema can evolve without
// mistaking an old file for a new one.
type fileFormat struct {
	Version int `json:"version"`
	Data
}

const currentVersion = 2

// safeName turns an account into a filesystem-safe file stem. It normalizes the
// screen name (matching the store's conversation keys) and replaces anything
// outside a conservative charset, so an unusual screen name can't escape the
// history directory or collide with path syntax.
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

// path returns the history file for an account, creating the parent directory.
// It sits under the same app dir as config.json. 0700 keeps logs private to the
// user — these are personal messages.
func path(account string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	histDir := filepath.Join(dir, "BENCchat", "history")
	if err := os.MkdirAll(histDir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(histDir, safeName(account)+".json"), nil
}

// Load reads an account's persisted scrollback (conversations + rooms). A
// missing file is the first-run case and returns a zero Data, not an error.
func Load(account string) (Data, error) {
	p, err := path(account)
	if err != nil {
		return Data{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Data{}, nil
		}
		return Data{}, err
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return Data{}, fmt.Errorf("history: parse %s: %w", p, err)
	}
	return f.Data, nil
}

// Save writes an account's scrollback atomically (temp file then rename) so a
// crash mid-write can't corrupt an existing history.
func Save(account string, d Data) error {
	p, err := path(account)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(fileFormat{Version: currentVersion, Data: d}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Clear removes an account's history file. A missing file is not an error.
func Clear(account string) error {
	p, err := path(account)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Prune drops every message older than cutoff, and any conversation or room left
// empty, across both conversations and rooms. A zero cutoff means retention is
// disabled — d is returned unchanged. The input is not mutated.
func Prune(d Data, cutoff time.Time) Data {
	if cutoff.IsZero() {
		return d
	}
	return Data{
		Conversations: pruneConvs(d.Conversations, cutoff),
		Rooms:         pruneRooms(d.Rooms, cutoff),
	}
}

func pruneConvs(convs []state.Conversation, cutoff time.Time) []state.Conversation {
	out := make([]state.Conversation, 0, len(convs))
	for _, c := range convs {
		if c.Messages = keptAfter(c.Messages, cutoff); len(c.Messages) > 0 {
			out = append(out, c)
		}
	}
	return out
}

func pruneRooms(rooms []state.Room, cutoff time.Time) []state.Room {
	out := make([]state.Room, 0, len(rooms))
	for _, r := range rooms {
		if r.Messages = keptAfter(r.Messages, cutoff); len(r.Messages) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func keptAfter(msgs []state.Message, cutoff time.Time) []state.Message {
	kept := make([]state.Message, 0, len(msgs))
	for _, m := range msgs {
		if m.At.After(cutoff) {
			kept = append(kept, m)
		}
	}
	return kept
}
