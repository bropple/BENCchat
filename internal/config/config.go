// Package config holds BENCchat's user-facing settings. The OSCAR server
// address is deliberately configurable rather than a compile-time constant, and
// is not stored in source control: which server an install talks to is a
// deployment detail, not a property of the client.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultAuthHost is deliberately EMPTY: the server address is a deployment
// detail, not something to bake into a published binary. A fresh install asks
// for it on the sign-on screen, and it is remembered from then on.
//
// A build can pre-fill it without putting the address in source control:
//
//	go build -ldflags "-X github.com/benco-holdings/benchat/internal/config.DefaultAuthHost=oscar.example.com"
var DefaultAuthHost = ""

// DefaultAuthPort is the port a BENCO server listens on, which is not
// sensitive. 5191 rather than OSCAR's traditional 5190: BENCoscar terminates
// TLS itself and runs no plaintext listener, so 5190 would only ever time out.
const DefaultAuthPort = 5191

// Config is the persisted client configuration.
type Config struct {
	// AuthHost / AuthPort address the authorizer — the first connection a
	// client makes. The server then hands back a BOS address to reconnect to,
	// so this is only the front door, not necessarily where messaging happens.
	AuthHost string `json:"authHost"`
	AuthPort int    `json:"authPort"`

	// LastScreenName is remembered to prefill the sign-on screen.
	LastScreenName string `json:"lastScreenName,omitempty"`

	// RememberedScreenName is the account to auto-login on launch, set when the
	// user signs on with "stay signed in" and cleared on explicit sign-off. The
	// password itself is NOT here — it lives in the OS secret store (see
	// internal/secret); this only records which account has one saved.
	RememberedScreenName string `json:"rememberedScreenName,omitempty"`

	// Theme is the user's chosen appearance. The set of themeable tokens and the
	// built-in presets live in the frontend; the backend only stores the choice,
	// so users (or a future sync feature) can hand-edit this in config.json.
	Theme Theme `json:"theme,omitempty"`

	// TLSEnabled connects over TLS. ON by default — a chat client should not
	// put your login handshake and buddy list on the wire in the clear because
	// you didn't find a checkbox. A pointer so an explicit false survives a
	// round trip: with omitempty a plain bool cannot distinguish "the user
	// turned this off" from "this config predates the setting", and those two
	// have to mean different things when the default is on.
	//
	// Read it through TLSOn(), never directly.
	TLSEnabled *bool `json:"tlsEnabled,omitempty"`

	// TLSInsecure skips certificate verification. For testing against a
	// self-signed development server ONLY — it removes exactly the protection
	// TLS provides, so the UI states this plainly wherever it is offered.
	TLSInsecure bool `json:"tlsInsecure,omitempty"`

	// SoundEnabled toggles the client-side sound effects (buddy sign-on, incoming
	// message). Defaults to on for the first run — the sounds are part of the
	// experience — but is honored once the user sets it either way.
	SoundEnabled *bool `json:"soundEnabled,omitempty"`

	// SoundPack is the chosen set of notification sounds (like Theme, but for
	// audio). Empty means the built-in default pack; the frontend owns the pack
	// definitions and only the name is persisted here.
	SoundPack string `json:"soundPack,omitempty"`

	// MutedSounds lists event keys (see the frontend's SOUND_EVENTS) silenced
	// individually, independent of the global SoundEnabled switch. Absent means
	// nothing is muted; the global switch still wins over any of these.
	MutedSounds []string `json:"mutedSounds,omitempty"`

	// HistoryEnabled toggles saving local chat history to disk. Defaults to on
	// (scrollback across restarts, like an AIM client with logging on). History
	// is local and per-account; nothing is sent to the server.
	HistoryEnabled *bool `json:"historyEnabled,omitempty"`

	// HistoryRetentionDays auto-deletes messages older than this many days the
	// next time history is loaded or saved. 0 (the default) keeps it forever.
	HistoryRetentionDays int `json:"historyRetentionDays,omitempty"`

	// E2EEEnabled turns on end-to-end encryption for 1:1 messages. ON by
	// default — encryption between BENCchat clients should be the normal case,
	// not something a user has to know to go and find. A nil pointer means
	// "never set", so an explicit false is still honored; messages to peers
	// with no published key fall back to plaintext either way.
	E2EEEnabled *bool `json:"e2eeEnabled,omitempty"`

	// Profile is the user's own profile/bio text. Persisted so the on-wire
	// profile (bio plus, when E2EE is on, a hidden public-key marker) can be
	// rebuilt without a round-trip.
	Profile string `json:"profile,omitempty"`

	// CustomFrame draws BENCchat's own titlebar (frameless window) instead of the
	// desktop environment's. Off by default — the DE normally handles window
	// decorations. Read at window-creation time, so a change needs a restart.
	CustomFrame bool `json:"customFrame,omitempty"`

	// SkinTone is the preferred emoji skin tone: 0 (or absent) = the neutral
	// yellow default, 1–5 = Fitzpatrick types 1-2…6. Applied to tone-capable
	// emoji in the picker; a per-emoji long-press can still override it.
	SkinTone int `json:"skinTone,omitempty"`
}

// Theme is a saved appearance: a preset name, plus any per-token overrides the
// user made in the editor. When Name is a built-in preset and Tokens is empty,
// the frontend renders that preset as-is; when the user customizes, Name becomes
// "custom" and Tokens holds the full overridden set.
type Theme struct {
	Name   string            `json:"name,omitempty"`
	Tokens map[string]string `json:"tokens,omitempty"`
}

// SoundOn reports the effective sound setting, defaulting to true on first run.
func (c Config) SoundOn() bool {
	return c.SoundEnabled == nil || *c.SoundEnabled
}

// TLSOn reports whether the transport is encrypted. It always is.
//
// This is no longer a preference. A BENCO server terminates TLS itself and runs
// no plaintext listener, so turning it off could only ever produce a timeout,
// and offering the choice invited someone to "fix" a connection problem by
// disabling the thing protecting the login handshake, buddy list, presence and
// who they talk to. Sign-on fails rather than connecting in the clear.
//
// The stored field is still read so a hand-edited config can turn it off for
// development against a plaintext server; there is simply no way to do it by
// accident from the UI.
func (c Config) TLSOn() bool {
	return c.TLSEnabled == nil || *c.TLSEnabled
}

// E2EEOn reports whether messages are end-to-end encrypted. They always are,
// where the other side supports it — a peer that does not is marked rather than
// quietly downgraded, so there is nothing a user gains by switching this off.
func (c Config) E2EEOn() bool {
	return c.E2EEEnabled == nil || *c.E2EEEnabled
}

// HistoryOn reports the effective history setting, defaulting to true on first
// run.
func (c Config) HistoryOn() bool {
	return c.HistoryEnabled == nil || *c.HistoryEnabled
}

// Default returns a Config seeded with the live deployment's address.
func Default() Config {
	return Config{
		AuthHost: DefaultAuthHost,
		AuthPort: DefaultAuthPort,
	}
}

// Address returns the "host:port" string used to dial the authorizer. Empty
// when no server has been configured yet.
func (c Config) Address() string {
	if c.AuthHost == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.AuthHost, c.AuthPort)
}

// HasServer reports whether a server address has been configured.
func (c Config) HasServer() bool { return c.AuthHost != "" }

// path returns the on-disk location of the config file, creating the parent
// directory if needed.
func path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	appDir := filepath.Join(dir, "BENCchat")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(appDir, "config.json"), nil
}

// Load reads the config from disk, falling back to defaults if no file exists
// yet. A missing file is not an error — it is the first-run case.
func Load() (Config, error) {
	p, err := path()
	if err != nil {
		return Default(), err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return Default(), err
	}
	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), fmt.Errorf("parse config %s: %w", p, err)
	}
	// A missing port is a corrupt/partial file; a missing HOST is the first-run
	// case, where the user has yet to say which server to use.
	if cfg.AuthPort == 0 {
		cfg.AuthPort = DefaultAuthPort
	}
	return cfg, nil
}

// Save writes the config back to disk.
func Save(cfg Config) error {
	p, err := path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}
