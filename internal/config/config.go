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

// DefaultAuthPort is the standard OSCAR port, which is not sensitive.
const DefaultAuthPort = 5190

// Config is the persisted client configuration.
type Config struct {
	// AuthHost / AuthPort address the BUCP authorizer — the first connection a
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

	// TLSEnabled connects over TLS. Off by default because the deployment is
	// still plaintext; turning it on requires a TLS listener server-side.
	TLSEnabled bool `json:"tlsEnabled,omitempty"`

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

// E2EEOn reports the effective encryption setting, defaulting to true.
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
