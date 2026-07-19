package config

import (
	"encoding/json"
	"testing"
)

func TestSoundOnDefaultsTrue(t *testing.T) {
	// First run: no preference stored. Sound should default ON — the effects are
	// part of the experience, and a nil pointer must not read as "off".
	if !(Config{}).SoundOn() {
		t.Error("SoundOn() should default to true when unset")
	}
}

func TestSoundOnHonorsExplicitChoice(t *testing.T) {
	off := false
	if (Config{SoundEnabled: &off}).SoundOn() {
		t.Error("SoundOn() should be false when explicitly disabled")
	}
	on := true
	if !(Config{SoundEnabled: &on}).SoundOn() {
		t.Error("SoundOn() should be true when explicitly enabled")
	}
}

// TLS defaults ON, and an explicit "off" has to survive being saved and
// reloaded. With a plain bool it would not: omitempty drops a false, the key
// vanishes, and the next load reads it back as the default — silently turning
// TLS on for someone who deliberately turned it off.
func TestTLSDefaultsOnAndExplicitOffRoundTrips(t *testing.T) {
	if !(Config{}).TLSOn() {
		t.Error("a config with no TLS setting must default to TLS on")
	}

	off := false
	on := true
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset", Config{}, true},
		{"explicit off", Config{TLSEnabled: &off}, false},
		{"explicit on", Config{TLSEnabled: &on}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(tc.cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got Config
			if err := json.Unmarshal(blob, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.TLSOn() != tc.want {
				t.Errorf("after round trip TLSOn() = %v, want %v (json: %s)",
					got.TLSOn(), tc.want, blob)
			}
		})
	}
}
