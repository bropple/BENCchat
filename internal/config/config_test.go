package config

import "testing"

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
