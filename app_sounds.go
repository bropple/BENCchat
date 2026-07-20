package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// soundEventKeys is the set of valid custom-sound event keys, mirroring the
// frontend's SOUND_EVENTS. Validated on every call so a bad key can't write
// outside the sounds directory.
var soundEventKeys = map[string]bool{
	"imrcv": true, "imsend": true, "dooropen": true, "doorslam": true,
	"newalert": true, "newmail": true, "ring": true, "phone": true,
	"talkbeg": true, "talkend": true, "talkstop": true, "cashregister": true,
	"moo": true,
}

// soundsDir is where imported custom sounds live, under the app config dir.
func soundsDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, "BENCchat", "sounds")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

// SetCustomSound stores an imported audio file for an event. data is base64 of
// the raw file bytes (a data: URL prefix, if present, is stripped). The file
// format is whatever the webview's decodeAudioData accepts (wav/mp3/ogg).
func (a *App) SetCustomSound(key, data string) string {
	if !soundEventKeys[key] {
		return "unknown sound event"
	}
	if i := strings.Index(data, ","); strings.HasPrefix(data, "data:") && i >= 0 {
		data = data[i+1:]
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err != nil {
		return "invalid audio data"
	}
	d, err := soundsDir()
	if err != nil {
		return err.Error()
	}
	if err := os.WriteFile(filepath.Join(d, key+".snd"), raw, 0o644); err != nil {
		return err.Error()
	}
	return ""
}

// GetCustomSounds returns every imported sound as event key → base64 of the file
// bytes, for the frontend to decode into playback buffers.
func (a *App) GetCustomSounds() map[string]string {
	out := map[string]string{}
	d, err := soundsDir()
	if err != nil {
		return out
	}
	for key := range soundEventKeys {
		raw, err := os.ReadFile(filepath.Join(d, key+".snd"))
		if err != nil {
			continue
		}
		out[key] = base64.StdEncoding.EncodeToString(raw)
	}
	return out
}

// ClearCustomSound removes one event's imported sound. Missing is not an error.
func (a *App) ClearCustomSound(key string) string {
	if !soundEventKeys[key] {
		return "unknown sound event"
	}
	d, err := soundsDir()
	if err != nil {
		return err.Error()
	}
	if err := os.Remove(filepath.Join(d, key+".snd")); err != nil && !os.IsNotExist(err) {
		return err.Error()
	}
	return ""
}
