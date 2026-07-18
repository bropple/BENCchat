package e2ee

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func mustRoomKey(t *testing.T) RoomKey {
	t.Helper()
	k, err := GenerateRoomKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestRoomRoundTrip: a member holding the key reads the message.
func TestRoomRoundTrip(t *testing.T) {
	k := mustRoomKey(t)
	env, err := SealRoom("hello room 🔒", k)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRoomEnvelope(env) {
		t.Fatal("sealed room message not recognized as an envelope")
	}
	if strings.Contains(env, "hello room") {
		t.Fatal("plaintext leaked into the room envelope")
	}
	got, err := OpenRoom(env, map[string]RoomKey{k.ID(): k})
	if err != nil || got != "hello room 🔒" {
		t.Fatalf("OpenRoom = %q, %v", got, err)
	}
}

// TestRoomKeyRotationKeepsHistory is why messages carry a key ID: after a
// rotation, older messages must still open rather than becoming unreadable.
func TestRoomKeyRotationKeepsHistory(t *testing.T) {
	oldKey, newKey := mustRoomKey(t), mustRoomKey(t)
	if oldKey.ID() == newKey.ID() {
		t.Fatal("two random keys collided on ID")
	}

	before, _ := SealRoom("said before rotation", oldKey)
	after, _ := SealRoom("said after rotation", newKey)

	// A member who kept both keys reads the whole scrollback.
	all := map[string]RoomKey{oldKey.ID(): oldKey, newKey.ID(): newKey}
	if got, err := OpenRoom(before, all); err != nil || got != "said before rotation" {
		t.Errorf("pre-rotation message unreadable: %q %v", got, err)
	}
	if got, err := OpenRoom(after, all); err != nil || got != "said after rotation" {
		t.Errorf("post-rotation message unreadable: %q %v", got, err)
	}

	// Someone invited only after the rotation cannot read the earlier traffic —
	// which is the point of rotating.
	onlyNew := map[string]RoomKey{newKey.ID(): newKey}
	if _, err := OpenRoom(before, onlyNew); !errors.Is(err, ErrUnknownRoomKey) {
		t.Errorf("a post-rotation member could read pre-rotation history (err=%v)", err)
	}
}

// TestRoomUnknownKeyIsDistinguishable: "I can't read this" must be tellable
// from "this is corrupt", so the UI can explain instead of showing an error.
func TestRoomUnknownKeyIsDistinguishable(t *testing.T) {
	k, other := mustRoomKey(t), mustRoomKey(t)
	env, _ := SealRoom("secret", k)

	_, err := OpenRoom(env, map[string]RoomKey{other.ID(): other})
	if !errors.Is(err, ErrUnknownRoomKey) {
		t.Errorf("err = %v, want ErrUnknownRoomKey", err)
	}
	id, ok := RoomEnvelopeKeyID(env)
	if !ok || id != k.ID() {
		t.Errorf("key ID = %q (ok=%v), want %q", id, ok, k.ID())
	}
	if _, ok := RoomEnvelopeKeyID("just a normal message"); ok {
		t.Error("a plain message was reported as an encrypted envelope")
	}
}

// TestRoomWrongKeyFailsClosed: a key with the right ID but wrong bytes (or a
// tampered body) must fail, not return garbage.
func TestRoomWrongKeyFailsClosed(t *testing.T) {
	k := mustRoomKey(t)
	env, _ := SealRoom("original", k)

	// Same ID, different key material.
	imposter := mustRoomKey(t)
	if _, err := OpenRoom(env, map[string]RoomKey{k.ID(): imposter}); err == nil {
		t.Error("a wrong key with a matching ID decrypted the message")
	}

	corrupt := []byte(env)
	corrupt[len(corrupt)-2] ^= 0x01
	if _, err := OpenRoom(string(corrupt), map[string]RoomKey{k.ID(): k}); err == nil {
		t.Error("a tampered room message decrypted successfully")
	}
}

// TestRoomEnvelopeSurvivesTheServer guards the two ways open-oscar-server
// mangles chat text.
//
// It runs an HTML tokenizer over the message and returns the first text token,
// then regex-matches "^//roll" to implement dice commands — REPLACING the
// message when it matches. An envelope that tripped either would be silently
// destroyed in transit, so the format has to be structurally incapable of it.
func TestRoomEnvelopeSurvivesTheServer(t *testing.T) {
	dice := regexp.MustCompile(`^//roll`)

	for i := 0; i < 200; i++ {
		k := mustRoomKey(t)
		env, err := SealRoom(strings.Repeat("x", i%50)+" message", k)
		if err != nil {
			t.Fatal(err)
		}
		if dice.MatchString(env) {
			t.Fatalf("envelope matches the server's dice-command pattern: %q", env[:20])
		}
		if strings.ContainsAny(env, "<>&") {
			t.Fatalf("envelope contains markup characters the server's HTML tokenizer would eat: %q", env)
		}
		if env[0] != 0x1b {
			t.Fatalf("envelope does not start with ESC, so it could be read as text: %q", env[:8])
		}
	}
}

// TestRoomInviteRoundTrip covers key delivery, including a room name with a
// colon in it — which would split a naively formatted invite.
func TestRoomInviteRoundTrip(t *testing.T) {
	k := mustRoomKey(t)
	for _, name := range []string{"bencchat-livetest", "weird:name:with:colons", "spaces and 🎲"} {
		body := EncodeRoomInvite(RoomInvite{Room: name, Key: k})
		if !IsRoomInvite(body) {
			t.Fatalf("invite for %q not recognized", name)
		}
		got, ok := DecodeRoomInvite(body)
		if !ok {
			t.Fatalf("invite for %q failed to decode", name)
		}
		if got.Room != name {
			t.Errorf("room = %q, want %q", got.Room, name)
		}
		if got.Key != k {
			t.Errorf("key did not survive the invite for %q", name)
		}
	}

	for _, bad := range []string{
		"hello there",
		roomInvitePrefix + "no-separator",
		roomInvitePrefix + "!!!:" + EncodeRoomKey(k),
		roomInvitePrefix + "dGVzdA==:not-a-key",
	} {
		if _, ok := DecodeRoomInvite(bad); ok {
			t.Errorf("malformed invite accepted: %q", bad)
		}
	}
}

// TestRoomInviteIsNotChatText: invites travel as 1:1 messages, so they must be
// distinguishable from something a person typed.
func TestRoomInviteIsNotChatText(t *testing.T) {
	if IsRoomInvite("BENCO-ROOMINV is a funny string") {
		t.Error("a typed message was treated as a room invite")
	}
	if IsRoomEnvelope(EncodeRoomInvite(RoomInvite{Room: "r", Key: mustRoomKey(t)})) {
		t.Error("an invite was mistaken for a room message envelope")
	}
}

// TestCatchupRoundTrip covers both directions of the catch-up exchange.
func TestCatchupRoundTrip(t *testing.T) {
	since := time.Unix(1750000000, 0)
	body := EncodeCatchupRequest(CatchupRequest{Room: "weird:room:name", Since: since})
	if !IsCatchup(body) {
		t.Fatal("request not recognized as catch-up traffic")
	}
	isReq, req, _, ok := DecodeCatchup(body)
	if !ok || !isReq {
		t.Fatalf("request failed to decode (ok=%v isReq=%v)", ok, isReq)
	}
	if req.Room != "weird:room:name" {
		t.Errorf("room = %q, want the colon-laden original", req.Room)
	}
	if !req.Since.Equal(since) {
		t.Errorf("since = %v, want %v", req.Since, since)
	}

	res := CatchupResponse{Room: "r", Messages: []CatchupMessage{
		{From: "bob", At: 1750000001, Text: "first"},
		{From: "alice", At: 1750000002, Text: "second 🔒"},
	}}
	rbody, err := EncodeCatchupResponse(res)
	if err != nil {
		t.Fatal(err)
	}
	isReq, _, got, ok := DecodeCatchup(rbody)
	if !ok || isReq {
		t.Fatalf("response failed to decode (ok=%v isReq=%v)", ok, isReq)
	}
	if len(got.Messages) != 2 || got.Messages[1].Text != "second 🔒" {
		t.Fatalf("messages did not survive: %+v", got.Messages)
	}
	if got.Truncated {
		t.Error("a small batch was marked truncated")
	}
}

// TestCatchupTrimsToFit: a response must fit an instant message, and should
// drop the OLDEST messages — a returning member needs the recent ones most.
func TestCatchupTrimsToFit(t *testing.T) {
	var msgs []CatchupMessage
	for i := 0; i < 500; i++ {
		msgs = append(msgs, CatchupMessage{From: "alice", At: int64(i), Text: strings.Repeat("x", 200)})
	}
	body, err := EncodeCatchupResponse(CatchupResponse{Room: "r", Messages: msgs})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > CatchupMaxBytes*2 {
		t.Errorf("encoded response is %d bytes — too large to send as one message", len(body))
	}
	_, _, got, ok := DecodeCatchup(body)
	if !ok {
		t.Fatal("trimmed response failed to decode")
	}
	if !got.Truncated {
		t.Error("a trimmed batch was not flagged truncated — the user would think it complete")
	}
	if len(got.Messages) == 0 {
		t.Fatal("everything was trimmed away")
	}
	// The newest message must survive; the oldest should be the one dropped.
	last := got.Messages[len(got.Messages)-1]
	if last.At != 499 {
		t.Errorf("newest message kept has At=%d, want 499 — trimming dropped the wrong end", last.At)
	}
}

// TestCatchupRejectsOverlongClaims: a peer cannot make us accept more than the
// protocol allows by simply asserting it.
func TestCatchupRejectsOverlongClaims(t *testing.T) {
	var msgs []CatchupMessage
	for i := 0; i < CatchupMaxMessages+50; i++ {
		msgs = append(msgs, CatchupMessage{From: "x", At: int64(i), Text: "m"})
	}
	payload, _ := json.Marshal(struct {
		T bool             `json:"tr,omitempty"`
		M []CatchupMessage `json:"m"`
	}{M: msgs})
	hostile := catchupPrefix + "res:" +
		base64.StdEncoding.EncodeToString([]byte("r")) + ":" +
		base64.StdEncoding.EncodeToString(payload)

	_, _, got, ok := DecodeCatchup(hostile)
	if !ok {
		t.Fatal("well-formed but oversized response should still decode, trimmed")
	}
	if len(got.Messages) > CatchupMaxMessages {
		t.Errorf("accepted %d messages, over the %d limit", len(got.Messages), CatchupMaxMessages)
	}
}

// TestCatchupMalformedRejected: junk must not panic or half-parse.
func TestCatchupMalformedRejected(t *testing.T) {
	for _, bad := range []string{
		"a normal message",
		catchupPrefix + "req",
		catchupPrefix + "req:!!!:123",
		catchupPrefix + "req:cm9vbQ==:notanumber",
		catchupPrefix + "res:cm9vbQ==:!!notbase64",
		catchupPrefix + "res:cm9vbQ==:" + base64.StdEncoding.EncodeToString([]byte("{not json")),
		catchupPrefix + "bogus:cm9vbQ==:x",
	} {
		if _, _, _, ok := DecodeCatchup(bad); ok {
			t.Errorf("malformed catch-up accepted: %q", bad)
		}
	}
	// And it must not be confused with the other room message types.
	if IsRoomEnvelope(EncodeCatchupRequest(CatchupRequest{Room: "r"})) {
		t.Error("catch-up traffic was mistaken for a room message")
	}
	if IsRoomInvite(EncodeCatchupRequest(CatchupRequest{Room: "r"})) {
		t.Error("catch-up traffic was mistaken for an invite")
	}
}
