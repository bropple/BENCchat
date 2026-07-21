package e2ee

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// TestStampSurvivesSingleRecipientRoundTrip: the send time and message ID must
// come back out of the envelope, because they are what makes a replay visible.
func TestStampSurvivesSingleRecipientRoundTrip(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recip, _ := GenerateKeyPair()

	before := time.Now().Add(-time.Second)
	env, err := Seal("meet me at six", recip.Public, sender.Private)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(env, sender.Public, recip.Private)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Text != "meet me at six" {
		t.Errorf("text = %q", got.Text)
	}
	if got.SentAt.Before(before) || got.SentAt.After(time.Now().Add(time.Second)) {
		t.Errorf("sent-at = %v, not close to now", got.SentAt)
	}
	if got.ID == ([16]byte{}) {
		t.Error("no message ID, so duplicates are undetectable")
	}
}

// TestStampSurvivesMultiRecipientRoundTrip: same for the multi-device envelope,
// which seals the body once under a per-message key.
func TestStampSurvivesMultiRecipientRoundTrip(t *testing.T) {
	sender, _ := GenerateKeyPair()
	a, _ := GenerateKeyPair()
	b, _ := GenerateKeyPair()

	env, err := SealFor("hello both", [][32]byte{a.Public, b.Public}, sender.Private)
	if err != nil {
		t.Fatalf("SealFor: %v", err)
	}
	for i, kp := range []KeyPair{a, b} {
		got, err := OpenAny(env, sender.Public, kp.Private)
		if err != nil {
			t.Fatalf("device %d: OpenAny: %v", i, err)
		}
		if got.Text != "hello both" {
			t.Errorf("device %d: text = %q", i, got.Text)
		}
		if got.ID == ([16]byte{}) {
			t.Errorf("device %d: no message ID", i)
		}
	}
}

// TestEveryMessageGetsADistinctID: a shared ID would make genuine repeats look
// like replays, and replays look genuine.
func TestEveryMessageGetsADistinctID(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recip, _ := GenerateKeyPair()

	seen := map[[16]byte]bool{}
	for i := 0; i < 50; i++ {
		env, _ := Seal("same text every time", recip.Public, sender.Private)
		got, err := Open(env, sender.Public, recip.Private)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if seen[got.ID] {
			t.Fatal("two messages shared a message ID")
		}
		seen[got.ID] = true
	}
}

// TestPlausibleSendTimeBoundsTheFutureOnly.
//
// Age must NOT be suspicious: OSCAR stores offline messages server-side and
// delivers them at sign-on, which can be days later, so rejecting old
// timestamps would break the case that store exists for.
func TestPlausibleSendTimeBoundsTheFutureOnly(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		sentAt time.Time
		want   bool
	}{
		{"just now", now, true},
		{"an hour ago", now.Add(-time.Hour), true},
		{"a week ago, delivered from the offline store", now.Add(-7 * 24 * time.Hour), true},
		{"slight clock skew ahead", now.Add(5 * time.Minute), true},
		{"far in the future", now.Add(24 * time.Hour), false},
		{"absent", time.Time{}, false},
	}
	for _, tc := range cases {
		if got := PlausibleSendTime(tc.sentAt, now); got != tc.want {
			t.Errorf("%s: PlausibleSendTime = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestLegacyEnvelopeCarriesNoStamp: a v1 envelope from an older client has no
// stamp, and absent must read as "told us nothing" so the receiver falls back to
// its own clock rather than showing the epoch.
func TestLegacyEnvelopeCarriesNoStamp(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recip, _ := GenerateKeyPair()

	v1 := sealLegacyV1(t, "an old message", recip.Public, sender.Private)
	got, err := Open(v1, sender.Public, recip.Private)
	if err != nil {
		t.Fatalf("Open(v1): %v", err)
	}
	if got.Text != "an old message" {
		t.Errorf("text = %q", got.Text)
	}
	if !got.SentAt.IsZero() {
		t.Errorf("sent-at = %v, want zero for an unstamped envelope", got.SentAt)
	}
	if PlausibleSendTime(got.SentAt, time.Now()) {
		t.Error("an absent stamp was treated as a usable timestamp")
	}
}

// sealLegacyV1 builds a pre-stamp envelope, the shape an older client emits.
func sealLegacyV1(t *testing.T, message string, recipientPub, senderPriv [32]byte) string {
	t.Helper()
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	sealed := box.Seal(nonce[:], []byte(message), &nonce, &recipientPub, &senderPriv)
	return envelopePrefix + base64.StdEncoding.EncodeToString(sealed)
}
