package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/benco-holdings/benchat/internal/history"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
)

// histKeyForTest gives a test App a working history key without going near a
// real keyring, and returns it for reading the file back.
func histKeyForTest(t *testing.T, a *App) *[32]byte {
	t.Helper()
	k, err := history.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	a.histKey = k
	return k
}

// Exercises the history orchestration the App owns — save the live scrollback to
// disk, then clear it — without needing a server. XDG_CONFIG_HOME is redirected
// so nothing touches the real config/history location.
func TestAppHistoryFlushAndClear(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInit() // ClearHistory drops the stored key; don't touch the real one
	a := NewApp()
	a.histAccount = "tester" // stand in for a signed-on account
	key := histKeyForTest(t, a)

	a.store.AddMessage(state.Message{From: "buddy", To: "tester", Text: "hi", At: time.Now()})
	a.store.AddMessage(state.Message{From: "tester", To: "buddy", Text: "hey", At: time.Now(), Outgoing: true})

	a.flushHistory()

	convs, err := history.Load("tester", key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(convs.Conversations) != 1 || len(convs.Conversations[0].Messages) != 2 {
		t.Fatalf("history not persisted as expected: %+v", convs)
	}

	if msg := a.ClearHistory(); msg != "" {
		t.Fatalf("ClearHistory returned error: %s", msg)
	}
	if convs, _ := history.Load("tester", key); len(convs.Conversations) != 0 {
		t.Fatalf("history file survived clear: %+v", convs)
	}
	// The session keeps a usable key afterwards, so clearing history doesn't
	// quietly switch saving off for the rest of it.
	if a.historyKey() == nil {
		t.Error("ClearHistory left the session without a history key")
	}
	if len(a.store.Conversations()) != 0 {
		t.Fatal("in-memory conversations survived clear")
	}
}

// Retention prunes on save: an old message is dropped, a recent one kept.
func TestAppHistoryRetention(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := NewApp()
	a.histAccount = "tester"
	key := histKeyForTest(t, a)
	a.cfg.HistoryRetentionDays = 7

	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "old", At: time.Now().AddDate(0, 0, -30)})
	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "new", At: time.Now()})
	a.flushHistory()

	convs, _ := history.Load("tester", key)
	if len(convs.Conversations) != 1 || len(convs.Conversations[0].Messages) != 1 || convs.Conversations[0].Messages[0].Text != "new" {
		t.Fatalf("retention not applied on save: %+v", convs)
	}
}

// With history disabled, nothing is written even when messages exist.
func TestAppHistoryDisabledDoesNotWrite(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := NewApp()
	a.histAccount = "tester"
	key := histKeyForTest(t, a)
	off := false
	a.cfg.HistoryEnabled = &off

	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "secret", At: time.Now()})
	a.flushHistory()

	if convs, _ := history.Load("tester", key); len(convs.Conversations) != 0 {
		t.Fatalf("history was written while disabled: %+v", convs)
	}
}

// Without a key, saving is skipped rather than attempted. There is no plaintext
// fallback: the alternative to an encrypted file is no file.
func TestAppHistoryWithoutKeyWritesNothing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := NewApp()
	a.histAccount = "tester"
	a.histKey = nil // as after a keyring failure at sign-on

	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "secret", At: time.Now()})
	a.flushHistory()
	// persistHistoryNow must also stand down — deleting history we merely failed
	// to open would be worse than a removal that doesn't stick.
	a.persistHistoryNow()

	if convs, err := history.Load("tester", nil); err != nil || len(convs.Conversations) != 0 {
		t.Fatalf("something was written without a key: %+v (%v)", convs, err)
	}
}

// With history off nothing is read or written, so setup must not reach for the
// keychain at all — an unlock prompt for a feature the user turned off. Turning
// it back on mid-session is what establishes the key.
func TestSetupHistoryKeySkippedWhileDisabledThenRecovers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInit()

	a := NewApp()
	off := false
	a.cfg.HistoryEnabled = &off
	a.setupHistoryKey("tester")

	if a.historyKey() != nil {
		t.Error("a key was set up while history saving is off")
	}
	if stored, _ := secret.RetrieveHistoryKey("tester"); stored != "" {
		t.Error("a key was stored while history saving is off")
	}

	a.histAccount = "tester"
	if msg := a.SetHistoryEnabled(true); msg != "" {
		t.Fatalf("SetHistoryEnabled: %s", msg)
	}
	if a.historyKey() == nil {
		t.Fatal("turning history on did not establish a key, so nothing would save")
	}
}

// The rule setupE2EE established, applied to history: a keyring read that FAILED
// is not the same answer as an account with no key yet. Minting one on failure
// would seal new history under a key unrelated to the file already on disk and
// make every saved message unreadable.
func TestSetupHistoryKeyFailClosedOnKeyringError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInitWithError(errors.New("keychain is locked"))
	t.Cleanup(keyring.MockInit)

	a := NewApp()
	a.setupHistoryKey("tester")

	if a.historyKey() != nil {
		t.Fatal("a failed keyring read produced a key — history on disk would be stranded")
	}
}

// An account with nothing stored is the genuine first-run case: mint, store, and
// carry on. A second sign-on must then reuse that key rather than minting again.
func TestSetupHistoryKeyMintsOnceThenReuses(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInit()

	a := NewApp()
	a.setupHistoryKey("tester")

	first := a.historyKey()
	if first == nil {
		t.Fatal("no key was generated for an account that has none")
	}
	stored, err := secret.RetrieveHistoryKey("tester")
	if err != nil || stored == "" {
		t.Fatalf("the generated key was not stored: %q (%v)", stored, err)
	}
	if want := base64.StdEncoding.EncodeToString(first[:]); stored != want {
		t.Fatal("the stored key is not the one in use")
	}

	a.setupHistoryKey("tester")
	if second := a.historyKey(); second == nil || *second != *first {
		t.Fatal("a second sign-on minted a new key instead of reusing the stored one")
	}
}

// A port/TLS mismatch fails in a way that reads like a network fault while
// actually being one checkbox. The message has to say which.
func TestTransportHint(t *testing.T) {
	// The verbatim error from a Windows client speaking plaintext at the TLS
	// port: the connection succeeded, then both ends waited for each other.
	plainAtTLSPort := errors.New("oscar: server hello: oscar: read FLAP frame: " +
		"failed to unmarshal: read tcp 10.0.0.245:51786->198.51.100.7:5191: i/o timeout")
	tlsAtPlainPort := errors.New("oscar: dial: tls: first record does not look like a TLS handshake")
	badCert := errors.New(`oscar: dial: x509: certificate is valid for other.example, not this.example`)
	badPassword := errors.New("incorrect screen name or password")

	tests := []struct {
		name   string
		err    error
		tlsOn  bool
		expect string // substring the hint must contain; "" means no hint at all
	}{
		{"plaintext at a TLS port suggests turning TLS on", plainAtTLSPort, false, "turn on"},
		{"TLS at a plaintext port names the port, not the setting", tlsAtPlainPort, true, "doesn't speak TLS"},
		{"a bad certificate is not a wrong port", badCert, true, "certificate"},
		{"an ordinary auth failure gets no transport advice", badPassword, false, ""},
		{"a timeout with TLS already on gets no advice", plainAtTLSPort, true, ""},
		{"no error, no hint", nil, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := transportHint(tc.err, tc.tlsOn)
			if tc.expect == "" {
				if got != "" {
					t.Errorf("expected no hint, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.expect) {
				t.Errorf("hint = %q, want it to mention %q", got, tc.expect)
			}
		})
	}

	// The certificate case must not tell people the port is wrong: that sends
	// them disabling verification when the address was the actual problem.
	if h := transportHint(badCert, true); strings.Contains(h, "doesn't speak TLS") {
		t.Errorf("certificate failure misreported as a port problem: %q", h)
	}
}
