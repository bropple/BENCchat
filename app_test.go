package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/history"
	"github.com/benco-holdings/benchat/internal/state"
)

// Exercises the history orchestration the App owns — save the live scrollback to
// disk, then clear it — without needing a server. XDG_CONFIG_HOME is redirected
// so nothing touches the real config/history location.
func TestAppHistoryFlushAndClear(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := NewApp()
	a.histAccount = "tester" // stand in for a signed-on account

	a.store.AddMessage(state.Message{From: "buddy", To: "tester", Text: "hi", At: time.Now()})
	a.store.AddMessage(state.Message{From: "tester", To: "buddy", Text: "hey", At: time.Now(), Outgoing: true})

	a.flushHistory()

	convs, err := history.Load("tester")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(convs.Conversations) != 1 || len(convs.Conversations[0].Messages) != 2 {
		t.Fatalf("history not persisted as expected: %+v", convs)
	}

	if msg := a.ClearHistory(); msg != "" {
		t.Fatalf("ClearHistory returned error: %s", msg)
	}
	if convs, _ := history.Load("tester"); len(convs.Conversations) != 0 {
		t.Fatalf("history file survived clear: %+v", convs)
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
	a.cfg.HistoryRetentionDays = 7

	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "old", At: time.Now().AddDate(0, 0, -30)})
	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "new", At: time.Now()})
	a.flushHistory()

	convs, _ := history.Load("tester")
	if len(convs.Conversations) != 1 || len(convs.Conversations[0].Messages) != 1 || convs.Conversations[0].Messages[0].Text != "new" {
		t.Fatalf("retention not applied on save: %+v", convs)
	}
}

// With history disabled, nothing is written even when messages exist.
func TestAppHistoryDisabledDoesNotWrite(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := NewApp()
	a.histAccount = "tester"
	off := false
	a.cfg.HistoryEnabled = &off

	a.store.AddMessage(state.Message{From: "b", To: "tester", Text: "secret", At: time.Now()})
	a.flushHistory()

	if convs, _ := history.Load("tester"); len(convs.Conversations) != 0 {
		t.Fatalf("history was written while disabled: %+v", convs)
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

// A device that announces more than once — a sibling reconnecting, an
// auto-login racing a manual sign-on — must be asked about once. Two dialogs
// for one device is how the same machine got approved twice.
func TestLinkPromptAsksOncePerDevice(t *testing.T) {
	var key [32]byte
	key[0] = 1
	var other [32]byte
	other[0] = 2

	a := &App{}
	a.resetLinkState()

	if !a.markLinkPrompted(key) {
		t.Fatal("the first announcement must prompt")
	}
	if a.markLinkPrompted(key) {
		t.Error("a repeat announcement from the same device must not prompt again")
	}
	if !a.markLinkPrompted(other) {
		t.Error("a different device must still get its own prompt")
	}

	// Declining is an answer too: the same device asking again in this session
	// must not re-open the dialog the user just dismissed.
	var declined [32]byte
	declined[0] = 3
	if msg := a.DeclineDevice(e2ee.EncodeKey(declined)); msg != "" {
		t.Fatalf("DeclineDevice: %s", msg)
	}
	if a.markLinkPrompted(declined) {
		t.Error("a declined device must not re-prompt in the same session")
	}

	// A new session starts fresh, so a device declined earlier can ask again
	// rather than being ignored forever.
	a.resetLinkState()
	if !a.markLinkPrompted(declined) {
		t.Error("after a new sign-on a previously declined device must be able to ask again")
	}
}

// The pending flag is what tells the new machine it can't read anything yet.
// It must survive being set twice and clear exactly once.
func TestLinkPendingState(t *testing.T) {
	a := &App{store: state.NewStore()}
	a.resetLinkState()

	if a.GetDeviceLinkState().Pending {
		t.Error("a fresh session must not start out pending")
	}
	a.setLinkPending()
	if !a.GetDeviceLinkState().Pending {
		t.Fatal("setLinkPending did not take effect")
	}
	a.setLinkPending() // idempotent: must not notify twice
	a.clearLinkPending()
	if a.GetDeviceLinkState().Pending {
		t.Error("clearLinkPending did not clear the flag")
	}
}
