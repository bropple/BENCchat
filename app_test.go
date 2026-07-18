package main

import (
	"testing"
	"time"

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
