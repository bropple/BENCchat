package oscar

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

func TestSetAwayEncoding(t *testing.T) {
	client, fs := newFakeServer(t)
	s := &Session{conn: client, closed: make(chan struct{})}

	// Setting an away message: the data TLV carries the text, and a MIME TLV
	// accompanies it.
	go func() { _ = s.SetAway("Out to lunch") }()
	tl := tlvsOf(t, fs.expectSNAC(wire.Locate, wire.LocateSetInfo))
	if msg, ok := tl.String(wire.LocateTLVUnavailableData); !ok || msg != "Out to lunch" {
		t.Fatalf("away data TLV = %q (found=%v), want %q", msg, ok, "Out to lunch")
	}
	if !tl.HasTag(wire.LocateTLVUnavailableMime) {
		t.Error("a non-empty away message should carry the MIME TLV")
	}
}

func TestClearAwayEncoding(t *testing.T) {
	client, fs := newFakeServer(t)
	s := &Session{conn: client, closed: make(chan struct{})}

	// Clearing: the data TLV is still present but empty — that is how the server
	// is told to drop away status. The MIME TLV is omitted.
	go func() { _ = s.SetAway("") }()
	tl := tlvsOf(t, fs.expectSNAC(wire.Locate, wire.LocateSetInfo))
	msg, ok := tl.String(wire.LocateTLVUnavailableData)
	if !ok {
		t.Fatal("clearing away must still send an (empty) data TLV")
	}
	if msg != "" {
		t.Errorf("cleared away data TLV = %q, want empty", msg)
	}
	if tl.HasTag(wire.LocateTLVUnavailableMime) {
		t.Error("clearing away should not send a MIME TLV")
	}
}
