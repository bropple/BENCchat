package oscar

import (
	"bytes"
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

func TestWarnRequestEncoding(t *testing.T) {
	client, fs := newFakeServer(t)
	s := &Session{conn: client, closed: make(chan struct{})}

	go func() { _ = s.WarnUser("triy", false) }()
	body := fs.expectSNAC(wire.ICBM, wire.ICBMEvilRequest)

	var req wire.SNAC_0x04_0x08_ICBMEvilRequest
	if err := wire.UnmarshalBE(&req, bytes.NewReader(body)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.SendAs != wire.EvilSendAsNamed {
		t.Errorf("SendAs = %d, want named (0)", req.SendAs)
	}
	if req.ScreenName != "triy" {
		t.Errorf("ScreenName = %q", req.ScreenName)
	}
}

func TestWarnAnonymousFlag(t *testing.T) {
	client, fs := newFakeServer(t)
	s := &Session{conn: client, closed: make(chan struct{})}

	go func() { _ = s.WarnUser("triy", true) }()
	body := fs.expectSNAC(wire.ICBM, wire.ICBMEvilRequest)

	var req wire.SNAC_0x04_0x08_ICBMEvilRequest
	if err := wire.UnmarshalBE(&req, bytes.NewReader(body)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.SendAs != wire.EvilSendAsAnonymous {
		t.Errorf("SendAs = %d, want anonymous (1)", req.SendAs)
	}
}

// TestWarnedNotificationNamed covers a named warning: the snitcher pointer is
// present and names the warner.
func TestWarnedNotificationNamed(t *testing.T) {
	n := wire.SNAC_0x01_0x10_OServiceEvilNotification{
		NewEvil:  100,
		Snitcher: &wire.EvilSnitcher{TLVUserInfo: wire.TLVUserInfo{ScreenName: "meanie"}},
	}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(n, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := DecodeWarnedNotification(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.NewLevel != 100 {
		t.Errorf("NewLevel = %d, want 100", got.NewLevel)
	}
	if got.From != "meanie" {
		t.Errorf("From = %q, want meanie", got.From)
	}
}

// TestWarnedNotificationAnonymous covers the critical optional-pointer case: an
// anonymous warning has NO snitcher, so the payload is just the 2-byte level.
// The decoder must treat the absent trailing struct as nil, not an error.
func TestWarnedNotificationAnonymous(t *testing.T) {
	// Marshal with a nil snitcher — should be exactly 2 bytes.
	n := wire.SNAC_0x01_0x10_OServiceEvilNotification{NewEvil: 30}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(n, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if buf.Len() != 2 {
		t.Fatalf("anonymous notification = %d bytes, want 2 (level only)", buf.Len())
	}

	got, err := DecodeWarnedNotification(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.NewLevel != 30 {
		t.Errorf("NewLevel = %d, want 30", got.NewLevel)
	}
	if got.From != "" {
		t.Errorf("From = %q, want empty for anonymous", got.From)
	}
}

func TestDecodeWarnResult(t *testing.T) {
	r := wire.SNAC_0x04_0x09_ICBMEvilReply{EvilDeltaApplied: 100, UpdatedEvilValue: 250}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(r, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeWarnResult(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.NewLevel != 250 || got.DeltaApplied != 100 {
		t.Errorf("got %+v, want delta 100 / level 250", got)
	}
}
