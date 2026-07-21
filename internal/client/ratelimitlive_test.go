package client

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// TestLiveSendBurstMarksNotSent drives the exact situation from the bug report:
// a burst of messages fired back to back. The server silently DROPS SNACs that
// exceed a rate limit — no error, no acknowledgement — so the only evidence is a
// missing ack. This checks both halves of the fix:
//
//	1. messages the server accepted are NOT falsely flagged, and
//	2. any that vanished end up marked NotSent rather than looking delivered.
//
//	BENCCHAT_LIVE_SERVER=aim.benco.lol:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_A=cmaximus  BENCCHAT_LIVE_A_PW=... \
//	BENCCHAT_LIVE_B=cmaximus2 BENCCHAT_LIVE_B_PW=... \
//	BENCCHAT_LIVE_BURST=40 \
//	go test ./internal/client/ -run TestLiveSendBurstMarksNotSent -v -timeout 300s
func TestLiveSendBurstMarksNotSent(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_SERVER")
	aName, aPw := os.Getenv("BENCCHAT_LIVE_A"), os.Getenv("BENCCHAT_LIVE_A_PW")
	bName, bPw := os.Getenv("BENCCHAT_LIVE_B"), os.Getenv("BENCCHAT_LIVE_B_PW")
	if addr == "" || aName == "" || bName == "" {
		t.Skip("set BENCCHAT_LIVE_SERVER and BENCCHAT_LIVE_A/_PW, BENCCHAT_LIVE_B/_PW")
	}
	burst := 40
	if v := os.Getenv("BENCCHAT_LIVE_BURST"); v != "" {
		fmt.Sscanf(v, "%d", &burst)
	}
	ctx := context.Background()

	// B online and auto-approving, so the pair is genuinely connected.
	b := New(state.NewStore(), nil)
	b.SetConnectionRequestHandler(func(req oscar.ConnectionRequest) {
		go func() { _ = b.ApproveConnection(req.ScreenName) }()
	})
	if err := b.SignOn(ctx, addr, oscar.Credentials{ScreenName: bName, Password: bPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn B: %v", err)
	}
	defer func() { _ = b.SignOff() }()

	a := New(state.NewStore(), nil)
	if err := a.SignOn(ctx, addr, oscar.Credentials{ScreenName: aName, Password: aPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn A: %v", err)
	}
	defer func() { _ = a.SignOff() }()
	time.Sleep(500 * time.Millisecond)

	connected := func() bool {
		for _, x := range a.store.Buddies() {
			if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
				return !x.Pending
			}
		}
		return false
	}
	if !connected() {
		_ = a.AddBuddy(bName, "Buddies")
		for i := 0; i < 40 && !connected(); i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}
	if !connected() {
		t.Fatalf("not connected to %s; can't test sending", bName)
	}

	// Fire the burst as fast as SendMessage will go.
	start := time.Now()
	sent := 0
	for i := 0; i < burst; i++ {
		if err := a.SendMessage(bName, fmt.Sprintf("burst %d", i+1)); err != nil {
			t.Logf("send %d returned an error: %v", i+1, err)
			continue
		}
		sent++
	}
	t.Logf("issued %d/%d sends in %s (client pacing included)", sent, burst, time.Since(start).Round(time.Millisecond))

	// Wait past the ack timeout so every send has resolved one way or the other.
	time.Sleep(ackTimeout + 5*time.Second)

	convo, ok := a.store.Conversation(bName)
	if !ok {
		t.Fatal("no conversation recorded")
	}
	var outgoing, notSent int
	for _, m := range convo.Messages {
		if !m.Outgoing {
			continue
		}
		outgoing++
		if m.NotSent {
			notSent++
		}
	}
	t.Logf("RESULT: %d outgoing tracked, %d marked NOT SENT, %d confirmed delivered",
		outgoing, notSent, outgoing-notSent)
	if outgoing == 0 {
		t.Fatal("no outgoing messages recorded")
	}
	// The point isn't that drops must happen — it's that whatever happened is
	// now visible instead of silent.
	if notSent == outgoing {
		t.Errorf("EVERY message was marked not-sent — acks aren't being matched")
	}
}
