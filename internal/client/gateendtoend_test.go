package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// TestLiveGateEndToEnd proves the consensual-connection gate in both directions
// WITHOUT depending on whatever state the accounts happen to be in. Test accounts
// get connected and disconnected constantly during development, so a probe that
// assumes "these two aren't connected" reports a false failure the moment someone
// links them by hand. This drives both accounts instead:
//
//	disconnect -> a message must be REFUSED
//	connect    -> a message must be DELIVERED
//
// and leaves them connected, the state it found most useful to leave behind.
// Delivery is judged by the send-tracking added for rate limiting: a refused or
// dropped message ends up flagged NotSent, a delivered one doesn't.
//
//	BENCCHAT_LIVE_SERVER=$SERVER:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_A=cmaximus  BENCCHAT_LIVE_A_PW=... \
//	BENCCHAT_LIVE_B=cmaximus2 BENCCHAT_LIVE_B_PW=... \
//	go test ./internal/client/ -run TestLiveGateEndToEnd -v -timeout 200s
func TestLiveGateEndToEnd(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_SERVER")
	aName, aPw := os.Getenv("BENCCHAT_LIVE_A"), os.Getenv("BENCCHAT_LIVE_A_PW")
	bName, bPw := os.Getenv("BENCCHAT_LIVE_B"), os.Getenv("BENCCHAT_LIVE_B_PW")
	if addr == "" || aName == "" || bName == "" {
		t.Skip("set BENCCHAT_LIVE_SERVER and BENCCHAT_LIVE_A/_PW, BENCCHAT_LIVE_B/_PW")
	}
	ctx := context.Background()

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

	// lastOutcome reports whether A's most recent message to B was flagged unsent.
	lastOutcome := func() (notSent bool, ok bool) {
		convo, exists := a.store.Conversation(bName)
		if !exists {
			return false, false
		}
		for i := len(convo.Messages) - 1; i >= 0; i-- {
			if convo.Messages[i].Outgoing {
				return convo.Messages[i].NotSent, true
			}
		}
		return false, false
	}
	connected := func() bool {
		for _, x := range a.store.Buddies() {
			if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
				return !x.Pending
			}
		}
		return false
	}

	// --- Disconnected: a message must be refused -----------------------------
	_ = a.RemoveBuddy(bName) // severs both directions and revokes the grants
	time.Sleep(1500 * time.Millisecond)
	if err := a.SendMessage(bName, "gate probe — should be refused"); err != nil {
		t.Logf("send while disconnected returned an error (also a refusal): %v", err)
	}
	time.Sleep(3 * time.Second)
	if notSent, ok := lastOutcome(); !ok {
		t.Fatal("no outgoing message recorded while disconnected")
	} else if !notSent {
		t.Errorf("GATE NOT ENFORCED: a message to a disconnected %q was accepted", bName)
	} else {
		t.Logf("RESULT: disconnected -> message refused (gate enforced)")
	}

	// --- Connected: a message must be delivered ------------------------------
	if err := a.AddBuddy(bName, "Buddies"); err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}
	for i := 0; i < 40 && !connected(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if !connected() {
		t.Fatalf("never reconnected to %s", bName)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := a.SendMessage(bName, "gate probe — should be delivered"); err != nil {
		t.Fatalf("send while connected failed: %v", err)
	}
	time.Sleep(3 * time.Second)
	if notSent, ok := lastOutcome(); !ok {
		t.Fatal("no outgoing message recorded while connected")
	} else if notSent {
		t.Errorf("a message to a CONNECTED %q was not delivered", bName)
	} else {
		t.Logf("RESULT: connected -> message delivered")
	}
}
