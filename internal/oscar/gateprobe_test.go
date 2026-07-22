package oscar

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// TestLiveGateProbe answers one question against the deployed server: is the
// consensual-connection gate actually enforcing? It removes the target first (on
// a gated server that revokes any grandfathered authorization), then re-adds and
// reads the FeedbagStatus the server returns:
//
//	AuthRequired (0x0E) → gate is LIVE   (re-add needs the target's approval)
//	Success      (0x00) → gate is ABSENT (add stored outright, no gate deployed)
//
// Run:
//
//	BENCCHAT_LIVE_SERVER=$SERVER:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=cmaximus2 BENCCHAT_LIVE_PASSWORD=... \
//	BENCCHAT_LIVE_GATE_TARGET=usec \
//	go test ./internal/oscar/ -run TestLiveGateProbe -v
func TestLiveGateProbe(t *testing.T) {
	addr := liveAddr(t)
	sn, pw := os.Getenv("BENCCHAT_LIVE_SCREENNAME"), os.Getenv("BENCCHAT_LIVE_PASSWORD")
	target := os.Getenv("BENCCHAT_LIVE_GATE_TARGET")
	if sn == "" || pw == "" || target == "" {
		t.Skip("set BENCCHAT_LIVE_SCREENNAME/PASSWORD and BENCCHAT_LIVE_GATE_TARGET")
	}

	ctx := context.Background()
	res, err := Login(ctx, addr, Credentials{ScreenName: sn, Password: pw}, liveTransport(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	session, err := SignOn(ctx, res)
	if err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer session.Close()

	var mu sync.Mutex
	var statuses []uint16
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		if frame.FoodGroup == wire.Feedbag && frame.SubGroup == wire.FeedbagStatus {
			var st wire.SNAC_0x13_0x0E_FeedbagStatus
			if wire.UnmarshalBE(&st, bytes.NewReader(body)) == nil {
				mu.Lock()
				statuses = append(statuses, st.Results...)
				mu.Unlock()
			}
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = session.Run(runCtx) }()

	// Clear any existing edge (grandfathered or otherwise). On a gated server this
	// also revokes the stored authorization, so the re-add below must re-ask.
	if _, err := session.RemoveBuddy(target); err != nil {
		t.Logf("remove (pre-clean, ok if absent): %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	mu.Lock()
	statuses = nil
	mu.Unlock()

	if _, err := session.AddBuddy(target, ""); err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(statuses) == 0 {
		t.Fatal("no FeedbagStatus after AddBuddy — could not read gate state")
	}
	gated := false
	for _, code := range statuses {
		if code == wire.FeedbagStatusAuthRequired {
			gated = true
		}
	}
	if gated {
		t.Logf("RESULT: GATE IS LIVE — server returned AuthRequired (0x000E) for %q → %q. codes=%v", sn, target, statuses)
	} else {
		t.Errorf("RESULT: GATE IS ABSENT — add of %q → %q stored with no auth required. codes=%v", sn, target, statuses)
	}
}
