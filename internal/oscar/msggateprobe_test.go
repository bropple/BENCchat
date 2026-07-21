package oscar

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// TestLiveMsgGateProbe sends a raw ICBM to an unconnected target and watches for
// the server's rejection. With the consensual-connection messaging gate live and
// no authorization between the two accounts, ChannelMsgToHost must bounce with
// ICBMErr / NotLoggedOn (0x04) rather than delivering.
//
//	BENCCHAT_LIVE_SCREENNAME=cmaximus2 BENCCHAT_LIVE_PASSWORD=... \
//	BENCCHAT_LIVE_GATE_TARGET=usec \
//	go test ./internal/oscar/ -run TestLiveMsgGateProbe -v
func TestLiveMsgGateProbe(t *testing.T) {
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
	var errCodes []uint16
	session.Handler = func(frame wire.SNACFrame, body []byte) {
		if frame.FoodGroup == wire.ICBM && frame.SubGroup == wire.ICBMErr {
			var code uint16
			if len(body) >= 2 {
				code = uint16(body[0])<<8 | uint16(body[1])
			}
			mu.Lock()
			errCodes = append(errCodes, code)
			mu.Unlock()
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = session.Run(runCtx) }()
	time.Sleep(500 * time.Millisecond)

	if _, _, err := session.SendMessage(target, "gate probe — you should never see this", false); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(errCodes) > 0 {
		t.Logf("RESULT: MESSAGING GATE IS LIVE — server rejected %q → %q with ICBMErr codes=%v", sn, target, errCodes)
		return
	}
	t.Errorf("RESULT: MESSAGING GATE IS ABSENT — no ICBMErr; server accepted %q → %q with no authorization", sn, target)
}
