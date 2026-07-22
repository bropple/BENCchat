package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// TestLiveMoveConnectedBuddy reproduces "move to a new group does nothing" with a
// genuinely connected buddy. It connects cmaximus <-> cmaximus2 through the
// consent flow, moves the buddy to a fresh group + renames it, then reads back
// what the SERVER stored (via a fresh session) and confirms messaging still
// works (i.e. the move didn't sever the connection).
//
//	BENCCHAT_LIVE_SERVER=$SERVER:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_A=cmaximus  BENCCHAT_LIVE_A_PW=... \
//	BENCCHAT_LIVE_B=cmaximus2 BENCCHAT_LIVE_B_PW=... \
//	go test ./internal/client/ -run TestLiveMoveConnectedBuddy -v -timeout 120s
func TestLiveMoveConnectedBuddy(t *testing.T) {
	addr := os.Getenv("BENCCHAT_LIVE_SERVER")
	aName, aPw := os.Getenv("BENCCHAT_LIVE_A"), os.Getenv("BENCCHAT_LIVE_A_PW")
	if addr == "" {
		t.Skip("set BENCCHAT_LIVE_SERVER")
	}
	bName, bPw := os.Getenv("BENCCHAT_LIVE_B"), os.Getenv("BENCCHAT_LIVE_B_PW")
	if aName == "" || aPw == "" || bName == "" || bPw == "" {
		t.Skip("set BENCCHAT_LIVE_A/_PW and BENCCHAT_LIVE_B/_PW")
	}
	ctx := context.Background()

	// B auto-approves any incoming connection request.
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

	// Clean slate, then add + get approved.
	_ = a.RemoveBuddy(bName)
	time.Sleep(500 * time.Millisecond)
	if err := a.AddBuddy(bName, "Buddies"); err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}

	connected := func() bool {
		for _, x := range a.store.Buddies() {
			if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
				return !x.Pending
			}
		}
		return false
	}
	for i := 0; i < 24 && !connected(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if !connected() {
		t.Fatalf("never became connected to %s (still pending/absent)", bName)
	}
	// Let the add/accept/clear-pending dance fully settle before moving, so a
	// stale pending tag can't ride along.
	time.Sleep(2500 * time.Millisecond)
	for _, x := range a.store.Buddies() {
		if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
			t.Logf("BEFORE move: group=%q pending=%v", x.Group, x.Pending)
		}
	}
	t.Logf("connected to %s; moving to a new group", bName)

	// Move from a FRESH session, which loads the clean server state (pending=false)
	// — exactly the user's scenario, not the stuck-pending local state on A.
	fresh := New(state.NewStore(), nil)
	if err := fresh.SignOn(ctx, addr, oscar.Credentials{ScreenName: aName, Password: aPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn fresh: %v", err)
	}
	defer func() { _ = fresh.SignOff() }()
	time.Sleep(900 * time.Millisecond)
	for _, x := range fresh.store.Buddies() {
		if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
			t.Logf("FRESH before move: group=%q pending=%v", x.Group, x.Pending)
		}
	}

	const newGroup = "MoveProbe"
	if err := fresh.MoveBuddy(bName, newGroup); err != nil {
		t.Errorf("MoveBuddy error: %v", err)
	}
	if err := fresh.RenameBuddy(bName, "Renamed Probe"); err != nil {
		t.Errorf("RenameBuddy error: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	for _, x := range fresh.store.Buddies() {
		if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
			t.Logf("FRESH local after: group=%q alias=%q pending=%v", x.Group, x.Alias, x.Pending)
		}
	}

	// Server truth via a fresh session.
	c := New(state.NewStore(), nil)
	if err := c.SignOn(ctx, addr, oscar.Credentials{ScreenName: aName, Password: aPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn C: %v", err)
	}
	defer func() { _ = c.SignOff() }()
	time.Sleep(800 * time.Millisecond)
	found := false
	for _, x := range c.store.Buddies() {
		if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
			found = true
			t.Logf("SERVER (fresh session): group=%q alias=%q pending=%v", x.Group, x.Alias, x.Pending)
			if x.Group != newGroup {
				t.Errorf("server did NOT store the move: group=%q want %q", x.Group, newGroup)
			}
			if x.Alias != "Renamed Probe" {
				t.Errorf("server did NOT store the rename: alias=%q", x.Alias)
			}
		}
	}
	if !found {
		t.Errorf("buddy VANISHED from the server after move (severed?)")
	}

	// Rename the group live, then confirm the buddy's group follows on the server.
	if err := fresh.RenameGroup(newGroup, "MoveProbe2"); err != nil {
		t.Errorf("RenameGroup error: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	d := New(state.NewStore(), nil)
	if err := d.SignOn(ctx, addr, oscar.Credentials{ScreenName: aName, Password: aPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn D: %v", err)
	}
	defer func() { _ = d.SignOff() }()
	time.Sleep(800 * time.Millisecond)
	for _, x := range d.store.Buddies() {
		if state.NormalizeScreenName(x.ScreenName) == state.NormalizeScreenName(bName) {
			t.Logf("SERVER after rename: group=%q", x.Group)
			if x.Group != "MoveProbe2" {
				t.Errorf("group rename didn't persist: group=%q want MoveProbe2", x.Group)
			}
		}
	}

	// Remove the buddy; its now-empty custom group should be pruned server-side.
	_ = fresh.RemoveBuddy(bName)
	time.Sleep(1200 * time.Millisecond)
	e := New(state.NewStore(), nil)
	if err := e.SignOn(ctx, addr, oscar.Credentials{ScreenName: aName, Password: aPw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn E: %v", err)
	}
	defer func() { _ = e.SignOff() }()
	time.Sleep(800 * time.Millisecond)
	for _, g := range e.Groups() {
		if g.Name == "MoveProbe2" {
			t.Errorf("emptied custom group %q was NOT pruned server-side", g.Name)
		}
	}
	t.Logf("groups after cleanup: %+v", e.Groups())
}
