package client

import (
	"context"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// TestLiveDumpBuddies prints an account's buddy list and blocked list. Read-only:
// useful for checking a probe's preconditions before trusting its verdict (e.g.
// "the gate is absent" really meaning "these two are legitimately connected").
//
//	BENCCHAT_LIVE_SERVER=aim.benco.lol:5191 BENCCHAT_LIVE_TLS=1 \
//	BENCCHAT_LIVE_SCREENNAME=cmaximus2 BENCCHAT_LIVE_PASSWORD=... \
//	go test ./internal/client/ -run TestLiveDumpBuddies -v
func TestLiveDumpBuddies(t *testing.T) {
	addr, sn, pw := liveCreds(t)

	c := New(state.NewStore(), nil)
	if err := c.SignOn(context.Background(), addr,
		oscar.Credentials{ScreenName: sn, Password: pw}, liveTransport(t)...); err != nil {
		t.Fatalf("SignOn: %v", err)
	}
	defer func() { _ = c.SignOff() }()
	time.Sleep(900 * time.Millisecond)

	buddies := c.store.Buddies()
	t.Logf("%s has %d buddies:", sn, len(buddies))
	for _, b := range buddies {
		t.Logf("  %-16s group=%-12q pending=%-5v blocked=%-5v presence=%s",
			b.ScreenName, b.Group, b.Pending, b.Blocked, b.Presence)
	}
	t.Logf("blocked list: %v", c.BlockedUsers())
	t.Logf("groups: %+v", c.Groups())
}
