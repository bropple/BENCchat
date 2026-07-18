package oscar

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// bosFoodGroups mirrors what open-oscar-server advertises on a BOS connection.
var bosFoodGroups = []uint16{
	0x0018, 0x0010, wire.Buddy, wire.Feedbag, wire.ICBM,
	0x0015, wire.Locate, wire.OService, 0x0009, 0x000A, 0x0006, 0x0008, 0x000B,
}

// TestHandshakeThroughRateParams drives the OSERVICE handshake against a
// scripted server, including the unsolicited MOTD the real server interleaves
// between HostVersions and the rate-params exchange.
func TestHandshakeThroughRateParams(t *testing.T) {
	client, fs := newFakeServer(t)
	cookie := testCookie()

	s := &Session{conn: client, screenName: "Triy", closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.handshake(cookie) }()

	fs.hello()

	// The BOS signon frame must present the cookie verbatim under TLV 0x06.
	sf := fs.expectSignon()
	got, ok := sf.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		t.Fatal("BOS signon frame missing auth cookie TLV 0x06")
	}
	if !bytes.Equal(got, cookie) {
		t.Fatalf("cookie must be presented verbatim: got %d bytes, want %d", len(got), len(cookie))
	}

	fs.send(wire.OService, wire.OServiceHostOnline,
		wire.SNAC_0x01_0x03_OServiceHostOnline{FoodGroups: bosFoodGroups})

	// ClientVersions must hold an even number of elements — an odd list makes the
	// real server reply with nothing at all and stall sign-on.
	var cv wire.SNAC_0x01_0x17_OServiceClientVersions
	if err := wire.UnmarshalBE(&cv, bytes.NewReader(fs.expectSNAC(wire.OService, wire.OServiceClientVersions))); err != nil {
		t.Fatalf("decode client versions: %v", err)
	}
	if len(cv.Versions) == 0 || len(cv.Versions)%2 != 0 {
		t.Fatalf("client versions must be non-empty (foodgroup, version) pairs, got %v", cv.Versions)
	}
	fs.send(wire.OService, wire.OServiceHostVersions,
		wire.SNAC_0x01_0x18_OServiceHostVersions{Versions: cv.Versions})

	// The real server pushes MOTD unsolicited here; the client must skip it
	// rather than treat it as a protocol violation.
	motd := wire.SNAC_0x01_0x13_OServiceMOTD{MessageType: 0x0004}
	motd.Append(wire.NewTLVBE(wire.OServiceTLVTagsMOTDMessage, []byte("Welcome to Open OSCAR Server")))
	fs.send(wire.OService, 0x0013, motd)

	fs.expectSNAC(wire.OService, wire.OServiceRateParamsQuery)
	fs.send(wire.OService, wire.OServiceRateParamsReply, wire.TLVRestBlock{})

	if err := <-done; err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if len(s.FoodGroups()) != len(bosFoodGroups) {
		t.Errorf("FoodGroups() = %d entries, want %d", len(s.FoodGroups()), len(bosFoodGroups))
	}
}

// TestLoadBuddyListSendsUseBeforeGoingOnline pins the ordering that sign-on
// depends on: FeedbagQuery, then FeedbagUse (which marks contacts initialized),
// and only then ClientOnline. Getting this backwards fails silently — you sign
// on fine and simply never see anyone come online.
func TestLoadBuddyListSendsUseBeforeGoingOnline(t *testing.T) {
	client, fs := newFakeServer(t)
	s := &Session{conn: client, screenName: "Triy", closed: make(chan struct{})}

	type result struct {
		list BuddyList
		err  error
	}
	done := make(chan result, 1)
	go func() {
		list, err := s.LoadBuddyList()
		if err == nil {
			err = s.goOnline()
		}
		done <- result{list, err}
	}()

	fs.expectSNAC(wire.Feedbag, wire.FeedbagQuery)
	fs.send(wire.Feedbag, wire.FeedbagReply, wire.SNAC_0x13_0x06_FeedbagReply{
		Items: []wire.FeedbagItem{
			rootItem(1),
			groupItem(1, "BENCO", 10),
			buddyItem(1, 10, "rtriy"),
		},
		LastUpdate: 1234,
	})

	// FeedbagUse must arrive BEFORE ClientOnline.
	fs.expectSNAC(wire.Feedbag, wire.FeedbagUse)
	fs.expectSNAC(wire.OService, wire.OServiceClientOnline)

	got := <-done
	if got.err != nil {
		t.Fatalf("LoadBuddyList/goOnline: %v", got.err)
	}
	if len(got.list.Buddies) != 1 || got.list.Buddies[0].ScreenName != "rtriy" {
		t.Fatalf("buddy list = %+v, want one buddy rtriy", got.list.Buddies)
	}
}

// TestHandshakeFailsOnFoodgroupError ensures an error SNAC in the foodgroup we
// are waiting on ends the handshake instead of hanging until the budget runs out.
func TestHandshakeFailsOnFoodgroupError(t *testing.T) {
	client, fs := newFakeServer(t)

	s := &Session{conn: client, closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.handshake(testCookie()) }()

	fs.hello()
	fs.expectSignon()
	fs.send(wire.OService, wire.OServiceErr, wire.TLVRestBlock{})

	if err := <-done; err == nil {
		t.Fatal("expected handshake to fail on an OSERVICE error SNAC")
	}
}

func TestSignOnRejectsExpiredCookie(t *testing.T) {
	// A stale cookie is rejected by a bare connection close with no diagnostic
	// frame, so catching it client-side turns a confusing network-looking fault
	// into a clear error.
	res := &LoginResult{BOSAddress: "127.0.0.1:1", Cookie: testCookie()}
	if _, err := SignOn(context.Background(), res); err == nil {
		t.Fatal("expected SignOn to reject an expired cookie before dialing")
	}
}

// TestRunStopsOnContextCancel guards the fix for a real bug: Run blocks on the
// socket read, so a cancelled context must actively unblock it. Before the fix,
// cancelling ctx left Run spinning until the peer closed the connection.
func TestRunStopsOnContextCancel(t *testing.T) {
	client, fs := newFakeServer(t)
	_ = fs // server end stays silent; nothing is ever sent
	s := &Session{conn: client, closed: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Give the read loop a moment to block, then cancel.
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation (still blocked on read)")
	}
}

func TestNextReqIDNeverSetsServerBit(t *testing.T) {
	// The high bit marks server-initiated SNACs; client IDs must stay below it.
	s := &Session{reqID: wire.ReqIDFromServer - 1}
	for i := 0; i < 3; i++ {
		if id := s.nextReqID(); id&wire.ReqIDFromServer != 0 {
			t.Fatalf("nextReqID returned 0x%08x with the server bit set", id)
		}
	}
}
