package oscar

import (
	"bytes"
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

// stripExtInfo mirrors what the transport's DecodeSNAC does to a SNAC that
// carries the extended-info flag: it removes the leading TLVLBlock, leaving the
// body the decode helpers actually receive.
func stripExtInfo(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) < 2 {
		t.Fatalf("body too short to strip ext-info: %x", body)
	}
	n := int(body[0])<<8 | int(body[1])
	return body[2+n:]
}

func marshalSNAC(t *testing.T, v any) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(v, buf); err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return buf.Bytes()
}

// TestDecodeConnectionRequest decodes an inbound 0x19 the way it arrives after
// the transport has stripped the extended-info block.
func TestDecodeConnectionRequest(t *testing.T) {
	snac := wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
		ScreenName: "alice",
		Reason:     "let me in",
	}
	snac.Append(wire.NewTLVBE(uint16(0x0001), uint16(2)))
	body := stripExtInfo(t, marshalSNAC(t, snac))

	req, err := DecodeConnectionRequest(body)
	if err != nil {
		t.Fatalf("DecodeConnectionRequest: %v", err)
	}
	if req.ScreenName != "alice" || req.Reason != "let me in" {
		t.Fatalf("got %+v", req)
	}
}

// TestDecodeConnectionResponse decodes an inbound 0x1B accept.
func TestDecodeConnectionResponse(t *testing.T) {
	snac := wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
		ScreenName: "bob",
		Accepted:   1,
	}
	snac.Append(wire.NewTLVBE(uint16(0x0001), uint16(2)))
	body := stripExtInfo(t, marshalSNAC(t, snac))

	res, err := DecodeConnectionResponse(body)
	if err != nil {
		t.Fatalf("DecodeConnectionResponse: %v", err)
	}
	if res.ScreenName != "bob" || !res.Accepted {
		t.Fatalf("got %+v", res)
	}
}

// testSession builds a Session wired to a fake server, with an editable feedbag,
// so edit/authorization SNACs can be sent and read back.
func testSession(t *testing.T, items []wire.FeedbagItem) (*Session, *fakeServer) {
	t.Helper()
	client, fs := newFakeServer(t)
	s := &Session{conn: client, feedbag: NewFeedbag(items), closed: make(chan struct{})}
	return s, fs
}

// TestRespondAuthorizationSendsToHost checks the approve/decline SNAC (0x1A).
func TestRespondAuthorizationSendsToHost(t *testing.T) {
	s, fs := testSession(t, nil)

	done := make(chan error, 1)
	go func() { done <- s.RespondAuthorization("requester", true, "") }()

	body := fs.expectSNAC(wire.Feedbag, wire.FeedbagRespondAuthorizeToHost)
	if err := <-done; err != nil {
		t.Fatalf("RespondAuthorization: %v", err)
	}
	var out wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost
	if err := wire.UnmarshalBE(&out, bytes.NewReader(body)); err != nil {
		t.Fatalf("decode 0x1A: %v", err)
	}
	if out.ScreenName != "requester" || out.Accepted != 1 {
		t.Fatalf("got %+v", out)
	}
}

// TestApproveConnectionReciprocalAdd is the behavioral departure: approving a
// request also adds the requester back as a buddy. The client must send the
// 0x1A approval AND a feedbag insert naming the requester.
func TestApproveConnectionReciprocalAdd(t *testing.T) {
	s, fs := testSession(t, nil)

	done := make(chan error, 1)
	go func() {
		_, err := s.ApproveConnection("requester", "")
		done <- err
	}()

	// First the approval.
	resp := fs.expectSNAC(wire.Feedbag, wire.FeedbagRespondAuthorizeToHost)
	var respBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost
	if err := wire.UnmarshalBE(&respBody, bytes.NewReader(resp)); err != nil {
		t.Fatalf("decode 0x1A: %v", err)
	}
	if respBody.Accepted != 1 {
		t.Fatalf("approval must set Accepted=1, got %d", respBody.Accepted)
	}

	// Then the reciprocal add: an insert that stores the requester as a buddy.
	ins := fs.expectSNAC(wire.Feedbag, wire.FeedbagInsertItem)
	var insBody wire.SNAC_0x13_0x08_FeedbagInsertItem
	if err := wire.UnmarshalBE(&insBody, bytes.NewReader(ins)); err != nil {
		t.Fatalf("decode insert: %v", err)
	}
	var found bool
	for _, it := range insBody.Items {
		if it.IsBuddy() && normName(it.Name) == "requester" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reciprocal add did not insert 'requester' as a buddy: %+v", insBody.Items)
	}
	if err := <-done; err != nil {
		t.Fatalf("ApproveConnection: %v", err)
	}
}

// TestPendingReAddAfterAuthRequired exercises the flow behind
// FeedbagStatusAuthRequired: a tracked add is correlated by request ID, then
// re-added with the pending tag so the server keeps a pending row and the buddy
// reads as Pending.
func TestPendingReAddAfterAuthRequired(t *testing.T) {
	s, fs := testSession(t, nil)

	// Add the buddy; capture the insert's request ID the way the server would.
	addDone := make(chan error, 1)
	go func() {
		_, err := s.AddBuddy("target", "")
		addDone <- err
	}()
	frame, _, err := fs.c.ReadSNAC()
	if err != nil {
		t.Fatalf("read insert: %v", err)
	}
	if frame.FoodGroup != wire.Feedbag || frame.SubGroup != wire.FeedbagInsertItem {
		t.Fatalf("expected insert, got 0x%04x/0x%04x", frame.FoodGroup, frame.SubGroup)
	}
	if err := <-addDone; err != nil {
		t.Fatalf("AddBuddy: %v", err)
	}

	// The request ID must map back to the buddy we added.
	name, ok := s.TakeAuthTarget(frame.RequestID)
	if !ok || normName(name) != "target" {
		t.Fatalf("TakeAuthTarget(%d) = %q,%v; want target", frame.RequestID, name, ok)
	}
	// Taking it again must fail — it is consumed.
	if _, ok := s.TakeAuthTarget(frame.RequestID); ok {
		t.Fatal("auth target should be consumed after TakeAuthTarget")
	}

	// Re-add with the pending tag.
	reAddDone := make(chan struct {
		bl  BuddyList
		err error
	}, 1)
	go func() {
		bl, err := s.ReAddBuddyPending(name)
		reAddDone <- struct {
			bl  BuddyList
			err error
		}{bl, err}
	}()
	ins := fs.expectSNAC(wire.Feedbag, wire.FeedbagInsertItem)
	var insBody wire.SNAC_0x13_0x08_FeedbagInsertItem
	if err := wire.UnmarshalBE(&insBody, bytes.NewReader(ins)); err != nil {
		t.Fatalf("decode pending insert: %v", err)
	}
	var pendingSent bool
	for _, it := range insBody.Items {
		if it.IsBuddy() && normName(it.Name) == "target" && it.HasTag(wire.FeedbagAttributesPending) {
			pendingSent = true
		}
	}
	if !pendingSent {
		t.Fatalf("pending re-add did not carry the pending tag: %+v", insBody.Items)
	}

	got := <-reAddDone
	if got.err != nil {
		t.Fatalf("ReAddBuddyPending: %v", got.err)
	}
	b, ok := findBuddyEntry(got.bl, "target")
	if !ok || !b.Pending {
		t.Fatalf("buddy should read as Pending after re-add: %+v", b)
	}

	// Clearing pending (as on an accept) drops the marker.
	cleared := s.ClearBuddyPending("target")
	if b, ok := findBuddyEntry(cleared, "target"); !ok || b.Pending {
		t.Fatalf("ClearBuddyPending should clear the marker: %+v", b)
	}
}
