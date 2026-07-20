package client

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/wire"
)

// stripExtInfo removes the leading extended-info TLVLBlock, mirroring what the
// transport does before dispatch to a handler.
func stripExtInfo(t *testing.T, body []byte) []byte {
	t.Helper()
	n := int(body[0])<<8 | int(body[1])
	return body[2+n:]
}

// TestIncomingConnectionRequestFiresHandler routes an inbound 0x19 through
// handleSNAC and checks the registered handler sees the requester.
func TestIncomingConnectionRequestFiresHandler(t *testing.T) {
	c, _ := newTestClient(t)

	var got oscar.ConnectionRequest
	c.SetConnectionRequestHandler(func(req oscar.ConnectionRequest) { got = req })

	snac := wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
		ScreenName: "alice",
		Reason:     "hey",
	}
	snac.Append(wire.NewTLVBE(uint16(0x0001), uint16(2)))
	body := stripExtInfo(t, marshal(t, snac))

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRequestAuthorizeToClient},
		body,
	)

	if got.ScreenName != "alice" || got.Reason != "hey" {
		t.Fatalf("handler got %+v", got)
	}
}

// TestIncomingConnectionResponseFiresHandler routes an inbound 0x1B accept
// through handleSNAC and checks the handler sees the acceptance.
func TestIncomingConnectionResponseFiresHandler(t *testing.T) {
	c, _ := newTestClient(t)

	var got oscar.ConnectionResponse
	c.SetConnectionResponseHandler(func(res oscar.ConnectionResponse) { got = res })

	snac := wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
		ScreenName: "bob",
		Accepted:   1,
	}
	snac.Append(wire.NewTLVBE(uint16(0x0001), uint16(2)))
	body := stripExtInfo(t, marshal(t, snac))

	c.handleSNAC(
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRespondAuthorizeToClient},
		body,
	)

	if got.ScreenName != "bob" || !got.Accepted {
		t.Fatalf("handler got %+v", got)
	}
}
