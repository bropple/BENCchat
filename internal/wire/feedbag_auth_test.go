package wire

import (
	"bytes"
	"testing"
)

// TestRespondAuthorizeToHostEncoding pins the byte layout of the approve/decline
// SNAC the client sends (0x13,0x1A): a uint8-prefixed screen name, a single
// Accepted byte, then a uint16-prefixed reason.
func TestRespondAuthorizeToHostEncoding(t *testing.T) {
	snac := SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
		ScreenName: "requester",
		Accepted:   1,
		Reason:     "",
	}
	buf := &bytes.Buffer{}
	if err := MarshalBE(snac, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x09, 'r', 'e', 'q', 'u', 'e', 's', 't', 'e', 'r', // uint8-prefixed name
		0x01,       // accepted
		0x00, 0x00, // uint16-prefixed reason (empty)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("0x1A encoding:\n got %x\nwant %x", buf.Bytes(), want)
	}
}

// TestRequestAuthorizeToClientRoundTrip round-trips the inbound "X wants to
// connect" SNAC (0x13,0x19), including its leading extended-info block.
func TestRequestAuthorizeToClientRoundTrip(t *testing.T) {
	in := SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
		ScreenName: "alice",
		Reason:     "hi there",
	}
	in.Append(NewTLVBE(uint16(0x0001), uint16(2))) // SSI version TLV, as the server sends

	buf := &bytes.Buffer{}
	if err := MarshalBE(in, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient
	if err := UnmarshalBE(&out, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ScreenName != "alice" || out.Reason != "hi there" {
		t.Fatalf("round trip: got %+v", out)
	}
}

// TestRespondAuthorizeToClientHasNullterm guards the one place the real server
// diverged from the task spec: 0x13,0x1B carries a trailing uint16 (Nullterm)
// after the reason. Marshalling it must emit those two bytes.
func TestRespondAuthorizeToClientHasNullterm(t *testing.T) {
	in := SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
		ScreenName: "bob",
		Accepted:   1,
	}
	buf := &bytes.Buffer{}
	if err := MarshalBE(in, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x00, 0x00, // empty extended-info block (TLVLBlock)
		0x03, 'b', 'o', 'b', // uint8-prefixed name
		0x01,       // accepted
		0x00, 0x00, // uint16-prefixed reason (empty)
		0x00, 0x00, // Nullterm
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("0x1B encoding:\n got %x\nwant %x", buf.Bytes(), want)
	}
}
