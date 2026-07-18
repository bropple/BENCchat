package wire

import (
	"bytes"
	"testing"
)

// marshalBE is a tiny helper: marshal v and return the bytes, failing the test
// on error.
func marshalBE(t *testing.T, v any) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := MarshalBE(v, buf); err != nil {
		t.Fatalf("MarshalBE(%T): %v", v, err)
	}
	return buf.Bytes()
}

func TestMarshalTLV(t *testing.T) {
	// tag 0x0001, value "toof" -> tag(2) len(2) "toof"
	got := marshalBE(t, TLV{Tag: 0x0001, Value: []byte("toof")})
	want := []byte{0x00, 0x01, 0x00, 0x04, 't', 'o', 'o', 'f'}
	if !bytes.Equal(got, want) {
		t.Fatalf("TLV bytes:\n got %x\nwant %x", got, want)
	}
}

func TestMarshalFLAPFrameRoundTrip(t *testing.T) {
	in := FLAPFrame{
		StartMarker: FLAPStartMarker,
		FrameType:   FLAPFrameData,
		Sequence:    0x1234,
		Payload:     []byte{0xAA, 0xBB},
	}
	got := marshalBE(t, in)
	want := []byte{0x2A, 0x02, 0x12, 0x34, 0x00, 0x02, 0xAA, 0xBB}
	if !bytes.Equal(got, want) {
		t.Fatalf("FLAP bytes:\n got %x\nwant %x", got, want)
	}

	var out FLAPFrame
	if err := UnmarshalBE(&out, bytes.NewReader(got)); err != nil {
		t.Fatalf("UnmarshalBE FLAP: %v", err)
	}
	if out.StartMarker != in.StartMarker || out.FrameType != in.FrameType ||
		out.Sequence != in.Sequence || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("FLAP round trip mismatch: got %+v want %+v", out, in)
	}
}

func TestMarshalSNACFrame(t *testing.T) {
	got := marshalBE(t, SNACFrame{
		FoodGroup: BUCP,
		SubGroup:  BUCPChallengeRequest,
		Flags:     0x0000,
		RequestID: 0x00000001,
	})
	want := []byte{0x00, 0x17, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("SNAC frame bytes:\n got %x\nwant %x", got, want)
	}
}

func TestMarshalSignonFrameNoTLVs(t *testing.T) {
	// FLAPVersion(4) = 1, no TLVs.
	got := marshalBE(t, FLAPSignonFrame{FLAPVersion: 1})
	want := []byte{0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("signon frame:\n got %x\nwant %x", got, want)
	}
}

func TestMarshalLenPrefixedString(t *testing.T) {
	// BUCP challenge response is a single uint16-length-prefixed string.
	got := marshalBE(t, SNAC_0x17_0x07_BUCPChallengeResponse{AuthKey: "key"})
	want := []byte{0x00, 0x03, 'k', 'e', 'y'}
	if !bytes.Equal(got, want) {
		t.Fatalf("authkey:\n got %x\nwant %x", got, want)
	}

	var out SNAC_0x17_0x07_BUCPChallengeResponse
	if err := UnmarshalBE(&out, bytes.NewReader(got)); err != nil {
		t.Fatalf("unmarshal authkey: %v", err)
	}
	if out.AuthKey != "key" {
		t.Fatalf("authkey round trip: got %q want %q", out.AuthKey, "key")
	}
}

func TestMarshalTLVRestBlockRoundTrip(t *testing.T) {
	in := TLVRestBlock{TLVList: TLVList{
		NewTLVBE(LoginTLVTagsScreenName, []byte("R.Triy")),
		NewTLVBE(LoginTLVTagsMultiConnFlags, uint8(0x01)),
	}}
	got := marshalBE(t, in)
	// screenname TLV: 00 01 00 06 "R.Triy"; multiconn TLV: 00 4a 00 01 01
	want := []byte{
		0x00, 0x01, 0x00, 0x06, 'R', '.', 'T', 'r', 'i', 'y',
		0x00, 0x4A, 0x00, 0x01, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rest block:\n got %x\nwant %x", got, want)
	}

	var out TLVRestBlock
	if err := UnmarshalBE(&out, bytes.NewReader(got)); err != nil {
		t.Fatalf("unmarshal rest block: %v", err)
	}
	if len(out.TLVList) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(out.TLVList))
	}
	if name, _ := out.String(LoginTLVTagsScreenName); name != "R.Triy" {
		t.Fatalf("screen name: got %q", name)
	}
	if flag := out.TLVList[1].Uint8(); flag != 0x01 {
		t.Fatalf("multiconn flag: got %d", flag)
	}
}

func TestMarshalTLVBlockCountPrefix(t *testing.T) {
	in := TLVBlock{TLVList: TLVList{NewTLVBE(0x0001, []byte("a"))}}
	got := marshalBE(t, in)
	// count=1 then TLV(tag 0x0001, len 1, "a")
	want := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 'a'}
	if !bytes.Equal(got, want) {
		t.Fatalf("count-prefixed block:\n got %x\nwant %x", got, want)
	}
}

func TestMarshalTLVLBlockLenPrefix(t *testing.T) {
	in := TLVLBlock{TLVList: TLVList{NewTLVBE(0x0001, []byte("a"))}}
	got := marshalBE(t, in)
	// inner bytes = tag(2)+len(2)+val(1) = 5, so length prefix 0x0005
	want := []byte{0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 'a'}
	if !bytes.Equal(got, want) {
		t.Fatalf("len-prefixed block:\n got %x\nwant %x", got, want)
	}
}

func TestWeakMD5PasswordHash(t *testing.T) {
	// Known-answer vector: md5("abc123" + "password123" + magic).
	got := WeakMD5PasswordHash("password123", "abc123")
	want := []byte{0xa0, 0x67, 0x52, 0x1c, 0x3d, 0x2b, 0x3d, 0xa4,
		0xfa, 0x1e, 0x52, 0xfe, 0x23, 0xb0, 0xb1, 0x20}
	if !bytes.Equal(got, want) {
		t.Fatalf("weak md5:\n got %x\nwant %x", got, want)
	}
}

func TestStrongMD5PasswordHash(t *testing.T) {
	// Known-answer vector: md5("abc123" + md5("password123") + magic).
	got := StrongMD5PasswordHash("password123", "abc123")
	want := []byte{0x9e, 0x78, 0xb9, 0x49, 0xde, 0xc5, 0x1b, 0x12,
		0x68, 0xc8, 0xa8, 0x4d, 0x2a, 0xf1, 0xb8, 0x27}
	if !bytes.Equal(got, want) {
		t.Fatalf("strong md5:\n got %x\nwant %x", got, want)
	}
}
