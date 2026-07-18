package oscar

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// connPair returns a client Conn and the raw server end of a loopback TCP
// connection, so tests can assert on exact bytes without a live server.
//
// This uses real TCP rather than net.Pipe deliberately: net.Pipe is unbuffered
// and synchronous, so any test where both sides write before reading (which the
// real handshake does — the server pushes MOTD unsolicited while the client is
// sending its next request) deadlocks against the harness rather than the code.
// A kernel socket buffer matches production behavior.
func connPair(t *testing.T, startSeq uint16) (*Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accept := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		accept <- accepted{c, err}
	}()

	clientEnd, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-accept
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}

	c := NewConn(clientEnd, startSeq)
	t.Cleanup(func() {
		_ = c.Close()
		_ = a.conn.Close()
	})
	return c, a.conn
}

// readFrom reads exactly n bytes from the server end, failing on timeout.
func readFrom(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

func TestWriteFrameStampsSequence(t *testing.T) {
	c, server := connPair(t, 0)

	// Three frames should carry strictly consecutive sequence numbers. The
	// counter is pre-incremented, so a startSeq of 0 puts the first frame at 1.
	go func() {
		for i := 0; i < 3; i++ {
			_ = c.WriteFrame(wire.FLAPFrameData, []byte{byte(i)})
		}
	}()

	for i := 0; i < 3; i++ {
		got := readFrom(t, server, 7)
		want := []byte{0x2A, 0x02, 0x00, byte(i + 1), 0x00, 0x01, byte(i)}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d:\n got %x\nwant %x", i, got, want)
		}
	}
}

func TestWriteFrameSequenceWrapsAtUint16(t *testing.T) {
	// FLAP sequence is a uint16 and wraps to 0 after 0xFFFF. Starting at 0xFFFE
	// puts the two writes at 0xFFFF and 0x0000.
	c, server := connPair(t, 0xFFFE)

	go func() {
		_ = c.WriteFrame(wire.FLAPFrameData, nil)
		_ = c.WriteFrame(wire.FLAPFrameData, nil)
	}()

	first := readFrom(t, server, 6)
	if seq := binaryBE16(first[2:4]); seq != 0xFFFF {
		t.Fatalf("first frame seq = 0x%04x, want 0xFFFF", seq)
	}
	second := readFrom(t, server, 6)
	if seq := binaryBE16(second[2:4]); seq != 0x0000 {
		t.Fatalf("second frame seq = 0x%04x, want 0x0000 (wraparound)", seq)
	}
}

func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	c, _ := connPair(t, 0)
	err := c.WriteFrame(wire.FLAPFrameData, make([]byte, wire.FLAPMaxDataSize+1))
	if err == nil {
		t.Fatal("expected oversize payload to be rejected before hitting the wire")
	}
}

func TestReadFrameRejectsBadStartMarker(t *testing.T) {
	c, server := connPair(t, 0)

	// A FLAP stream cannot be resynchronized, so a bad marker must be terminal.
	go func() { _, _ = server.Write([]byte{0xFF, 0x02, 0x00, 0x01, 0x00, 0x00}) }()

	if _, err := c.ReadFrame(); err == nil {
		t.Fatal("expected error on bad start marker")
	}
}

func TestReadFrameReturnsEOFOnPeerClose(t *testing.T) {
	c, server := connPair(t, 0)
	go func() { _ = server.Close() }()

	// A clean peer close must surface as io.EOF, not a decode failure, so the
	// session layer can tell "signed off" from "malformed frame".
	if _, err := c.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrame after peer close: got %v, want io.EOF", err)
	}
}

// TestReadSignonFrameMatchesLiveServer replays the exact bytes oscar.example.com
// sends on connect: FLAP signon, seq 100, payload = version 1, no TLVs.
func TestReadSignonFrameMatchesLiveServer(t *testing.T) {
	c, server := connPair(t, 0)

	go func() {
		_, _ = server.Write([]byte{0x2A, 0x01, 0x00, 0x64, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01})
	}()

	sf, err := c.ReadSignonFrame()
	if err != nil {
		t.Fatalf("ReadSignonFrame: %v", err)
	}
	if sf.FLAPVersion != 1 {
		t.Fatalf("FLAPVersion = %d, want 1", sf.FLAPVersion)
	}
	if len(sf.TLVList) != 0 {
		t.Fatalf("expected no TLVs in server hello, got %d", len(sf.TLVList))
	}
}

func TestWriteSignonFrameCarriesTLVs(t *testing.T) {
	c, server := connPair(t, 0)

	go func() {
		_ = c.WriteSignonFrame([]wire.TLV{wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("triy"))})
	}()

	// 6B FLAP header + 4B version + 4B TLV header + 4B "triy"
	got := readFrom(t, server, 18)
	want := []byte{
		0x2A, 0x01, 0x00, 0x01, 0x00, 0x0C, // FLAP: signon, seq 1, len 12
		0x00, 0x00, 0x00, 0x01, // FLAP version 1
		0x00, 0x01, 0x00, 0x04, 't', 'r', 'i', 'y', // TLV 0x01 = "triy"
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("signon frame:\n got %x\nwant %x", got, want)
	}
}

func TestWriteSNACRoundTrip(t *testing.T) {
	c, server := connPair(t, 0)

	in := wire.SNACFrame{
		FoodGroup: wire.BUCP,
		SubGroup:  wire.BUCPChallengeRequest,
		RequestID: 0x11223344,
	}
	body := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
	body.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("triy")))

	go func() { _ = c.WriteSNAC(in, body) }()

	hdr := readFrom(t, server, 6)
	if hdr[1] != wire.FLAPFrameData {
		t.Fatalf("frame type = 0x%02x, want data (0x02)", hdr[1])
	}
	payload := readFrom(t, server, int(binaryBE16(hdr[4:6])))

	gotFrame, gotBody, err := DecodeSNAC(payload)
	if err != nil {
		t.Fatalf("DecodeSNAC: %v", err)
	}
	if gotFrame != in {
		t.Fatalf("SNAC header round trip: got %+v, want %+v", gotFrame, in)
	}

	var decoded wire.SNAC_0x17_0x06_BUCPChallengeRequest
	if err := wire.UnmarshalBE(&decoded, bytes.NewReader(gotBody)); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sn, ok := decoded.String(wire.LoginTLVTagsScreenName); !ok || sn != "triy" {
		t.Fatalf("screen name TLV = %q (found=%v), want \"triy\"", sn, ok)
	}
}

func TestDecodeSNACSkipsExtendedInfoBlock(t *testing.T) {
	// With SNACFlagsExtendedInfo set, a uint16-length-prefixed block sits between
	// the header and the body; DecodeSNAC must skip it so the caller sees only
	// the body it expects.
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(wire.SNACFrame{
		FoodGroup: wire.OService,
		SubGroup:  wire.OServiceHostOnline,
		Flags:     wire.SNACFlagsExtendedInfo,
	}, buf); err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	buf.Write([]byte{0x00, 0x03, 0xDE, 0xAD, 0xBE}) // extended block: 3 bytes
	buf.Write([]byte{0xCA, 0xFE})                   // real body

	_, body, err := DecodeSNAC(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeSNAC: %v", err)
	}
	if want := []byte{0xCA, 0xFE}; !bytes.Equal(body, want) {
		t.Fatalf("body after skipping extended info: got %x, want %x", body, want)
	}
}

func TestDecodeSNACRejectsOverrunningExtendedInfo(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(wire.SNACFrame{
		FoodGroup: wire.OService,
		SubGroup:  wire.OServiceHostOnline,
		Flags:     wire.SNACFlagsExtendedInfo,
	}, buf); err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	buf.Write([]byte{0xFF, 0xFF, 0x01}) // claims 65535 bytes, has 1

	if _, _, err := DecodeSNAC(buf.Bytes()); err == nil {
		t.Fatal("expected error when extended-info length overruns the body")
	}
}

func binaryBE16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
