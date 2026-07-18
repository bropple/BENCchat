package wire

// FLAP is OSCAR's outer framing layer. Every byte on the wire lives inside a
// FLAP frame:
//
//	+------------+-----------+------------------+------------------+
//	| 0x2A (1B)  | type (1B) | sequence (2B BE) | payload len (2B) | payload...
//	+------------+-----------+------------------+------------------+
//
// The sequence number increments per frame sent on a connection. A subtly
// wrong length here manifests as a hung socket, not a clean error, so this
// layer must be exactly right before anything is layered on top (CLAUDE.md).

// FLAP frame types.
const (
	FLAPFrameSignon    uint8 = 0x01
	FLAPFrameData      uint8 = 0x02
	FLAPFrameError     uint8 = 0x03
	FLAPFrameSignoff   uint8 = 0x04
	FLAPFrameKeepAlive uint8 = 0x05
)

// FLAPStartMarker is the constant first byte of every FLAP frame (ASCII '*').
const FLAPStartMarker uint8 = 0x2A

// FLAPMaxDataSize is the largest payload a single FLAP frame may carry.
const FLAPMaxDataSize uint32 = 0xFFF9

// FLAPFrame is a single framed message. Payload is length-prefixed with a
// uint16 on the wire.
type FLAPFrame struct {
	StartMarker uint8
	FrameType   uint8
	Sequence    uint16
	Payload     []byte `oscar:"len_prefix=uint16"`
}

// FLAPSignonFrame is the payload of the initial sign-on handshake: a FLAP
// version (always 1) followed by the rest of the TLVs.
type FLAPSignonFrame struct {
	FLAPVersion uint32
	TLVRestBlock
}
