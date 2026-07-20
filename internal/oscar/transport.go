// Package oscar is the transport and session layer: it owns the TCP socket,
// FLAP framing, and the SNAC request/response plumbing built on top.
//
// Layering (per CLAUDE.md): this package speaks FLAP/SNAC and nothing else. It
// has no knowledge of the UI, and the UI never reaches through it. The state
// layer sits above and binds to a UI; a headless consumer (R. Triy, Home
// Assistant) can use this package directly.
package oscar

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// ErrClosed is returned by Conn operations after the connection is closed.
var ErrClosed = errors.New("oscar: connection closed")

// ErrSignedOff reports that the peer sent a FLAP signoff frame. This is not
// always a failure: the server deliberately signs off the auth connection right
// after delivering the login response, so the caller decides whether it was
// expected.
var ErrSignedOff = errors.New("oscar: server sent FLAP signoff")

// SignoffError carries the reason TLVs from a BOS signoff frame. The server
// sends one of these when it kicks a session — most commonly because the same
// account signed on elsewhere.
type SignoffError struct {
	Reason uint8  // OServiceDiscErr* (0 if absent)
	Info   string // optional "more info" URL
}

func (e *SignoffError) Error() string {
	if e.Reason == wire.OServiceDiscErrNewLogin {
		return "oscar: signed off — this account signed on from another location"
	}
	if e.Reason != 0 {
		return fmt.Sprintf("oscar: signed off by server (reason 0x%02x)", e.Reason)
	}
	return "oscar: signed off by server"
}

func (e *SignoffError) Unwrap() error { return ErrSignedOff }

// dialTimeout bounds connection setup for both dial paths in Transport.dial.
// For a plaintext dial that is the TCP connect alone; for a TLS one the
// tls.Dialer applies it to the handshake as well, since the deployment is
// TLS-only and a proxy that accepts the socket but never completes the
// handshake would otherwise hang indefinitely.
const dialTimeout = 20 * time.Second

// Conn is a framed OSCAR connection: a TCP socket that reads and writes FLAP
// frames. It is safe for one reader goroutine and concurrent writers — writes
// are serialized because the FLAP sequence number must advance without gaps.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader

	// writeMu guards seq and the socket writes it stamps. FLAP sequence numbers
	// must be strictly consecutive per connection, so incrementing the counter
	// and writing the frame cannot be split across goroutines.
	writeMu sync.Mutex
	seq     uint16

	closeOnce sync.Once
	closed    chan struct{}
}

// NewConn wraps an existing net.Conn. Split out from Transport.dial so tests
// can drive the framing over a net.Pipe without a real server.
//
// startSeq seeds the client's FLAP sequence counter. OSCAR lets each side pick
// its own starting value (the server opens at 100); the two directions are
// independent counters.
func NewConn(c net.Conn, startSeq uint16) *Conn {
	return &Conn{
		conn:   c,
		br:     bufio.NewReader(c),
		seq:    startSeq,
		closed: make(chan struct{}),
	}
}

// Close shuts the socket down. It is safe to call more than once; concurrent
// reads and writes unblock with an error.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.conn.Close()
	})
	return err
}

// ReadFrame reads the next FLAP frame off the wire, blocking until one arrives.
// It returns io.EOF when the peer closes the connection cleanly.
//
// Only one goroutine may call ReadFrame at a time (the session read loop).
func (c *Conn) ReadFrame() (wire.FLAPFrame, error) {
	var f wire.FLAPFrame
	if err := wire.UnmarshalBE(&f, c.br); err != nil {
		// Unwrap to a bare io.EOF so callers can distinguish a clean peer close
		// from a malformed frame; the codec wraps everything in ErrUnmarshalFailure.
		if errors.Is(err, io.EOF) {
			return f, io.EOF
		}
		select {
		case <-c.closed:
			return f, ErrClosed
		default:
		}
		return f, fmt.Errorf("oscar: read FLAP frame: %w", err)
	}
	if f.StartMarker != wire.FLAPStartMarker {
		// Framing is lost — there is no way to resynchronize a FLAP stream, so
		// this is terminal rather than a skippable frame.
		return f, fmt.Errorf("oscar: bad FLAP start marker 0x%02x (stream desynchronized)", f.StartMarker)
	}
	return f, nil
}

// WriteFrame writes a FLAP frame of the given type, stamping it with the next
// sequence number.
func (c *Conn) WriteFrame(frameType uint8, payload []byte) error {
	if uint32(len(payload)) > wire.FLAPMaxDataSize {
		return fmt.Errorf("oscar: FLAP payload %d exceeds max %d", len(payload), wire.FLAPMaxDataSize)
	}

	select {
	case <-c.closed:
		return ErrClosed
	default:
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// The sequence advances per frame sent and wraps naturally at uint16.
	c.seq++
	f := wire.FLAPFrame{
		StartMarker: wire.FLAPStartMarker,
		FrameType:   frameType,
		Sequence:    c.seq,
		Payload:     payload,
	}

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(f, buf); err != nil {
		return fmt.Errorf("oscar: marshal FLAP frame: %w", err)
	}
	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("oscar: write FLAP frame: %w", err)
	}
	return nil
}

// WriteSNAC wraps a SNAC header + body in a FLAP data frame and sends it.
func (c *Conn) WriteSNAC(frame wire.SNACFrame, body any) error {
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(frame, buf); err != nil {
		return fmt.Errorf("oscar: marshal SNAC header (%s): %w", snacName(frame), err)
	}
	if body != nil {
		if err := wire.MarshalBE(body, buf); err != nil {
			return fmt.Errorf("oscar: marshal SNAC body (%s): %w", snacName(frame), err)
		}
	}
	return c.WriteFrame(wire.FLAPFrameData, buf.Bytes())
}

// WriteSignonFrame sends a FLAP sign-on frame (version 1 plus any TLVs). This
// is the first frame the client sends on both the auth and BOS connections.
func (c *Conn) WriteSignonFrame(tlvs []wire.TLV) error {
	f := wire.FLAPSignonFrame{FLAPVersion: 1}
	f.AppendList(tlvs)

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(f, buf); err != nil {
		return fmt.Errorf("oscar: marshal signon frame: %w", err)
	}
	return c.WriteFrame(wire.FLAPFrameSignon, buf.Bytes())
}

// ReadSignonFrame reads a FLAP sign-on frame. The server sends one immediately
// on connect (version 1, no TLVs) before any SNAC traffic.
func (c *Conn) ReadSignonFrame() (wire.FLAPSignonFrame, error) {
	var sf wire.FLAPSignonFrame

	f, err := c.ReadFrame()
	if err != nil {
		return sf, err
	}
	if f.FrameType != wire.FLAPFrameSignon {
		return sf, fmt.Errorf("oscar: expected FLAP signon frame (0x%02x), got 0x%02x", wire.FLAPFrameSignon, f.FrameType)
	}
	if err := wire.UnmarshalBE(&sf, bytes.NewReader(f.Payload)); err != nil {
		return sf, fmt.Errorf("oscar: decode signon frame: %w", err)
	}
	if sf.FLAPVersion != 1 {
		return sf, fmt.Errorf("oscar: unsupported FLAP version %d (want 1)", sf.FLAPVersion)
	}
	return sf, nil
}

// SendSignoff sends a graceful FLAP signoff. Best-effort: the socket is being
// torn down regardless, so the caller does not need to act on an error.
func (c *Conn) SendSignoff() error {
	return c.WriteFrame(wire.FLAPFrameSignoff, nil)
}

// SendKeepAlive sends an empty keepalive frame to hold the connection open
// through NAT/idle timeouts.
func (c *Conn) SendKeepAlive() error {
	return c.WriteFrame(wire.FLAPFrameKeepAlive, nil)
}

// SetReadDeadline bounds the next ReadFrame. A zero time clears the deadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetDeadline bounds both reads and writes. The auth connection has a hard
// 30-second budget server-side, so the client mirrors it rather than hanging.
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// ReadSNAC returns the next SNAC from the connection, transparently skipping
// keepalive frames.
//
// A signoff frame yields a *SignoffError (which unwraps to ErrSignedOff) with
// any reason TLVs decoded. A FLAP error frame is terminal.
func (c *Conn) ReadSNAC() (wire.SNACFrame, []byte, error) {
	for {
		f, err := c.ReadFrame()
		if err != nil {
			return wire.SNACFrame{}, nil, err
		}

		switch f.FrameType {
		case wire.FLAPFrameData:
			return DecodeSNAC(f.Payload)

		case wire.FLAPFrameKeepAlive:
			// Nothing to do: keepalives carry no payload and need no reply.
			continue

		case wire.FLAPFrameSignoff:
			return wire.SNACFrame{}, nil, decodeSignoff(f.Payload)

		case wire.FLAPFrameError:
			return wire.SNACFrame{}, nil, fmt.Errorf("oscar: server sent FLAP error frame (%d bytes)", len(f.Payload))

		default:
			// Unknown frame types are skipped rather than fatal: the wire format
			// long outlived its documentation and an unrecognized frame is not a
			// reason to drop a working session.
			continue
		}
	}
}

// decodeSignoff parses the optional reason TLVs on a signoff frame. A signoff
// with no TLVs (which is what the auth connection sends) yields a bare
// SignoffError.
func decodeSignoff(payload []byte) error {
	e := &SignoffError{}
	if len(payload) == 0 {
		return e
	}

	var tlvs wire.TLVRestBlock
	if err := wire.UnmarshalBE(&tlvs, bytes.NewReader(payload)); err != nil {
		// The connection is going away regardless; an undecodable reason block is
		// not worth surfacing over the signoff itself.
		return e
	}
	if b, ok := tlvs.Bytes(wire.OServiceTLVTagsDisconnectReason); ok && len(b) > 0 {
		e.Reason = b[0]
	}
	if s, ok := tlvs.String(wire.OServiceTLVTagsDisconnectInfo); ok {
		e.Info = s
	}
	return e
}

// snacName renders a SNAC identity for error messages. Decoding a hung OSCAR
// connection is miserable enough without anonymous numbers in the logs.
func snacName(f wire.SNACFrame) string {
	return fmt.Sprintf("foodgroup 0x%04x subgroup 0x%04x", f.FoodGroup, f.SubGroup)
}

// DecodeSNAC splits a FLAP data frame payload into its SNAC header and body
// bytes. The body is returned undecoded because its type depends on the
// foodgroup/subgroup pair the caller dispatches on.
func DecodeSNAC(payload []byte) (wire.SNACFrame, []byte, error) {
	var frame wire.SNACFrame
	r := bytes.NewReader(payload)
	if err := wire.UnmarshalBE(&frame, r); err != nil {
		return frame, nil, fmt.Errorf("oscar: decode SNAC header: %w", err)
	}

	body := make([]byte, r.Len())
	if _, err := io.ReadFull(r, body); err != nil {
		return frame, nil, fmt.Errorf("oscar: read SNAC body: %w", err)
	}

	// SNACFlagsExtendedInfo means a length-prefixed TLV block sits between the
	// header and the body proper; skip it so callers decode the body they expect.
	if frame.Flags&wire.SNACFlagsExtendedInfo != 0 {
		if len(body) < 2 {
			return frame, nil, fmt.Errorf("oscar: SNAC (%s) has extended-info flag but no length prefix", snacName(frame))
		}
		skip := int(body[0])<<8 | int(body[1])
		if 2+skip > len(body) {
			return frame, nil, fmt.Errorf("oscar: SNAC (%s) extended-info length %d overruns body (%d bytes)", snacName(frame), skip, len(body)-2)
		}
		body = body[2+skip:]
	}
	return frame, body, nil
}
