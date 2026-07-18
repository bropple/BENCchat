package oscar

import (
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// OSCAR clients advertise what they can do as a list of 16-byte capability
// UUIDs in Locate SetInfo (TLV 0x05), which the server relays to anyone who
// looks them up. This is the protocol's own extension point — the mechanism AIM
// used to signal file transfer, voice chat, and so on — so using it keeps
// BENCchat a well-behaved OSCAR client rather than smuggling BENCO-specific
// fields into the wire format.
//
// Two are advertised:
//
//   - CapSecureIM is the standard "this client does encrypted IM" capability,
//     understood by other OSCAR clients, not just ours.
//   - CapBENCchat identifies BENCchat specifically, so we can tell a peer who
//     speaks our exact E2EE dialect from one that merely claims encryption.
//
// Note this makes BENCchat users identifiable as BENCchat users to anyone who
// can query their info, including the server. That's inherent to advertising a
// capability at all, and is the trade for being able to warn — rather than
// silently downgrade — when a peer can't encrypt.
var (
	// CapSecureIM is the well-known SECURE_IM capability
	// (09460001-4C7F-11D1-8222-444553540000).
	CapSecureIM = Capability{
		0x09, 0x46, 0x00, 0x01, 0x4C, 0x7F, 0x11, 0xD1,
		0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
	}

	// CapBENCchat marks a BENCchat client. It lives in the BENCO namespace
	// rather than AOL's 0946.../4C7F-11D1-8222-444553540000 family, so it can
	// never collide with a real AIM capability:
	// 42454E43-4348-4154-0001-000000000001 ("BENC" "CH" "AT").
	CapBENCchat = Capability{
		0x42, 0x45, 0x4E, 0x43, 0x43, 0x48, 0x41, 0x54,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
)

// Capability is a 16-byte OSCAR capability UUID.
type Capability [16]byte

// Equal reports whether two capabilities match.
func (c Capability) Equal(other Capability) bool { return c == other }

// String renders the UUID in canonical 8-4-4-4-12 form.
func (c Capability) String() string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", c[0:4], c[4:6], c[6:8], c[8:10], c[10:16])
}

// SetCapabilities advertises what this client supports.
//
// Sent as its own SNAC rather than folded into SetProfile: the server handles
// the capabilities TLV in a separate branch from the profile one and
// re-broadcasts our presence for each, so combining them would emit two
// arrival broadcasts for a single logical change.
func (s *Session) SetCapabilities(caps []Capability) error {
	// The server rejects a capabilities blob whose length isn't a multiple of
	// 16 and drops the connection, so build it from whole UUIDs only.
	blob := make([]byte, 0, len(caps)*16)
	for _, c := range caps {
		blob = append(blob, c[:]...)
	}
	body := wire.SNAC_0x02_0x04_LocateSetInfo{}
	body.Append(wire.NewTLVBE(wire.LocateTLVCapabilities, blob))
	if err := s.Send(wire.Locate, wire.LocateSetInfo, body); err != nil {
		return fmt.Errorf("oscar: set capabilities: %w", err)
	}
	return nil
}

// decodeCapabilities splits a raw capabilities blob into UUIDs. A trailing
// partial entry is ignored rather than treated as fatal — a peer's malformed
// advertisement shouldn't break decoding the rest of their user info.
func decodeCapabilities(blob []byte) []Capability {
	if len(blob) < 16 {
		return nil
	}
	out := make([]Capability, 0, len(blob)/16)
	for i := 0; i+16 <= len(blob); i += 16 {
		var c Capability
		copy(c[:], blob[i:i+16])
		out = append(out, c)
	}
	return out
}

// HasCapability reports whether a capability list contains the given UUID.
func HasCapability(caps []Capability, want Capability) bool {
	for _, c := range caps {
		if c.Equal(want) {
			return true
		}
	}
	return false
}
