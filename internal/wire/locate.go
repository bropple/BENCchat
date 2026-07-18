package wire

// LOCATE (0x0002) — profile text, away message, and capabilities.

// Locate SetInfo TLV tags. The server reads only a handful; these are the ones
// BENCchat uses.
const (
	// LocateTLVSigMime is the profile's MIME type (e.g. text/aolrtf).
	LocateTLVSigMime uint16 = 0x01
	// LocateTLVSigData is the profile text itself.
	LocateTLVSigData uint16 = 0x02
	// LocateTLVUnavailableMime is the away message's MIME type.
	LocateTLVUnavailableMime uint16 = 0x03
	// LocateTLVUnavailableData is the away message. An empty value clears away
	// status; a non-empty value sets the Unavailable user flag and re-broadcasts
	// presence to buddies.
	LocateTLVUnavailableData uint16 = 0x04
	// LocateTLVCapabilities is the concatenated 16-byte capability UUIDs.
	LocateTLVCapabilities uint16 = 0x05
	// LocateTLVSupportHostSig would ask the server to store the profile
	// server-side instead of on the live session. DO NOT SEND IT: for a BUCP
	// (non-Kerberos) client open-oscar-server writes the profile to its database
	// but never copies it onto the session instance, and both own- and peer
	// lookups read only from live instances (state/session.go Session.Profile).
	// Sending this makes the profile — and so our published E2EE keys —
	// invisible to everyone. Verified live.
	LocateTLVSupportHostSig uint16 = 0x0C
)

// ProfileMIME is the content type AIM used for both profiles and away messages.
const ProfileMIME = `text/aolrtf; charset="us-ascii"`

// SNAC_0x02_0x04_LocateSetInfo sets the client's profile, away message, and/or
// capabilities. Each field is optional — only the TLVs present are applied, so
// setting an away message doesn't disturb the profile and vice versa.
type SNAC_0x02_0x04_LocateSetInfo struct {
	TLVRestBlock
}

// Locate UserInfoQuery request-type bits.
const (
	LocateTypeProfile     uint16 = 0x0001
	LocateTypeAwayMessage uint16 = 0x0002
)

// SNAC_0x02_0x05_LocateUserInfoQuery asks for another user's profile and/or away
// message. Type is a bitmask of LocateType* selecting which to return.
type SNAC_0x02_0x05_LocateUserInfoQuery struct {
	Type       uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0x02_0x06_LocateUserInfoReply carries the queried user's presence plus a
// trailing block of the requested info (profile in TLV 0x01/0x02, away message
// in TLV 0x03/0x04 — the latter only present when the user is actually away).
type SNAC_0x02_0x06_LocateUserInfoReply struct {
	TLVUserInfo
	LocateInfo TLVRestBlock
}
