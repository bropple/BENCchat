package wire

// BUDDY (0x0003) — presence notifications.

// TLV tags inside a TLVUserInfo block.
const (
	OServiceUserInfoUserFlags uint16 = 0x01
	OServiceUserInfoSignonTOD uint16 = 0x03
	OServiceUserInfoIdleTime  uint16 = 0x04
	OServiceUserInfoStatus    uint16 = 0x06
	OServiceUserInfoOscarCaps uint16 = 0x0D
	OServiceUserInfoBARTInfo  uint16 = 0x1D
	OServiceUserInfoSubscript uint16 = 0x1E
)

// User flag bits (TLV 0x01, uint16).
const (
	OServiceUserFlagUnconfirmed   uint16 = 0x0001
	OServiceUserFlagAdministrator uint16 = 0x0002
	OServiceUserFlagAOL           uint16 = 0x0004
	OServiceUserFlagOSCARFree     uint16 = 0x0010
	// OServiceUserFlagUnavailable is the away bit. This — not the Status TLV's
	// away bit — is what the server itself tests to decide whether a user is
	// away, so it is what BENCchat tests too.
	OServiceUserFlagUnavailable uint16 = 0x0020
	OServiceUserFlagICQ         uint16 = 0x0040
	OServiceUserFlagWireless    uint16 = 0x0080
	OServiceUserFlagBot         uint16 = 0x0400
)

// Status bits (TLV 0x06, uint32).
const (
	OServiceUserStatusAvailable uint32 = 0x00000000
	OServiceUserStatusAway      uint32 = 0x00000001
	OServiceUserStatusDND       uint32 = 0x00000002
	OServiceUserStatusOut       uint32 = 0x00000004
	OServiceUserStatusBusy      uint32 = 0x00000010
	OServiceUserStatusInvisible uint32 = 0x00000100
)

// TLVUserInfo describes a user's presence. It appears in buddy arrival/departure
// notifications, inbound instant messages, and locate replies.
//
//	uint8 snLen | screen name | uint16 warningLevel | uint16 TLV COUNT | TLVs
//
// The embedded TLVBlock is a COUNT prefix, not a byte-length prefix. Getting
// this wrong is the classic OSCAR decoding bug: both are uint16 on the wire, so
// a length-prefixed read appears to work until it desynchronizes the stream.
type TLVUserInfo struct {
	ScreenName   string `oscar:"len_prefix=uint8"`
	WarningLevel uint16
	TLVBlock
}

// IsAway reports whether the user has an away message set.
func (u TLVUserInfo) IsAway() bool {
	flags, ok := u.Uint16BE(OServiceUserInfoUserFlags)
	return ok && flags&OServiceUserFlagUnavailable != 0
}

// IsInvisible reports whether the user is signed on invisibly. In practice the
// server never sends us arrivals for invisible users, so this is informational.
func (u TLVUserInfo) IsInvisible() bool {
	status, ok := u.Uint32BE(OServiceUserInfoStatus)
	return ok && status&OServiceUserStatusInvisible != 0
}

// IdleMinutes returns how long the user has been idle. The bool is false when
// the user is not idle at all — the server omits TLV 0x04 entirely rather than
// sending zero.
//
// Note the unit: this TLV is uint16 MINUTES, not seconds.
func (u TLVUserInfo) IdleMinutes() (uint16, bool) {
	return u.Uint16BE(OServiceUserInfoIdleTime)
}

// SignonTOD returns the user's sign-on time as a unix timestamp.
func (u TLVUserInfo) SignonTOD() (uint32, bool) {
	return u.Uint32BE(OServiceUserInfoSignonTOD)
}

// SNAC_0x03_0x0B_BuddyArrived announces that a buddy is online, or that their
// details changed.
//
// This is re-sent for away/idle/icon/warning changes as well as actual sign-on,
// so treat it as an idempotent upsert rather than a "came online" edge.
type SNAC_0x03_0x0B_BuddyArrived struct {
	TLVUserInfo
}

// SNAC_0x03_0x0C_BuddyDeparted announces that a buddy went offline.
//
// Its TLV block is deliberately degenerate: the server sends either zero TLVs
// (the normal path — AIM clients fail to process a full block here) or exactly
// one (UserFlags = 0, needed for ICQ). Decode it defensively; do not expect
// full user info.
type SNAC_0x03_0x0C_BuddyDeparted struct {
	TLVUserInfo
}

// SNAC_0x03_0x02_BuddyRightsQuery asks for presence limits. The server ignores
// the body.
type SNAC_0x03_0x02_BuddyRightsQuery struct {
	TLVRestBlock
}

// SNAC_0x03_0x03_BuddyRightsReply carries the presence limits.
type SNAC_0x03_0x03_BuddyRightsReply struct {
	TLVRestBlock
}
