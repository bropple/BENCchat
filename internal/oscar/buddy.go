package oscar

import (
	"bytes"
	"fmt"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// UserInfo is a decoded presence notification.
type UserInfo struct {
	// ScreenName is the server's canonical casing.
	ScreenName string
	// WarningLevel is the user's warning percentage, in tenths of a percent.
	WarningLevel uint16
	// Away reports whether the user has an away message set.
	Away bool
	// IdleMinutes is 0 when the user is not idle. The wire format omits the TLV
	// entirely in that case rather than sending zero.
	IdleMinutes uint16
	// SignedOn is when the user came online; zero if the server didn't say.
	SignedOn time.Time
	// IconHash is the MD5 of the user's buddy icon (BART item), or nil if they
	// have none. IconType/IconFlags identify the item for a download request.
	// The hash is what changes when a buddy swaps their icon.
	IconType  uint16
	IconFlags uint8
	IconHash  []byte
	// Capabilities is what the peer's client advertises it can do. Empty when
	// the client sent none — which is normal for older clients, and is why an
	// absent capability means "unknown", never "definitely unsupported".
	Capabilities []Capability
}

// DecodeUserInfo parses the TLVUserInfo body shared by buddy arrival and
// departure notifications.
//
// It tolerates a departure's degenerate body — the server sends zero or one
// TLVs there, not a full user-info block — because the TLV block is a count
// prefix, so an empty block decodes cleanly to no TLVs.
func DecodeUserInfo(body []byte) (UserInfo, error) {
	var info wire.TLVUserInfo
	if err := wire.UnmarshalBE(&info, bytes.NewReader(body)); err != nil {
		return UserInfo{}, fmt.Errorf("oscar: decode user info: %w", err)
	}

	out := UserInfo{
		ScreenName:   info.ScreenName,
		WarningLevel: info.WarningLevel,
		Away:         info.IsAway(),
	}
	if mins, idle := info.IdleMinutes(); idle {
		out.IdleMinutes = mins
	}
	if tod, ok := info.SignonTOD(); ok && tod > 0 {
		out.SignedOn = time.Unix(int64(tod), 0)
	}
	// Buddy icon reference (BART), if present. The TLV value is a marshaled
	// BARTID. We only treat a full 16-byte MD5 as a real icon, which excludes
	// both an empty hash and the 5-byte "cleared icon" sentinel.
	if raw, ok := info.Bytes(wire.OServiceUserInfoBARTInfo); ok {
		var id wire.BARTID
		if err := wire.UnmarshalBE(&id, bytes.NewReader(raw)); err == nil && len(id.Hash) == 16 {
			out.IconType = id.Type
			out.IconFlags = id.Flags
			out.IconHash = id.Hash
		}
	}
	if raw, ok := info.Bytes(wire.OServiceUserInfoOscarCaps); ok {
		out.Capabilities = decodeCapabilities(raw)
	}
	return out, nil
}
