package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// SetAway sets or clears the client's away message via Locate SetInfo.
//
// An empty message clears away status; a non-empty one sets the Unavailable
// flag and causes the server to re-broadcast our presence to buddies. Only the
// away TLV is sent, so this leaves any profile untouched.
func (s *Session) SetAway(message string) error {
	body := wire.SNAC_0x02_0x04_LocateSetInfo{}
	if message != "" {
		body.Append(wire.NewTLVBE(wire.LocateTLVUnavailableMime, []byte(wire.ProfileMIME)))
	}
	// The data TLV is always present — sending it empty is how away is cleared.
	body.Append(wire.NewTLVBE(wire.LocateTLVUnavailableData, []byte(message)))

	if err := s.Send(wire.Locate, wire.LocateSetInfo, body); err != nil {
		return fmt.Errorf("oscar: set away message: %w", err)
	}
	return nil
}

// SetProfile sets the client's profile ("info") text. An empty string is still
// sent, which clears the profile.
func (s *Session) SetProfile(text string) error {
	body := wire.SNAC_0x02_0x04_LocateSetInfo{}
	body.Append(wire.NewTLVBE(wire.LocateTLVSigMime, []byte(wire.ProfileMIME)))
	body.Append(wire.NewTLVBE(wire.LocateTLVSigData, []byte(text)))
	if err := s.Send(wire.Locate, wire.LocateSetInfo, body); err != nil {
		return fmt.Errorf("oscar: set profile: %w", err)
	}
	return nil
}

// RequestAwayMessage asks the server for a buddy's away message.
func (s *Session) RequestAwayMessage(screenName string) error {
	return s.requestUserInfo(screenName, wire.LocateTypeAwayMessage)
}

// RequestUserInfo asks for a buddy's profile and away message together. The
// reply arrives asynchronously as a LocateUserInfoReply on the read loop.
func (s *Session) RequestUserInfo(screenName string) error {
	return s.requestUserInfo(screenName, wire.LocateTypeProfile|wire.LocateTypeAwayMessage)
}

func (s *Session) requestUserInfo(screenName string, typ uint16) error {
	req := wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: typ, ScreenName: screenName}
	if err := s.Send(wire.Locate, wire.LocateUserInfoQuery, req); err != nil {
		return fmt.Errorf("oscar: request user info: %w", err)
	}
	return nil
}

// LocateReply is a decoded LocateUserInfoReply. The Has* flags distinguish "the
// field was returned as empty" from "the field was not requested/applicable", so
// a query for one field doesn't clobber a stored value for the other.
type LocateReply struct {
	ScreenName string
	Profile    string
	HasProfile bool
	Away       string
	HasAway    bool
	// Capabilities is what the peer's client advertises. Carried in the reply's
	// embedded user-info block rather than the locate info, so it arrives on a
	// lookup as well as on a buddy arrival — which matters for anyone not on the
	// buddy list, where an arrival broadcast never comes.
	Capabilities []Capability
}

// DecodeLocateReply parses a LocateUserInfoReply's profile and away text.
func DecodeLocateReply(body []byte) (LocateReply, error) {
	var reply wire.SNAC_0x02_0x06_LocateUserInfoReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return LocateReply{}, fmt.Errorf("oscar: decode locate reply: %w", err)
	}
	lr := LocateReply{ScreenName: reply.ScreenName}
	if p, ok := reply.LocateInfo.String(wire.LocateTLVSigData); ok {
		lr.Profile, lr.HasProfile = p, true
	}
	if a, ok := reply.LocateInfo.String(wire.LocateTLVUnavailableData); ok {
		lr.Away, lr.HasAway = a, true
	}
	if raw, ok := reply.TLVUserInfo.Bytes(wire.OServiceUserInfoOscarCaps); ok {
		lr.Capabilities = decodeCapabilities(raw)
	}
	return lr, nil
}
