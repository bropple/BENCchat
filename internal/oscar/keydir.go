package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// Session-level access to the BENCO device key directory (foodgroup 0xBE00).
//
// Every call here returns the request ID, because replies arrive asynchronously
// on the read loop and several queries can be outstanding at once.

// SupportsKeyDir reports whether the server offers the device key directory.
//
// This is the graceful-degradation check. The foodgroup sits above wire.MDir, so
// it cannot take part in OSCAR's foodgroup version negotiation; the server
// advertises it in the HostOnline list instead. A server that does not list it —
// a stock open-oscar-server, or a BENCoscar older than the directory — means we
// must keep publishing keys in the Locate profile.
func (s *Session) SupportsKeyDir() bool {
	for _, fg := range s.FoodGroups() {
		if fg == wire.BENCOKeyDir {
			return true
		}
	}
	return false
}

// PublishDeviceKeys publishes this account's complete device set.
//
// The set is replaced rather than merged, so callers send every device they know
// about. The server takes the screen name from the session, so this can only
// ever publish for ourselves.
func (s *Session) PublishDeviceKeys(devices []wire.BENCODevice) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
		Version: wire.BENCOKeyDirVersion,
		Devices: devices,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirPublishRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: publish device keys: %w", err)
	}
	return reqID, nil
}

// QueryDeviceKeys asks for an account's published devices. Works for a peer who
// is offline and for our own screen name, neither of which the profile-marker
// scheme could do.
func (s *Session) QueryDeviceKeys(screenName string) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: screenName,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirQueryRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: query device keys: %w", err)
	}
	return reqID, nil
}

// RevokeDeviceKey removes one of this account's own devices. The server keeps a
// tombstone, so the removed machine cannot republish itself on next sign-on.
func (s *Session) RevokeDeviceKey(boxKey []byte) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest{
		Version: wire.BENCOKeyDirVersion,
		BoxKey:  boxKey,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirRevokeRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: revoke device key: %w", err)
	}
	return reqID, nil
}

// DecodeKeyDirQueryReply decodes a query reply body.
func DecodeKeyDirQueryReply(body []byte) (wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply, error) {
	var reply wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory query reply: %w", err)
	}
	return reply, nil
}

// DecodeKeyDirPublishReply decodes a publish reply body.
func DecodeKeyDirPublishReply(body []byte) (wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply, error) {
	var reply wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory publish reply: %w", err)
	}
	return reply, nil
}

// DecodeKeyDirRevokeReply decodes a revoke reply body.
func DecodeKeyDirRevokeReply(body []byte) (wire.SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply, error) {
	var reply wire.SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory revoke reply: %w", err)
	}
	return reply, nil
}
