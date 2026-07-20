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
//
// Nothing in this file interprets a manifest or a signature. Manifest bytes go
// out as handed in and come back as received; verification and construction
// belong to internal/e2ee, and putting either here would mean a layer that
// speaks TCP deciding what to trust.

// SupportsKeyDir reports whether the server offers the device key directory.
//
// This is the graceful-degradation check. The foodgroup sits above wire.MDir, so
// it cannot take part in OSCAR's foodgroup version negotiation; the server
// advertises it in the HostOnline list instead. A server that does not list it —
// a stock open-oscar-server, or a BENCoscar older than the directory — cannot
// carry device keys at all, since the Locate profile no longer does.
func (s *Session) SupportsKeyDir() bool {
	for _, fg := range s.FoodGroups() {
		if fg == wire.BENCOKeyDir {
			return true
		}
	}
	return false
}

// PublishManifest publishes this account's signed device manifest.
//
// manifest is the exact byte string that was signed and must be passed through
// untouched — this function deliberately takes bytes rather than a
// wire.BENCOManifest, so there is no place here where a manifest could be
// re-encoded between signing and sending.
//
// The server takes the screen name from the session and checks it against the
// one inside the manifest, so this can only ever publish for ourselves.
func (s *Session) PublishManifest(manifest []byte, sigAlg uint8, signature []byte) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
		Version:   wire.BENCOKeyDirVersion,
		Manifest:  manifest,
		SigAlg:    sigAlg,
		Signature: signature,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirPublishRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: publish manifest: %w", err)
	}
	return reqID, nil
}

// QueryManifest asks for an account's published manifest. Works for a peer who
// is offline and for our own screen name, neither of which the profile-marker
// scheme could do.
func (s *Session) QueryManifest(screenName string) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: screenName,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirQueryRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: query manifest: %w", err)
	}
	return reqID, nil
}

// PutIdentityBackup stores this account's encrypted identity key.
//
// The KDF parameters travel with the blob rather than being implied, so the
// work factor can be raised later without stranding backups made under the old
// one. Scoped to the sending account: the screen name comes from the session.
func (s *Session) PutIdentityBackup(kdf uint8, params, salt, blob []byte) (uint32, error) {
	req := wire.SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{
		Version: wire.BENCOKeyDirVersion,
		KDF:     kdf,
		Params:  params,
		Salt:    salt,
		Blob:    blob,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirPutBackupRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: put identity backup: %w", err)
	}
	return reqID, nil
}

// GetIdentityBackup fetches this account's encrypted identity key.
//
// There is no screen name parameter and there deliberately cannot be one: the
// blob is attackable offline once held, so the protocol only ever serves the
// session's own.
func (s *Session) GetIdentityBackup() (uint32, error) {
	req := wire.SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{
		Version: wire.BENCOKeyDirVersion,
	}
	reqID, err := s.SendReq(wire.BENCOKeyDir, wire.BENCOKeyDirGetBackupRequest, req)
	if err != nil {
		return 0, fmt.Errorf("oscar: get identity backup: %w", err)
	}
	return reqID, nil
}

// DecodeKeyDirPublishReply decodes a publish reply body.
func DecodeKeyDirPublishReply(body []byte) (wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply, error) {
	var reply wire.SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory publish reply: %w", err)
	}
	return reply, nil
}

// DecodeKeyDirQueryReply decodes a query reply body.
//
// The Manifest field of the result is the byte string the publisher signed. It
// is returned as-is and must be verified in that form; decoding it into a
// wire.BENCOManifest before verification would invite re-encoding it, which
// breaks the signature.
func DecodeKeyDirQueryReply(body []byte) (wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply, error) {
	var reply wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory query reply: %w", err)
	}
	return reply, nil
}

// DecodeKeyDirPutBackupReply decodes a put-backup reply body.
func DecodeKeyDirPutBackupReply(body []byte) (wire.SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply, error) {
	var reply wire.SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory put backup reply: %w", err)
	}
	return reply, nil
}

// DecodeKeyDirGetBackupReply decodes a get-backup reply body.
func DecodeKeyDirGetBackupReply(body []byte) (wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply, error) {
	var reply wire.SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return reply, fmt.Errorf("oscar: decode key directory get backup reply: %w", err)
	}
	return reply, nil
}
