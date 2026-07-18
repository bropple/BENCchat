package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// ChangePassword changes the account password. Both passwords are sent as
// plaintext — the server hashes them for comparison — so this is only as private
// as the transport, which is currently unencrypted. The reply arrives
// asynchronously as an AdminInfoChangeReply.
func (s *Session) ChangePassword(oldPassword, newPassword string) error {
	req := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{}
	req.Append(wire.NewTLVBE(wire.AdminTLVNewPassword, []byte(newPassword)))
	req.Append(wire.NewTLVBE(wire.AdminTLVOldPassword, []byte(oldPassword)))
	if err := s.Send(wire.Admin, wire.AdminInfoChangeRequest, req); err != nil {
		return fmt.Errorf("oscar: change password: %w", err)
	}
	return nil
}

// ChangeEmail changes the account email address.
func (s *Session) ChangeEmail(email string) error {
	req := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{}
	req.Append(wire.NewTLVBE(wire.AdminTLVEmailAddress, []byte(email)))
	if err := s.Send(wire.Admin, wire.AdminInfoChangeRequest, req); err != nil {
		return fmt.Errorf("oscar: change email: %w", err)
	}
	return nil
}

// AdminResult is a decoded AdminChangeReply. OK is false when the server
// rejected the change, in which case Message explains why.
type AdminResult struct {
	OK      bool
	Message string
}

// DecodeAdminChangeReply parses an AdminChangeReply. Failure is indicated by the
// presence of the ErrorCode TLV.
func DecodeAdminChangeReply(body []byte) (AdminResult, error) {
	var reply wire.SNAC_0x07_0x05_AdminChangeReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return AdminResult{}, fmt.Errorf("oscar: decode admin reply: %w", err)
	}
	if code, ok := reply.Uint16BE(wire.AdminTLVErrorCode); ok {
		return AdminResult{OK: false, Message: wire.AdminErrString(code)}, nil
	}
	return AdminResult{OK: true}, nil
}
