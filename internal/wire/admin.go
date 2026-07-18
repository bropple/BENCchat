package wire

// ADMIN (0x0007) — in-band account management (password, email).

// Admin subgroups.
const (
	AdminErr               uint16 = 0x0001
	AdminInfoQuery         uint16 = 0x0002
	AdminInfoReply         uint16 = 0x0003
	AdminInfoChangeRequest uint16 = 0x0004
	AdminInfoChangeReply   uint16 = 0x0005
	AdminAcctConfirmReq    uint16 = 0x0006
	AdminAcctConfirmReply  uint16 = 0x0007
)

// Admin TLV tags.
const (
	AdminTLVScreenNameFormatted uint16 = 0x01
	AdminTLVNewPassword         uint16 = 0x02
	AdminTLVUrl                 uint16 = 0x04
	AdminTLVErrorCode           uint16 = 0x08
	AdminTLVEmailAddress        uint16 = 0x11
	AdminTLVOldPassword         uint16 = 0x12
	AdminTLVRegistrationStatus  uint16 = 0x13
)

// Admin error subcodes (values of AdminTLVErrorCode). Only the ones BENCchat
// surfaces are named.
const (
	AdminErrNeedOldPassword    uint16 = 0x0F
	AdminErrInvalidOldPassword uint16 = 0x0A
	AdminErrValidatePassword   uint16 = 0x02
	AdminErrInvalidEmail       uint16 = 0x08
	AdminErrInvalidPasswordLen uint16 = 0x0C
)

// SNAC_0x07_0x04_AdminInfoChangeRequest changes one account field. The field is
// selected by which TLV is present: NewPassword+OldPassword to change the
// password, EmailAddress to change the email, etc.
type SNAC_0x07_0x04_AdminInfoChangeRequest struct {
	TLVRestBlock
}

// SNAC_0x07_0x05_AdminChangeReply is the result. Failure is signalled by the
// presence of the ErrorCode TLV (0x08); success echoes the changed field.
type SNAC_0x07_0x05_AdminChangeReply struct {
	Permissions uint16
	TLVBlock
}

// AdminErrString renders an admin error subcode for the user.
func AdminErrString(code uint16) string {
	switch code {
	case AdminErrNeedOldPassword:
		return "Your current password is required."
	case AdminErrInvalidOldPassword, AdminErrValidatePassword:
		return "Your current password is incorrect."
	case AdminErrInvalidPasswordLen:
		return "That password is not an acceptable length."
	case AdminErrInvalidEmail:
		return "That email address is invalid."
	default:
		return "The server rejected the change."
	}
}
