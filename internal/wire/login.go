package wire

import (
	"crypto/md5"
	"fmt"
	"io"
)

// Login TLV tags used across the BUCP handshake and the sign-on frame.
const (
	LoginTLVTagsScreenName          uint16 = 0x01
	LoginTLVTagsRoastedPassword     uint16 = 0x02
	LoginTLVTagsClientIdentity      uint16 = 0x03
	LoginTLVTagsReconnectHere       uint16 = 0x05
	LoginTLVTagsAuthorizationCookie uint16 = 0x06
	LoginTLVTagsErrorSubcode        uint16 = 0x08
	LoginTLVTagsPasswordHash        uint16 = 0x25
	// LoginTLVTagsPlaintextPassword carries the password itself in the sign-on
	// frame. This is the mechanism BENCchat uses, and it is safe only because the
	// connection is TLS: the server verifies it against an argon2id hash, which
	// is impossible with challenge-response because that requires the server to
	// store a value it can reproduce the client's digest from. See BENCoscar's
	// docs/BENCO_AUTH.md.
	LoginTLVTagsPlaintextPassword   uint16 = 0x1339
	LoginTLVTagsMultiConnFlags      uint16 = 0x4A
	LoginTLVTagsClientCountry       uint16 = 0x0E
	LoginTLVTagsClientLanguage      uint16 = 0x0F
	LoginTLVTagsClientDistribution  uint16 = 0x14
	LoginTLVTagsClientMajorVersion  uint16 = 0x17
	LoginTLVTagsClientMinorVersion  uint16 = 0x18
	LoginTLVTagsClientLesserVersion uint16 = 0x19
	LoginTLVTagsClientBuildNumber   uint16 = 0x1A
	LoginTLVTagsClientID            uint16 = 0x16
)

// OSERVICE TLV tags returned in the login/service response.
const (
	OServiceTLVTagsReconnectHere uint16 = 0x05
	OServiceTLVTagsLoginCookie   uint16 = 0x06
	OServiceTLVTagsSSLState      uint16 = 0x8E
)

// Login error subcodes (values of LoginTLVTagsErrorSubcode). The server passes
// a user's SuspendedStatus through verbatim as the error code, so any of the
// suspension values can appear even though the server never emits some of the
// others.
const (
	LoginErrInvalidUsernameOrPassword uint16 = 0x01
	LoginErrInvalidPassword           uint16 = 0x05
	LoginErrInvalidAccount            uint16 = 0x07
	LoginErrDeletedAccount            uint16 = 0x08
	LoginErrExpiredAccount            uint16 = 0x09
	LoginErrSuspendedAccount          uint16 = 0x11
	LoginErrTooHeavilyWarned          uint16 = 0x19
	LoginErrRateLimitExceeded         uint16 = 0x1D
	LoginErrInvalidSecureID           uint16 = 0x20
	LoginErrSuspendedAccountAge       uint16 = 0x22
)

// LoginErrString renders a login error subcode as a message fit to show a user.
// Unknown codes are reported numerically rather than swallowed — an unexplained
// sign-on failure is worse than an ugly one.
func LoginErrString(code uint16) string {
	switch code {
	case LoginErrInvalidUsernameOrPassword:
		return "Invalid screen name or password."
	case LoginErrInvalidPassword:
		return "Incorrect password."
	case LoginErrInvalidAccount:
		return "Invalid account."
	case LoginErrDeletedAccount:
		return "This account has been deleted."
	case LoginErrExpiredAccount:
		return "This account has expired."
	case LoginErrSuspendedAccount:
		return "This account is suspended."
	case LoginErrTooHeavilyWarned:
		return "This account is suspended: too heavily warned."
	case LoginErrRateLimitExceeded:
		return "Too many sign-on attempts. Wait a moment and try again."
	case LoginErrInvalidSecureID:
		return "Invalid SecurID."
	case LoginErrSuspendedAccountAge:
		return "This account is suspended due to age requirements."
	default:
		return fmt.Sprintf("Sign-on refused by server (error 0x%02x).", code)
	}
}

// Disconnect reason tags/values sent in a BOS signoff frame.
const (
	OServiceTLVTagsDisconnectReason uint16 = 0x09
	OServiceTLVTagsDisconnectInfo   uint16 = 0x0B
	OServiceDiscErrNewLogin         uint8  = 0x01
)

// MultiConnFlagsRecentClient tells the server this is a modern client that
// supports multiple concurrent sessions.
const MultiConnFlagsRecentClient uint8 = 0x01

// SNAC_0x17_0x06_BUCPChallengeRequest asks the server for the auth key (salt)
// associated with a screen name. The screen name rides in a TLV.
type SNAC_0x17_0x06_BUCPChallengeRequest struct {
	TLVRestBlock
}

// SNAC_0x17_0x07_BUCPChallengeResponse carries the auth key used to salt the
// password hash.
type SNAC_0x17_0x07_BUCPChallengeResponse struct {
	AuthKey string `oscar:"len_prefix=uint16"`
}

// SNAC_0x17_0x02_BUCPLoginRequest carries the screen name, hashed password, and
// client identity TLVs.
type SNAC_0x17_0x02_BUCPLoginRequest struct {
	TLVRestBlock
}

// SNAC_0x17_0x03_BUCPLoginResponse carries either an error subcode or the BOS
// reconnect address plus the authorization cookie.
type SNAC_0x17_0x03_BUCPLoginResponse struct {
	TLVRestBlock
}

// The trailing magic string AIM appends to every MD5 password hash.
const aimMD5Magic = "AOL Instant Messenger (SM)"

// WeakMD5PasswordHash computes md5(authKey + pass + magic). Older clients send
// this; the server accepts it.
func WeakMD5PasswordHash(pass, authKey string) []byte {
	h := md5.New()
	_, _ = io.WriteString(h, authKey)
	_, _ = io.WriteString(h, pass)
	_, _ = io.WriteString(h, aimMD5Magic)
	return h.Sum(nil)
}

// StrongMD5PasswordHash computes md5(authKey + md5(pass) + magic). Newer AIM
// clients (and BENCchat) send this; it avoids putting the raw password length
// into the outer hash.
func StrongMD5PasswordHash(pass, authKey string) []byte {
	inner := md5.New()
	_, _ = io.WriteString(inner, pass)

	outer := md5.New()
	_, _ = io.WriteString(outer, authKey)
	_, _ = outer.Write(inner.Sum(nil))
	_, _ = io.WriteString(outer, aimMD5Magic)
	return outer.Sum(nil)
}
