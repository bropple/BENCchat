package wire

// The BENCO device key directory, foodgroup 0xBE00.
//
// This mirrors BENCoscar's wire/benco_keydir.go byte for byte. It replaces
// publishing device keys inside the Locate profile as a hidden HTML comment,
// which only worked for peers who were ONLINE, could not see this account's own
// other devices, and let a removed machine silently republish itself.
//
// The server is the authority the old scheme lacked: it holds a tombstone for a
// revoked device and refuses to accept that key again.
const BENCOKeyDir uint16 = 0xBE00

// BENCOKeyDir subgroups.
const (
	BENCOKeyDirErr            uint16 = 0x0001
	BENCOKeyDirPublishRequest uint16 = 0x0002
	BENCOKeyDirPublishReply   uint16 = 0x0003
	BENCOKeyDirQueryRequest   uint16 = 0x0004
	BENCOKeyDirQueryReply     uint16 = 0x0005
	BENCOKeyDirRevokeRequest  uint16 = 0x0006
	BENCOKeyDirRevokeReply    uint16 = 0x0007
)

// BENCOKeyDirVersion is the payload version we send.
//
// The foodgroup sits above wire.MDir, which on the server bounds a fixed array
// used for foodgroup version negotiation — so this foodgroup deliberately takes
// no part in that, and BENCchat must NOT list it in OServiceClientVersions.
// Support is discovered from the HostOnline foodgroup list instead, and the
// payload carries its own version.
const BENCOKeyDirVersion uint16 = 1

// BENCODevice is one machine belonging to an account: the X25519 key messages
// are sealed to, and the Ed25519 key that signs room messages. SignKey is empty
// for a client that has not generated one.
type BENCODevice struct {
	BoxKey  []byte `oscar:"len_prefix=uint16"`
	SignKey []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest publishes this account's devices.
// It replaces the published set, so the complete list is sent every time. There
// is no screen name field: the server uses the session's, so an account can only
// publish for itself.
type SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest struct {
	Version uint16
	Devices []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply reports what the server stored.
// Refused carries devices declined because they were revoked — a machine the
// user removed announcing itself again, which belongs in front of a human rather
// than being retried.
type SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply struct {
	Accepted uint16
	Refused  []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest asks for an account's devices. It
// is answered from server storage, so unlike the profile it replaces it works
// for an offline user and for our own screen name.
type SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest struct {
	Version    uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

// SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply carries an account's active devices.
// An empty list is a normal answer meaning "no encryption keys published", not
// an error.
type SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply struct {
	ScreenName string        `oscar:"len_prefix=uint8"`
	Devices    []BENCODevice `oscar:"count_prefix=uint16"`
}

// SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest removes one of this account's own
// devices. The server tombstones it so it cannot republish itself.
type SNAC_0xBE00_0x0006_BENCOKeyDirRevokeRequest struct {
	Version uint16
	BoxKey  []byte `oscar:"len_prefix=uint16"`
}

// SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply reports whether anything changed.
// Zero means the key was not active, which is not a failure.
type SNAC_0xBE00_0x0007_BENCOKeyDirRevokeReply struct {
	Revoked uint8
}
