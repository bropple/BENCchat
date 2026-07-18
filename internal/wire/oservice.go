package wire

// OSERVICE (0x0001) bodies — core session management on the BOS connection.

// OService TLV tags carried in service/MOTD responses. (ReconnectHere 0x05,
// LoginCookie 0x06, SSLState 0x8E live in login.go, shared with the login reply.)
const (
	OServiceTLVTagsMOTDMessage    uint16 = 0x0B
	OServiceTLVTagsGroupID        uint16 = 0x0D // the service (foodgroup) being granted
	OServiceServiceReqTLVRoomInfo uint16 = 0x01 // room-info block in a Chat service request
)

// SNAC_0x01_0x04_OServiceServiceRequest asks the server to grant access to
// another service (foodgroup) — e.g. ChatNav or Chat — running on its own
// connection. The reply is an OServiceServiceResponse with the host + cookie to
// reconnect with. For a Chat request the TLVRestBlock carries a room-info block
// under OServiceServiceReqTLVRoomInfo identifying which room.
type SNAC_0x01_0x04_OServiceServiceRequest struct {
	FoodGroup uint16
	TLVRestBlock
}

// SNAC_0x01_0x05_OServiceServiceResponse grants a service: TLV 0x05 is the
// host:port to dial, 0x06 the cookie to present in the new connection's signon
// frame, 0x0D echoes the granted foodgroup.
type SNAC_0x01_0x05_OServiceServiceResponse struct {
	TLVRestBlock
}

// ServiceReqRoomInfo identifies a room in a Chat service request (TLV 0x01). The
// cookie is the room cookie learned from ChatNav ("{exchange}-{instance}-{name}").
type ServiceReqRoomInfo struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
}

// EvilSnitcher identifies who warned us, when the warning wasn't anonymous.
type EvilSnitcher struct {
	TLVUserInfo
}

// SNAC_0x01_0x10_OServiceEvilNotification tells us our warning level changed
// because someone warned us. Snitcher names the warner; it is absent (nil) for
// an anonymous warning, which is why it is an optional trailing pointer.
type SNAC_0x01_0x10_OServiceEvilNotification struct {
	NewEvil  uint16
	Snitcher *EvilSnitcher `oscar:"optional"`
}

// SNAC_0x01_0x03_OServiceHostOnline is the server's opening SNAC on a new BOS
// connection: the list of foodgroups this connection serves. The list is a bare
// uint16 array with no count prefix — it runs to the end of the SNAC.
type SNAC_0x01_0x03_OServiceHostOnline struct {
	FoodGroups []uint16
}

// SNAC_0x01_0x17_OServiceClientVersions declares which foodgroup versions the
// client speaks, as flat (foodgroup, version) pairs with no count prefix.
//
// An odd-length list makes the server log an error and reply with nothing at
// all, stalling sign-on — so this must always hold an even number of elements.
type SNAC_0x01_0x17_OServiceClientVersions struct {
	Versions []uint16
}

// SNAC_0x01_0x18_OServiceHostVersions is the server's reply. open-oscar-server
// echoes the client's list back verbatim rather than negotiating.
type SNAC_0x01_0x18_OServiceHostVersions struct {
	Versions []uint16
}

// GroupVersion is one entry of the ClientOnline payload.
type GroupVersion struct {
	FoodGroup   uint16
	Version     uint16
	ToolID      uint16
	ToolVersion uint16
}

// SNAC_0x01_0x02_OServiceClientOnline signals that the client has finished
// signing on. Until it arrives the server never marks the session complete, so
// the user stays invisible to buddies and several foodgroups stay gated.
type SNAC_0x01_0x02_OServiceClientOnline struct {
	GroupVersions []GroupVersion
}

// SNAC_0x01_0x06_OServiceRateParamsQuery asks for the rate-limit rules. It has
// an empty body; the type exists for symmetry and documentation.
type SNAC_0x01_0x06_OServiceRateParamsQuery struct{}

// RateParamsSNAC is one rate class in RateParamsReply: the thresholds of a
// moving-average rate limiter, all in milliseconds. The server keeps a per-class
// moving average of the gap between the SNACs a client sends; when that average
// drops below LimitLevel it silently discards further SNACs in the class.
// internal/oscar/ratelimit.go mirrors this to pace our own sends.
//
// This fixed 30-byte layout has NO trailing {LastTime, DroppingSNACs} tail: the
// server appends that tail only when the client declares OSERVICE version > 1.
// BENCchat declares version 1 (see ClientFoodGroupVersions), so the tail is
// absent and the classes decode cleanly. If that version is ever raised, this
// struct must grow the tail or per-class decode desyncs by 5 bytes each.
type RateParamsSNAC struct {
	ID              uint16
	WindowSize      uint32
	ClearLevel      uint32
	AlertLevel      uint32
	LimitLevel      uint32
	DisconnectLevel uint32
	CurrentLevel    uint32
	MaxLevel        uint32
}

// RateGroupPair is a (foodgroup, subgroup) SNAC type governed by a rate class.
type RateGroupPair struct {
	FoodGroup uint16
	SubGroup  uint16
}

// RateGroup maps one rate class to the SNAC types it governs. ClassID matches a
// RateParamsSNAC.ID; Pairs lists every SNAC type limited under that class.
type RateGroup struct {
	ClassID uint16
	Pairs   []RateGroupPair `oscar:"count_prefix=uint16"`
}

// SNAC_0x01_0x07_OServiceRateParamsReply carries the rate classes followed by
// the mapping from SNAC type to governing class.
//
// The count prefix applies only to RateClasses. RateGroups has the same number
// of entries but no prefix of its own — it runs to the end of the SNAC, which
// the codec reads greedily. This is correct only because RateParamsSNAC has no
// version-conditional tail (see its note); a wrong class size would make the
// greedy RateGroups read consume garbage.
type SNAC_0x01_0x07_OServiceRateParamsReply struct {
	RateClasses []RateParamsSNAC `oscar:"count_prefix=uint16"`
	RateGroups  []RateGroup
}

// SNAC_0x01_0x13_OServiceMOTD is the message-of-the-day the server pushes
// unsolicited during the handshake. Some clients wait for it before continuing,
// which is why the server sends it unprompted.
type SNAC_0x01_0x13_OServiceMOTD struct {
	MessageType uint16
	TLVRestBlock
}

// ClientFoodGroupVersions is the set BENCchat declares in ClientVersions.
//
// OService is declared at version 1 deliberately: at version > 1 the server
// appends a conditional V2Params tail to every rate class in RateParamsReply,
// and a decoder that disagrees with the server about that desynchronizes by 5
// bytes per class. Declaring 1 keeps that reply unambiguous — RateParamsSNAC is
// modeled without the tail to match, which is what lets the client-side rate
// limiter decode the reply. Raising this version means growing RateParamsSNAC.
var ClientFoodGroupVersions = []uint16{
	OService, 1,
	Locate, 1,
	Buddy, 1,
	ICBM, 1,
	BART, 1,
	Feedbag, 4,
}
