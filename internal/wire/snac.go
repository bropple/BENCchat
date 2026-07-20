package wire

// SNAC is the command layer carried inside FLAP data frames. Every SNAC begins
// with an 8-byte header identifying the foodgroup (family), subgroup (command),
// flags, and a request ID that ties a response back to its request.
//
//	+---------------+--------------+-----------+-----------------+
//	| foodgroup(2B) | subgroup(2B) | flags(2B) | request id (4B) |  body...
//	+---------------+--------------+-----------+-----------------+

// SNACFrame is the SNAC header.
type SNACFrame struct {
	FoodGroup uint16
	SubGroup  uint16
	Flags     uint16
	RequestID uint32
}

// SNACMessage pairs a header with its (foodgroup-specific) body.
type SNACMessage struct {
	Frame SNACFrame
	Body  any
}

// SNAC frame flags.
const (
	// SNACFlagsMoreToCome marks all but the last fragment of a multi-frame
	// response.
	SNACFlagsMoreToCome uint16 = 0x0001
	// SNACFlagsExtendedInfo signals a TLVLBlock follows the header before the
	// rest of the body.
	SNACFlagsExtendedInfo uint16 = 0x8000
	// ReqIDFromServer is OR'd into request IDs for server-initiated SNACs.
	ReqIDFromServer uint32 = 1 << 31
)

// Foodgroups (SNAC families) BENCchat cares about for core messaging. The full
// set the server implements is larger; these are the ones exercised by the
// login → buddy list → IM path.
const (
	OService   uint16 = 0x0001
	Locate     uint16 = 0x0002
	Buddy      uint16 = 0x0003
	ICBM       uint16 = 0x0004
	Admin      uint16 = 0x0007
	UserLookup uint16 = 0x000A
	ChatNav    uint16 = 0x000D
	Chat       uint16 = 0x000E
	ODir       uint16 = 0x000F
	BART       uint16 = 0x0010
	Feedbag    uint16 = 0x0013
	BUCP       uint16 = 0x0017
)

// OSERVICE (0x0001) subgroups — core session management.
const (
	OServiceErr               uint16 = 0x0001
	OServiceClientOnline      uint16 = 0x0002
	OServiceHostOnline        uint16 = 0x0003
	OServiceServiceRequest    uint16 = 0x0004
	OServiceServiceResponse   uint16 = 0x0005
	OServiceRateParamsQuery   uint16 = 0x0006
	OServiceRateParamsReply   uint16 = 0x0007
	OServiceRateParamsSubAdd  uint16 = 0x0008
	OServiceUserInfoQuery     uint16 = 0x000E
	OServiceUserInfoUpdate    uint16 = 0x000F
	OServiceEvilNotification  uint16 = 0x0010
	OServiceIdleNotification  uint16 = 0x0011
	OServiceClientVersions    uint16 = 0x0017
	OServiceHostVersions      uint16 = 0x0018
	OServiceSetUserInfoFields uint16 = 0x001E
)

// LOCATE (0x0002) subgroups — profile and away message.
const (
	LocateErr           uint16 = 0x0001
	LocateRightsQuery   uint16 = 0x0002
	LocateRightsReply   uint16 = 0x0003
	LocateSetInfo       uint16 = 0x0004
	LocateUserInfoQuery uint16 = 0x0005
	LocateUserInfoReply uint16 = 0x0006
)

// BUDDY (0x0003) subgroups — presence.
const (
	BuddyErr         uint16 = 0x0001
	BuddyRightsQuery uint16 = 0x0002
	BuddyRightsReply uint16 = 0x0003
	BuddyArrived     uint16 = 0x000B
	BuddyDeparted    uint16 = 0x000C
)

// ICBM (0x0004) subgroups — instant messages.
const (
	ICBMErr                uint16 = 0x0001
	ICBMAddParameters      uint16 = 0x0002
	ICBMParameterQuery     uint16 = 0x0004
	ICBMParameterReply     uint16 = 0x0005
	ICBMChannelMsgToHost   uint16 = 0x0006
	ICBMChannelMsgToClient uint16 = 0x0007
	ICBMEvilRequest        uint16 = 0x0008
	ICBMEvilReply          uint16 = 0x0009
	// ICBMOfflineRetrieve asks the server to deliver messages stored while we
	// were offline. Empty body; the server replays each as a ChannelMsgToClient.
	ICBMOfflineRetrieve uint16 = 0x0010
	// ICBMClientEvent carries typing notifications, in both directions.
	ICBMClientEvent uint16 = 0x0014
	// ICBMOfflineRetrieveReply terminates the offline-message replay.
	ICBMOfflineRetrieveReply uint16 = 0x0017
)

// FEEDBAG (0x0013) subgroups — server-stored buddy list.
const (
	FeedbagErr         uint16 = 0x0001
	FeedbagRightsQuery uint16 = 0x0002
	FeedbagRightsReply uint16 = 0x0003
	FeedbagQuery       uint16 = 0x0004
	FeedbagReply       uint16 = 0x0006
	FeedbagUse         uint16 = 0x0007
	FeedbagInsertItem  uint16 = 0x0008
	FeedbagUpdateItem  uint16 = 0x0009
	FeedbagDeleteItem  uint16 = 0x000A
	FeedbagStatus      uint16 = 0x000E
)

// BUCP (0x0017) subgroups — the login flow BENCchat uses.
const (
	BUCPErr               uint16 = 0x0001
	BUCPLoginRequest      uint16 = 0x0002
	BUCPLoginResponse     uint16 = 0x0003
	BUCPChallengeRequest  uint16 = 0x0006
	BUCPChallengeResponse uint16 = 0x0007
)

// Feedbag item class IDs (the "type" of a buddy-list row).
const (
	FeedbagClassIdBuddy uint16 = 0x0000
	FeedbagClassIdGroup uint16 = 0x0001
)
