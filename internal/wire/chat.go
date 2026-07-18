package wire

// CHATNAV (0x000D) and CHAT (0x000E) — multi-user chat rooms.
//
// Chat uses two service connections beyond BOS: a ChatNav connection to
// create/look-up rooms, and one Chat connection per joined room. Both are
// reached via the OSERVICE service-request cookie redirect. A room's identity is
// the string cookie "{exchange}-{instance}-{name}" (e.g. "4-0-lobby"), which
// round-trips from ChatNav's reply into the Chat service request.

import "bytes"

// ChatNav (0x000D) subgroups.
const (
	ChatNavErr               uint16 = 0x0001
	ChatNavRequestChatRights uint16 = 0x0002
	ChatNavRequestRoomInfo   uint16 = 0x0004
	ChatNavCreateRoom        uint16 = 0x0008
	ChatNavNavInfo           uint16 = 0x0009
)

// ChatNav reply TLV tags (inside ChatNavNavInfo).
const (
	ChatNavTLVRoomInfo uint16 = 0x0004 // wraps a ChatRoomInfoUpdate for the room
)

// Chat exchanges. 4 is the user-creatable private exchange; 5 is public
// (operator-only on this server). BENCchat creates/join on 4.
const (
	ChatExchangePrivate uint16 = 4
	ChatExchangePublic  uint16 = 5
)

// Chat (0x000E) subgroups.
const (
	ChatErr                uint16 = 0x0001
	ChatRoomInfoUpdate     uint16 = 0x0002
	ChatUsersJoined        uint16 = 0x0003
	ChatUsersLeft          uint16 = 0x0004
	ChatChannelMsgToHost   uint16 = 0x0005 // client -> server
	ChatChannelMsgToClient uint16 = 0x0006 // server -> client
)

// Chat message TLV tags (top level of a chat message block).
const (
	ChatTLVSenderInformation    uint16 = 0x03 // TLVUserInfo of the sender
	ChatTLVMessageInfo          uint16 = 0x05 // sub-block: text/encoding/lang
	ChatTLVEnableReflectionFlag uint16 = 0x06 // ask server to echo to sender too
)

// Sub-TLV tags inside a ChatTLVMessageInfo block.
const (
	ChatTLVMessageInfoText     uint16 = 0x01
	ChatTLVMessageInfoEncoding uint16 = 0x02
	ChatTLVMessageInfoLang     uint16 = 0x03
)

// Room metadata TLV tags (inside a ChatRoomInfoUpdate's TLVBlock).
const (
	ChatRoomTLVFullyQualifiedName uint16 = 0x006A
	ChatRoomTLVRoomName           uint16 = 0x00D3
)

// Chat channel: standard multi-user chat messages travel on channel 3.
const chatMessageChannel uint16 = 3

// Chat message encodings (the ChatTLVMessageInfoEncoding value).
const (
	chatEncodingASCII   = "us-ascii"
	chatEncodingUnicode = "unicode-2-0" // UCS-2 big-endian
	chatEncodingLatin1  = "iso-8859-1"
)

// SNAC_0x0D_0x04_ChatNavRequestRoomInfo asks ChatNav for a known room's info.
type SNAC_0x0D_0x04_ChatNavRequestRoomInfo struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
	DetailLevel    uint8
}

// SNAC_0x0D_0x09_ChatNavNavInfo is ChatNav's universal reply. For a room
// create/lookup it carries TLV ChatNavTLVRoomInfo wrapping a ChatRoomInfoUpdate.
type SNAC_0x0D_0x09_ChatNavNavInfo struct {
	TLVRestBlock
}

// SNAC_0x0E_0x02_ChatRoomInfoUpdate describes a room. Used three ways: as the
// body of a ChatNav create request (Cookie set to "create"), wrapped in the
// ChatNav reply (with the room's real cookie), and pushed on the chat
// connection after joining.
type SNAC_0x0E_0x02_ChatRoomInfoUpdate struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
	DetailLevel    uint8
	TLVBlock
}

// SNAC_0x0E_0x03_ChatUsersJoined lists occupants (the full roster on join, or a
// single arrival afterward). The user list has no count prefix — it runs to the
// end of the SNAC.
type SNAC_0x0E_0x03_ChatUsersJoined struct {
	Users []TLVUserInfo
}

// SNAC_0x0E_0x04_ChatUsersLeft lists occupants who left. Same layout as joined.
type SNAC_0x0E_0x04_ChatUsersLeft struct {
	Users []TLVUserInfo
}

// SNAC_0x0E_0x05_ChatChannelMsgToHost sends a message to the room. Cookie is a
// per-message id (echoed to recipients); Channel is 3 for normal messages.
type SNAC_0x0E_0x05_ChatChannelMsgToHost struct {
	Cookie  uint64
	Channel uint16
	TLVRestBlock
}

// SNAC_0x0E_0x06_ChatChannelMsgToClient delivers a room message. The rest block
// carries the sender (ChatTLVSenderInformation) and text (ChatTLVMessageInfo).
type SNAC_0x0E_0x06_ChatChannelMsgToClient struct {
	Cookie  uint64
	Channel uint16
	TLVRestBlock
}

// NewChatCreateRoom builds the ChatNavCreateRoom request body for creating (or
// joining, on the private exchange) a room by name. The server keys the create
// off Cookie == "create" and the room-name TLV.
func NewChatCreateRoom(name string) SNAC_0x0E_0x02_ChatRoomInfoUpdate {
	return SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange:       ChatExchangePrivate,
		Cookie:         "create",
		InstanceNumber: 0,
		DetailLevel:    0x02,
		TLVBlock: TLVBlock{TLVList: TLVList{
			NewTLVBE(ChatRoomTLVRoomName, []byte(name)),
		}},
	}
}

// MarshalChatMessage builds the message block (sender omitted — the server fills
// that in) for a ChatChannelMsgToHost: a ChatTLVMessageInfo sub-block holding the
// text, encoding, and language. Text is sent us-ascii when 7-bit clean, else as
// big-endian UCS-2, mirroring the 1:1 ICBM path.
func MarshalChatMessage(text string) (TLVRestBlock, error) {
	encoding, payload, err := encodeChatText(text)
	if err != nil {
		return TLVRestBlock{}, err
	}
	info := TLVRestBlock{TLVList: TLVList{
		NewTLVBE(ChatTLVMessageInfoText, payload),
		NewTLVBE(ChatTLVMessageInfoEncoding, []byte(encoding)),
		NewTLVBE(ChatTLVMessageInfoLang, []byte("en")),
	}}
	var buf bytes.Buffer
	if err := MarshalBE(info, &buf); err != nil {
		return TLVRestBlock{}, err
	}
	return TLVRestBlock{TLVList: TLVList{
		NewTLVBE(ChatTLVMessageInfo, buf.Bytes()),
	}}, nil
}

// UnmarshalChatMessage extracts the sender screen name and decoded text from a
// ChatChannelMsgToClient rest block.
func UnmarshalChatMessage(block TLVRestBlock) (sender, text string, err error) {
	if raw, ok := block.Bytes(ChatTLVSenderInformation); ok {
		var info TLVUserInfo
		if err := UnmarshalBE(&info, bytes.NewReader(raw)); err == nil {
			sender = info.ScreenName
		}
	}
	raw, ok := block.Bytes(ChatTLVMessageInfo)
	if !ok {
		return sender, "", nil
	}
	var msgInfo TLVRestBlock
	if err := UnmarshalBE(&msgInfo, bytes.NewReader(raw)); err != nil {
		return sender, "", err
	}
	payload, _ := msgInfo.Bytes(ChatTLVMessageInfoText)
	encoding, _ := msgInfo.String(ChatTLVMessageInfoEncoding)
	return sender, decodeChatText(payload, encoding), nil
}

// encodeChatText picks an encoding for outbound chat text.
func encodeChatText(text string) (encoding string, payload []byte, err error) {
	if isASCII(text) {
		return chatEncodingASCII, []byte(text), nil
	}
	b, err := encodeUTF16BE(text)
	if err != nil {
		return "", nil, err
	}
	return chatEncodingUnicode, b, nil
}

// decodeChatText turns inbound chat bytes into a Go string per the wire encoding.
func decodeChatText(payload []byte, encoding string) string {
	switch encoding {
	case chatEncodingUnicode:
		if s, err := decodeUTF16BE(payload); err == nil {
			return s
		}
		return ""
	case chatEncodingLatin1:
		runes := make([]rune, len(payload))
		for i, b := range payload {
			runes[i] = rune(b)
		}
		return string(runes)
	default:
		return string(payload)
	}
}
