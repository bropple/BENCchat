package oscar

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"github.com/benco-holdings/benchat/internal/wire"
)

// RoomInfo identifies a chat room after a ChatNav lookup or create. The Cookie
// ("{exchange}-{instance}-{name}") is the identity that must round-trip into the
// Chat service request.
type RoomInfo struct {
	Exchange       uint16
	Cookie         string
	InstanceNumber uint16
	Name           string
}

// serviceReq builds the room-info block for a Chat ServiceRequest TLV.
func (r RoomInfo) serviceReq() *wire.ServiceReqRoomInfo {
	return &wire.ServiceReqRoomInfo{Exchange: r.Exchange, Cookie: r.Cookie, InstanceNumber: r.InstanceNumber}
}

// CreateRoom asks ChatNav (on the ChatNav connection) to create — or, on the
// private exchange, join-or-create — a room by name. Returns the request ID; the
// ChatNavNavInfo reply arrives asynchronously.
func (s *Session) CreateRoom(name string) (uint32, error) {
	return s.SendReq(wire.ChatNav, wire.ChatNavCreateRoom, wire.NewChatCreateRoom(name))
}

// DecodeNavInfo extracts the room from a ChatNavNavInfo reply.
func DecodeNavInfo(body []byte) (RoomInfo, error) {
	var nav wire.SNAC_0x0D_0x09_ChatNavNavInfo
	if err := wire.UnmarshalBE(&nav, bytes.NewReader(body)); err != nil {
		return RoomInfo{}, fmt.Errorf("oscar: decode nav info: %w", err)
	}
	raw, ok := nav.Bytes(wire.ChatNavTLVRoomInfo)
	if !ok {
		return RoomInfo{}, fmt.Errorf("oscar: nav info carried no room")
	}
	var ru wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate
	if err := wire.UnmarshalBE(&ru, bytes.NewReader(raw)); err != nil {
		return RoomInfo{}, fmt.Errorf("oscar: decode room info: %w", err)
	}
	return roomInfoFrom(ru), nil
}

// roomInfoFrom pulls a RoomInfo out of a ChatRoomInfoUpdate (from ChatNav or a
// join push). Prefers the plain room name, falling back to the fully-qualified.
func roomInfoFrom(ru wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) RoomInfo {
	name, ok := ru.String(wire.ChatRoomTLVRoomName)
	if !ok {
		name, _ = ru.String(wire.ChatRoomTLVFullyQualifiedName)
	}
	return RoomInfo{
		Exchange:       ru.Exchange,
		Cookie:         ru.Cookie,
		InstanceNumber: ru.InstanceNumber,
		Name:           name,
	}
}

// RequestChatConnection asks BOS for a Chat service connection for a room. Call
// on the BOS session; the ServiceResponse arrives asynchronously. Returns the
// request ID.
func (s *Session) RequestChatConnection(room RoomInfo) (uint32, error) {
	return s.RequestService(wire.Chat, room.serviceReq())
}

var chatMsgSeq atomic.Uint64

// SendChatMessage sends a message to the room on this Chat connection.
func (s *Session) SendChatMessage(text string) error {
	return s.sendChatMessage(text, false)
}

// SendChatMessageReflected asks the server to echo the message back to us as
// well as relaying it.
//
// Normally the server relays to everyone EXCEPT the sender, so a client never
// sees its own message as it appeared on the wire. That makes it the only way
// to check that text survived relay unmodified — which matters here because the
// server rewrites chat text (it tokenizes HTML and intercepts "//roll"), and an
// encrypted payload mangled in transit would otherwise fail silently.
func (s *Session) SendChatMessageReflected(text string) error {
	return s.sendChatMessage(text, true)
}

func (s *Session) sendChatMessage(text string, reflect bool) error {
	block, err := wire.MarshalChatMessage(text)
	if err != nil {
		return fmt.Errorf("oscar: encode chat message: %w", err)
	}
	if reflect {
		block.Append(wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, []byte{1}))
	}
	msg := wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
		Cookie:       chatMsgSeq.Add(1),
		Channel:      3,
		TLVRestBlock: block,
	}
	return s.Send(wire.Chat, wire.ChatChannelMsgToHost, msg)
}

// ChatUser is one participant in a room, with what their client advertises.
type ChatUser struct {
	ScreenName string
	// Capabilities is what their client says it supports. Note this is the union
	// across ALL of that person's signed-on devices, not the one in this room —
	// so it answers "does this human run BENCchat" rather than "can the client
	// sitting in this room decrypt". Treat a missing capability as a reliable
	// "no" and a present one as a hopeful "probably".
	Capabilities []Capability
}

// DecodeChatUsers extracts participants from a ChatUsersJoined or ChatUsersLeft
// body (identical layouts).
func DecodeChatUsers(body []byte) ([]ChatUser, error) {
	var list wire.SNAC_0x0E_0x03_ChatUsersJoined
	if err := wire.UnmarshalBE(&list, bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("oscar: decode chat users: %w", err)
	}
	users := make([]ChatUser, 0, len(list.Users))
	for _, u := range list.Users {
		cu := ChatUser{ScreenName: u.ScreenName}
		if raw, ok := u.Bytes(wire.OServiceUserInfoOscarCaps); ok {
			cu.Capabilities = decodeCapabilities(raw)
		}
		users = append(users, cu)
	}
	return users, nil
}

// ChatUserNames is the screen names alone, for callers that don't care about
// capabilities.
func ChatUserNames(users []ChatUser) []string {
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.ScreenName)
	}
	return names
}

// DecodeChatMessage extracts the sender and text from a ChatChannelMsgToClient.
func DecodeChatMessage(body []byte) (sender, text string, err error) {
	var msg wire.SNAC_0x0E_0x06_ChatChannelMsgToClient
	if err := wire.UnmarshalBE(&msg, bytes.NewReader(body)); err != nil {
		return "", "", fmt.Errorf("oscar: decode chat message: %w", err)
	}
	return wire.UnmarshalChatMessage(msg.TLVRestBlock)
}

// DecodeRoomInfoUpdate reads a room-info push on the Chat connection (sent right
// after join), so the client can confirm which room it's in.
func DecodeRoomInfoUpdate(body []byte) (RoomInfo, error) {
	var ru wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate
	if err := wire.UnmarshalBE(&ru, bytes.NewReader(body)); err != nil {
		return RoomInfo{}, fmt.Errorf("oscar: decode room info update: %w", err)
	}
	return roomInfoFrom(ru), nil
}
