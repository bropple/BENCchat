package wire

import (
	"bytes"
	"testing"
)

func userInfo(sn string) TLVUserInfo {
	return TLVUserInfo{ScreenName: sn, WarningLevel: 0, TLVBlock: TLVBlock{}}
}

// The Chat service request carries a room-info block; it must round-trip so the
// server can find the room.
func TestServiceRequestRoomInfoRoundTrip(t *testing.T) {
	roomInfo := ServiceReqRoomInfo{Exchange: 4, Cookie: "4-0-lobby", InstanceNumber: 0}
	var ib bytes.Buffer
	if err := MarshalBE(roomInfo, &ib); err != nil {
		t.Fatalf("marshal room info: %v", err)
	}
	req := SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: Chat,
		TLVRestBlock: TLVRestBlock{TLVList: TLVList{
			NewTLVBE(OServiceServiceReqTLVRoomInfo, ib.Bytes()),
		}},
	}
	var buf bytes.Buffer
	if err := MarshalBE(req, &buf); err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var got SNAC_0x01_0x04_OServiceServiceRequest
	if err := UnmarshalBE(&got, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.FoodGroup != Chat {
		t.Fatalf("foodgroup = %#x, want Chat", got.FoodGroup)
	}
	raw, ok := got.Bytes(OServiceServiceReqTLVRoomInfo)
	if !ok {
		t.Fatal("room-info TLV missing")
	}
	var ri ServiceReqRoomInfo
	if err := UnmarshalBE(&ri, bytes.NewReader(raw)); err != nil {
		t.Fatalf("unmarshal room info: %v", err)
	}
	if ri.Cookie != "4-0-lobby" || ri.Exchange != 4 {
		t.Fatalf("room info round-trip wrong: %+v", ri)
	}
}

// The service response (host + cookie TLVs) must decode so we know where to
// reconnect and with what cookie.
func TestServiceResponseDecode(t *testing.T) {
	cookie := bytes.Repeat([]byte{0xAB}, 256)
	resp := SNAC_0x01_0x05_OServiceServiceResponse{
		TLVRestBlock: TLVRestBlock{TLVList: TLVList{
			NewTLVBE(OServiceTLVTagsGroupID, Chat),
			NewTLVBE(OServiceTLVTagsReconnectHere, []byte("chat.example.com:5191")),
			NewTLVBE(OServiceTLVTagsLoginCookie, cookie),
		}},
	}
	var buf bytes.Buffer
	if err := MarshalBE(resp, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SNAC_0x01_0x05_OServiceServiceResponse
	if err := UnmarshalBE(&got, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	host, _ := got.String(OServiceTLVTagsReconnectHere)
	gotCookie, _ := got.Bytes(OServiceTLVTagsLoginCookie)
	group, _ := got.Uint16BE(OServiceTLVTagsGroupID)
	if host != "chat.example.com:5191" || len(gotCookie) != 256 || group != Chat {
		t.Fatalf("response decode wrong: host=%q cookieLen=%d group=%#x", host, len(gotCookie), group)
	}
}

// The room-info update (used for create requests, ChatNav replies, and join
// pushes) must round-trip including its name TLV.
func TestChatRoomInfoUpdateRoundTrip(t *testing.T) {
	create := NewChatCreateRoom("lobby")
	if create.Cookie != "create" {
		t.Fatalf("create cookie = %q, want \"create\"", create.Cookie)
	}
	var buf bytes.Buffer
	if err := MarshalBE(create, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SNAC_0x0E_0x02_ChatRoomInfoUpdate
	if err := UnmarshalBE(&got, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	name, ok := got.String(ChatRoomTLVRoomName)
	if !ok || name != "lobby" || got.Exchange != 4 || got.DetailLevel != 0x02 {
		t.Fatalf("room info round-trip wrong: %+v name=%q", got, name)
	}
}

// The occupant list has no count prefix (greedy to EOF); both users must survive.
func TestChatUsersJoinedRoundTrip(t *testing.T) {
	joined := SNAC_0x0E_0x03_ChatUsersJoined{Users: []TLVUserInfo{userInfo("rtriy"), userInfo("alice")}}
	var buf bytes.Buffer
	if err := MarshalBE(joined, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SNAC_0x0E_0x03_ChatUsersJoined
	if err := UnmarshalBE(&got, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Users) != 2 || got.Users[0].ScreenName != "rtriy" || got.Users[1].ScreenName != "alice" {
		t.Fatalf("occupant list wrong: %+v", got.Users)
	}
}

// A room message must survive the full send-shape → receive-shape round-trip:
// build the message block, wrap it as the server delivers it (with sender info),
// and decode sender + text back. Covers ASCII and non-ASCII (UCS-2) text.
func TestChatMessageRoundTrip(t *testing.T) {
	for _, text := range []string{"hello room", "Привет 世界"} {
		msg, err := MarshalChatMessage(text)
		if err != nil {
			t.Fatalf("marshal %q: %v", text, err)
		}
		// The server prepends the sender's info before relaying.
		var senderBuf bytes.Buffer
		if err := MarshalBE(userInfo("rtriy"), &senderBuf); err != nil {
			t.Fatal(err)
		}
		delivered := TLVRestBlock{TLVList: append(
			TLVList{NewTLVBE(ChatTLVSenderInformation, senderBuf.Bytes())},
			msg.TLVList...,
		)}

		sender, gotText, err := UnmarshalChatMessage(delivered)
		if err != nil {
			t.Fatalf("unmarshal %q: %v", text, err)
		}
		if sender != "rtriy" {
			t.Fatalf("sender = %q, want rtriy", sender)
		}
		if gotText != text {
			t.Fatalf("text round-trip: got %q, want %q", gotText, text)
		}
	}
}
