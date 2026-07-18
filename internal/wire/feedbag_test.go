package wire

import (
	"bytes"
	"testing"
)

// TestTLVUserInfoUsesCountPrefix pins the single most dangerous layout detail in
// this protocol: TLVUserInfo's block is prefixed with the NUMBER of TLVs, while
// FeedbagItem's block is prefixed with its BYTE LENGTH. Both are uint16 on the
// wire, so confusing them decodes cleanly right up until the stream
// desynchronizes.
func TestTLVUserInfoUsesCountPrefix(t *testing.T) {
	u := TLVUserInfo{ScreenName: "triy", WarningLevel: 0}
	u.Append(NewTLVBE(OServiceUserInfoUserFlags, uint16(0x0010)))
	u.Append(NewTLVBE(OServiceUserInfoStatus, uint32(0)))

	buf := &bytes.Buffer{}
	if err := MarshalBE(u, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x04, 't', 'r', 'i', 'y', // uint8-prefixed screen name
		0x00, 0x00, // warning level
		0x00, 0x02, // TLV COUNT = 2 (not byte length, which would be 14)
		0x00, 0x01, 0x00, 0x02, 0x00, 0x10, // TLV 0x01 = uint16 0x0010
		0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // TLV 0x06 = uint32 0
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("TLVUserInfo:\n got %x\nwant %x", buf.Bytes(), want)
	}

	var out TLVUserInfo
	if err := UnmarshalBE(&out, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ScreenName != "triy" || len(out.TLVList) != 2 {
		t.Fatalf("round trip: got %+v", out)
	}
}

// TestFeedbagItemUsesLengthPrefix is the counterpart: a byte-length prefix, and
// a uint16-prefixed name (every other screen name in OSCAR is uint8-prefixed).
func TestFeedbagItemUsesLengthPrefix(t *testing.T) {
	item := FeedbagItem{Name: "rtriy", GroupID: 1, ItemID: 2, ClassID: FeedbagClassIdBuddy}
	item.Append(NewTLVBE(FeedbagAttributesAlias, []byte("R. Triy")))

	buf := &bytes.Buffer{}
	if err := MarshalBE(item, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x00, 0x05, 'r', 't', 'r', 'i', 'y', // uint16-prefixed name
		0x00, 0x01, // group ID
		0x00, 0x02, // item ID
		0x00, 0x00, // class ID (buddy)
		0x00, 0x0B, // TLV BYTE LENGTH = 11 (not count, which would be 1)
		0x01, 0x31, 0x00, 0x07, 'R', '.', ' ', 'T', 'r', 'i', 'y',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("FeedbagItem:\n got %x\nwant %x", buf.Bytes(), want)
	}
}

func TestFeedbagReplyRoundTrip(t *testing.T) {
	root := FeedbagItem{Name: "", GroupID: 0, ItemID: 0, ClassID: FeedbagClassIdGroup}
	root.Append(NewTLVBE(FeedbagAttributesOrder, []byte{0x00, 0x01}))

	group := FeedbagItem{Name: "BENCO", GroupID: 1, ItemID: 0, ClassID: FeedbagClassIdGroup}
	group.Append(NewTLVBE(FeedbagAttributesOrder, []byte{0x00, 0x0A}))

	buddy := FeedbagItem{Name: "rtriy", GroupID: 1, ItemID: 10, ClassID: FeedbagClassIdBuddy}

	in := SNAC_0x13_0x06_FeedbagReply{
		Version:    0,
		Items:      []FeedbagItem{root, group, buddy},
		LastUpdate: 1234567890,
	}

	buf := &bytes.Buffer{}
	if err := MarshalBE(in, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out SNAC_0x13_0x06_FeedbagReply
	if err := UnmarshalBE(&out, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Items) != 3 {
		t.Fatalf("item count = %d, want 3", len(out.Items))
	}
	if out.LastUpdate != 1234567890 {
		t.Errorf("LastUpdate = %d", out.LastUpdate)
	}
	if !out.Items[0].IsRoot() {
		t.Error("item 0 should be the root group (class Group, GroupID 0)")
	}
	if !out.Items[1].IsGroup() {
		t.Error("item 1 should be a group")
	}
	if !out.Items[2].IsBuddy() {
		t.Error("item 2 should be a buddy")
	}
	if name := out.Items[2].Name; name != "rtriy" {
		t.Errorf("buddy name = %q", name)
	}
}

func TestFeedbagItemClassification(t *testing.T) {
	// The root is distinguished from an ordinary group only by GroupID == 0.
	root := FeedbagItem{ClassID: FeedbagClassIdGroup, GroupID: 0}
	if !root.IsRoot() || root.IsGroup() {
		t.Error("class Group + GroupID 0 must classify as root, not group")
	}
	group := FeedbagItem{ClassID: FeedbagClassIdGroup, GroupID: 3}
	if group.IsRoot() || !group.IsGroup() {
		t.Error("class Group + GroupID != 0 must classify as group, not root")
	}
}

func TestUint16SliceBE(t *testing.T) {
	var l TLVList
	l.Append(NewTLVBE(FeedbagAttributesOrder, []byte{0x00, 0x01, 0x00, 0x0A, 0xFF, 0xFF}))

	got, ok := l.Uint16SliceBE(FeedbagAttributesOrder)
	if !ok {
		t.Fatal("Uint16SliceBE reported not-found for a valid array")
	}
	want := []uint16{1, 10, 0xFFFF}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestUint16SliceBERejectsOddLength(t *testing.T) {
	// A trailing odd byte means the value isn't a uint16 array; reporting
	// not-found beats silently returning a truncated ordering list.
	var l TLVList
	l.Append(NewTLVBE(FeedbagAttributesOrder, []byte{0x00, 0x01, 0x02}))

	if _, ok := l.Uint16SliceBE(FeedbagAttributesOrder); ok {
		t.Fatal("odd-length value must not decode as a uint16 array")
	}
}

func TestUint16SliceBEEmpty(t *testing.T) {
	// An empty group has an empty order list — valid, not an error.
	var l TLVList
	l.Append(NewTLVBE(FeedbagAttributesOrder, []byte{}))

	got, ok := l.Uint16SliceBE(FeedbagAttributesOrder)
	if !ok || len(got) != 0 {
		t.Fatalf("empty order list: got %v, ok=%v; want empty and ok", got, ok)
	}
}

func TestUserInfoAwayAndIdle(t *testing.T) {
	// Away is signalled by the UserFlags bit — this is what the server itself
	// tests, rather than the Status TLV's away bit.
	u := TLVUserInfo{ScreenName: "triy"}
	u.Append(NewTLVBE(OServiceUserInfoUserFlags, OServiceUserFlagOSCARFree|OServiceUserFlagUnavailable))
	if !u.IsAway() {
		t.Error("IsAway should be true when the Unavailable flag is set")
	}

	// Not idle: the server omits TLV 0x04 entirely rather than sending zero.
	if _, idle := u.IdleMinutes(); idle {
		t.Error("IdleMinutes should report not-idle when TLV 0x04 is absent")
	}

	u.Append(NewTLVBE(OServiceUserInfoIdleTime, uint16(15)))
	mins, idle := u.IdleMinutes()
	if !idle || mins != 15 {
		t.Errorf("IdleMinutes = %d (idle=%v), want 15 minutes", mins, idle)
	}
}

func TestUserInfoNotAwayByDefault(t *testing.T) {
	u := TLVUserInfo{ScreenName: "triy"}
	u.Append(NewTLVBE(OServiceUserInfoUserFlags, OServiceUserFlagOSCARFree))
	if u.IsAway() {
		t.Error("a plain AIM user should not report away")
	}
	if u.IsInvisible() {
		t.Error("a plain AIM user should not report invisible")
	}
}

// TestBuddyDepartedTolerateEmptyTLVBlock covers the server's degenerate
// departure body: zero TLVs on the normal path.
func TestBuddyDepartedTolerateEmptyTLVBlock(t *testing.T) {
	raw := []byte{
		0x04, 't', 'r', 'i', 'y',
		0x00, 0x00, // warning level
		0x00, 0x00, // TLV count = 0
	}
	var d SNAC_0x03_0x0C_BuddyDeparted
	if err := UnmarshalBE(&d, bytes.NewReader(raw)); err != nil {
		t.Fatalf("decode departed with no TLVs: %v", err)
	}
	if d.ScreenName != "triy" {
		t.Errorf("ScreenName = %q", d.ScreenName)
	}
	if len(d.TLVList) != 0 {
		t.Errorf("TLV count = %d, want 0", len(d.TLVList))
	}
}
