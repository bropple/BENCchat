package oscar

import (
	"bytes"
	"testing"

	"github.com/benco-holdings/benchat/internal/wire"
)

func md5Hash() []byte {
	h := make([]byte, 16)
	for i := range h {
		h[i] = byte(i + 1)
	}
	return h
}

// A buddy arrival carrying a BART icon TLV (0x1D) must yield the icon hash on
// the decoded UserInfo — that's the trigger for downloading the image.
func TestDecodeUserInfoIcon(t *testing.T) {
	hash := md5Hash()
	id := wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash},
	}
	info := wire.TLVUserInfo{
		ScreenName:   "iconbuddy",
		WarningLevel: 0,
		TLVBlock: wire.TLVBlock{TLVList: wire.TLVList{
			wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, id),
		}},
	}
	var buf bytes.Buffer
	if err := wire.MarshalBE(info, &buf); err != nil {
		t.Fatalf("marshal user info: %v", err)
	}

	got, err := DecodeUserInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeUserInfo: %v", err)
	}
	if !bytes.Equal(got.IconHash, hash) {
		t.Fatalf("IconHash = %x, want %x", got.IconHash, hash)
	}
	if got.IconType != wire.BARTTypesBuddyIcon || got.IconFlags != wire.BARTFlagsCustom {
		t.Fatalf("icon meta: type=%#x flags=%#x", got.IconType, got.IconFlags)
	}
}

// The 5-byte "cleared icon" sentinel (and any non-16-byte hash) must NOT be
// treated as a real icon, so we don't try to download a phantom image.
func TestDecodeUserInfoClearedIcon(t *testing.T) {
	id := wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Flags: 0, Hash: []byte{0x02, 0x01, 0xd2, 0x04, 0x72}},
	}
	info := wire.TLVUserInfo{
		ScreenName: "cleared",
		TLVBlock: wire.TLVBlock{TLVList: wire.TLVList{
			wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, id),
		}},
	}
	var buf bytes.Buffer
	if err := wire.MarshalBE(info, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeUserInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeUserInfo: %v", err)
	}
	if got.IconHash != nil {
		t.Fatalf("cleared/short hash treated as icon: %x", got.IconHash)
	}
}

// A buddy with no BART TLV at all decodes to no icon.
func TestDecodeUserInfoNoIcon(t *testing.T) {
	info := wire.TLVUserInfo{ScreenName: "plain"}
	var buf bytes.Buffer
	if err := wire.MarshalBE(info, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeUserInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeUserInfo: %v", err)
	}
	if got.IconHash != nil {
		t.Fatalf("unexpected icon: %x", got.IconHash)
	}
}

// The download request/reply must survive a marshal/unmarshal round-trip: the
// embedded BARTID and the length-prefixed image bytes are the fiddly parts.
func TestBARTDownloadRoundTrip(t *testing.T) {
	hash := md5Hash()
	imgBytes := []byte("\x89PNG\r\n\x1a\n....fake png bytes....")

	query := wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: "buddy",
		Command:    wire.BARTDownloadCommand,
		BARTID: wire.BARTID{
			Type:     wire.BARTTypesBuddyIcon,
			BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash},
		},
	}
	var qbuf bytes.Buffer
	if err := wire.MarshalBE(query, &qbuf); err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	var gotQuery wire.SNAC_0x10_0x04_BARTDownloadQuery
	if err := wire.UnmarshalBE(&gotQuery, bytes.NewReader(qbuf.Bytes())); err != nil {
		t.Fatalf("unmarshal query: %v", err)
	}
	if gotQuery.ScreenName != "buddy" || !bytes.Equal(gotQuery.Hash, hash) {
		t.Fatalf("query round-trip: %+v", gotQuery)
	}

	reply := wire.SNAC_0x10_0x05_BARTDownloadReply{
		ScreenName: "buddy",
		BARTID:     query.BARTID,
		Data:       imgBytes,
	}
	var rbuf bytes.Buffer
	if err := wire.MarshalBE(reply, &rbuf); err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	icon, err := DecodeBARTDownloadReply(rbuf.Bytes())
	if err != nil {
		t.Fatalf("DecodeBARTDownloadReply: %v", err)
	}
	if icon.ScreenName != "buddy" || !bytes.Equal(icon.Hash, hash) || !bytes.Equal(icon.Data, imgBytes) {
		t.Fatalf("reply round-trip: sn=%q hash=%x len(data)=%d", icon.ScreenName, icon.Hash, len(icon.Data))
	}
}
