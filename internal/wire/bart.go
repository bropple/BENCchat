package wire

// BART (0x0010) — "Buddy ART": the store the server keeps of buddy icons (and,
// in full AIM, other decorations). BENCchat uses it read-only: when a buddy's
// presence carries an icon hash (user-info TLV 0x1D), we download the icon bytes
// by that hash and display them. open-oscar-server serves BART on the BOS
// connection, so no separate service connection is needed.

// BART (0x0010) subgroups. Only the download path is used today; upload (setting
// our own icon) is not implemented.
const (
	BARTErr           uint16 = 0x0001
	BARTUploadQuery   uint16 = 0x0002
	BARTUploadReply   uint16 = 0x0003
	BARTDownloadQuery uint16 = 0x0004
	BARTDownloadReply uint16 = 0x0005
)

// BART item types. Only the standard buddy icon is used here.
const (
	BARTTypesBuddyIcon uint16 = 0x0001
)

// BART item flags (BARTInfo.Flags).
const (
	BARTFlagsKnown  uint8 = 0x00
	BARTFlagsCustom uint8 = 0x01
)

// BARTDownloadCommand is the (server-ignored, but conventionally set) command
// byte on a download request. The server selects the item purely by hash.
const BARTDownloadCommand uint8 = 0x01

// BARTInfo identifies one BART item by content hash. On the wire the hash is a
// uint8-length-prefixed byte string — an MD5 (16 bytes) for a real buddy icon.
type BARTInfo struct {
	Flags uint8
	Hash  []byte `oscar:"len_prefix=uint8"`
}

// BARTID is a typed BART item reference: an item type plus its content hash.
// It rides in the user-info BART TLV (0x1D) and in download requests/replies.
type BARTID struct {
	Type uint16
	BARTInfo
}

// SNAC_0x10_0x04_BARTDownloadQuery asks the server for a buddy's BART item by
// hash. ScreenName is whose item, Command is conventional (0x01), and the
// embedded BARTID names the item.
type SNAC_0x10_0x04_BARTDownloadQuery struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Command    uint8
	BARTID
}

// SNAC_0x10_0x05_BARTDownloadReply returns the raw item bytes. Data is the icon
// image (PNG/GIF/JPEG); it is empty for a not-found or cleared item.
type SNAC_0x10_0x05_BARTDownloadReply struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	BARTID     BARTID
	Data       []byte `oscar:"len_prefix=uint16"`
}
