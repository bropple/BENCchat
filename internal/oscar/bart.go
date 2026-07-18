package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// RequestBuddyIcon asks the server for a buddy's icon image by its BART hash.
// The reply (BARTDownloadReply) arrives asynchronously on the read loop; there
// is no synchronous return of the bytes here. The hash comes from the buddy's
// presence (user-info TLV 0x1D); the server looks the item up by hash alone.
func (s *Session) RequestBuddyIcon(screenName string, iconType uint16, flags uint8, hash []byte) error {
	return s.Send(wire.BART, wire.BARTDownloadQuery, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: screenName,
		Command:    wire.BARTDownloadCommand,
		BARTID: wire.BARTID{
			Type:     iconType,
			BARTInfo: wire.BARTInfo{Flags: flags, Hash: hash},
		},
	})
}

// BuddyIcon is a decoded BART download reply: whose icon it is, the hash the
// server keyed it under, and the raw image bytes (empty for not-found/cleared).
type BuddyIcon struct {
	ScreenName string
	Hash       []byte
	Data       []byte
}

// DecodeBARTDownloadReply parses a BARTDownloadReply body into a BuddyIcon.
func DecodeBARTDownloadReply(body []byte) (BuddyIcon, error) {
	var reply wire.SNAC_0x10_0x05_BARTDownloadReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return BuddyIcon{}, fmt.Errorf("oscar: decode BART download reply: %w", err)
	}
	return BuddyIcon{
		ScreenName: reply.ScreenName,
		Hash:       reply.BARTID.Hash,
		Data:       reply.Data,
	}, nil
}
