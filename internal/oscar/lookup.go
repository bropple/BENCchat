package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// FindByEmail asks the server for the screen name registered to an email
// address. The reply arrives asynchronously: a UserLookupFindReply on a match,
// or a UserLookupErr when nothing matches.
func (s *Session) FindByEmail(email string) error {
	req := wire.SNAC_0x0A_0x02_UserLookupFindByEmail{Email: []byte(email)}
	if err := s.Send(wire.UserLookup, wire.UserLookupFindByEmail, req); err != nil {
		return fmt.Errorf("oscar: find by email: %w", err)
	}
	return nil
}

// DecodeFindReply extracts the matched screen name from a UserLookupFindReply.
func DecodeFindReply(body []byte) (string, error) {
	var reply wire.SNAC_0x0A_0x03_UserLookupFindReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return "", fmt.Errorf("oscar: decode lookup reply: %w", err)
	}
	name, _ := reply.String(wire.UserLookupTLVEmailAddress)
	return name, nil
}
