package oscar

import (
	"bytes"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// DirResult is one directory match and the fields the server returned for it.
type DirResult struct {
	ScreenName string
	FirstName  string
	LastName   string
	City       string
	State      string
	Country    string
}

// SearchDirectoryByName searches the user directory by first and/or last name.
// The server needs at least one to be non-empty. Results arrive asynchronously
// as an ODirInfoReply on the read loop.
func (s *Session) SearchDirectoryByName(firstName, lastName string) error {
	var tlvs wire.TLVList
	if firstName != "" {
		tlvs = append(tlvs, wire.NewTLVBE(wire.ODirTLVFirstName, []byte(firstName)))
	}
	if lastName != "" {
		tlvs = append(tlvs, wire.NewTLVBE(wire.ODirTLVLastName, []byte(lastName)))
	}
	req := wire.SNAC_0x0F_0x02_InfoQuery{TLVRestBlock: wire.TLVRestBlock{TLVList: tlvs}}
	if err := s.Send(wire.ODir, wire.ODirInfoQuery, req); err != nil {
		return fmt.Errorf("oscar: directory search: %w", err)
	}
	return nil
}

// DecodeDirReply parses an ODirInfoReply into its result rows. ok is false when
// the search itself didn't run cleanly (a NameMissing or TooManyResults status),
// which the UI reports differently from an empty-but-successful result set.
func DecodeDirReply(body []byte) (results []DirResult, ok bool, err error) {
	var reply wire.SNAC_0x0F_0x03_InfoReply
	if err := wire.UnmarshalBE(&reply, bytes.NewReader(body)); err != nil {
		return nil, false, fmt.Errorf("oscar: decode directory reply: %w", err)
	}
	if reply.Status != wire.ODirStatusOK {
		return nil, false, nil
	}
	out := make([]DirResult, 0, len(reply.Results))
	for i := range reply.Results {
		block := reply.Results[i]
		r := DirResult{}
		r.ScreenName, _ = block.String(wire.ODirTLVScreenName)
		r.FirstName, _ = block.String(wire.ODirTLVFirstName)
		r.LastName, _ = block.String(wire.ODirTLVLastName)
		r.City, _ = block.String(wire.ODirTLVCity)
		r.State, _ = block.String(wire.ODirTLVState)
		r.Country, _ = block.String(wire.ODirTLVCountry)
		if r.ScreenName != "" {
			out = append(out, r)
		}
	}
	return out, true, nil
}
