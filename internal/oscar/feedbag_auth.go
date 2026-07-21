package oscar

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// Buddy authorization — the consensual-connection flow.
//
// Adding an AIM buddy requires the target's authorization before presence (and
// messaging) flows. The server drives it with four SNACs; this file is the
// client half:
//
//   - inbound  SNAC(0x13,0x19): someone wants to connect to us      → decode
//   - outbound SNAC(0x13,0x1A): our approve/decline of such a request → send
//   - inbound  SNAC(0x13,0x1B): the answer to a request WE made       → decode
//
// The two inbound SNACs carry a leading extended-info TLVLBlock, but the server
// sets SNACFlagsExtendedInfo on them, so the transport (DecodeSNAC) has already
// stripped that block by the time a body reaches these helpers. The documented
// wire structs still include the block for on-wire fidelity, so we re-frame the
// stripped body with an empty (zero-length) block before decoding into them —
// which keeps a single canonical struct instead of a decode-only variant.
var emptyExtInfoBlock = []byte{0x00, 0x00}

// ConnectionRequest is an inbound "X wants to connect".
type ConnectionRequest struct {
	// ScreenName is who wants to connect to us.
	ScreenName string
	// Reason is the optional note they attached.
	Reason string
}

// DecodeConnectionRequest decodes an inbound SNAC(0x13,0x19).
func DecodeConnectionRequest(body []byte) (ConnectionRequest, error) {
	var snac wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient
	framed := append(append([]byte(nil), emptyExtInfoBlock...), body...)
	if err := wire.UnmarshalBE(&snac, bytes.NewReader(framed)); err != nil {
		return ConnectionRequest{}, fmt.Errorf("oscar: decode connection request: %w", err)
	}
	return ConnectionRequest{ScreenName: snac.ScreenName, Reason: snac.Reason}, nil
}

// ConnectionResponse is the answer to a request we made.
type ConnectionResponse struct {
	// ScreenName is who answered.
	ScreenName string
	// Accepted reports whether they approved the connection.
	Accepted bool
	// Reason is the optional note on a decline.
	Reason string
	// WasPending reports whether this arrived against a request WE had
	// outstanding (they declined) versus an established connection they severed
	// (they removed us). The wire is identical for both — Accepted=0 either way —
	// so the caller fills this from the buddy's pending state at receipt, and the
	// app uses it to notify on a decline but stay silent on a removal.
	WasPending bool
}

// DecodeConnectionResponse decodes an inbound SNAC(0x13,0x1B).
func DecodeConnectionResponse(body []byte) (ConnectionResponse, error) {
	var snac wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient
	framed := append(append([]byte(nil), emptyExtInfoBlock...), body...)
	if err := wire.UnmarshalBE(&snac, bytes.NewReader(framed)); err != nil {
		return ConnectionResponse{}, fmt.Errorf("oscar: decode connection response: %w", err)
	}
	return ConnectionResponse{
		ScreenName: snac.ScreenName,
		Accepted:   snac.Accepted != 0,
		Reason:     snac.Reason,
	}, nil
}

// RespondAuthorization answers an inbound connection request from screenName,
// approving or declining it. It sends SNAC(0x13,0x1A) — no extended-info block
// on this direction, so it goes out as a plain SNAC.
func (s *Session) RespondAuthorization(screenName string, accepted bool, reason string) error {
	var acc uint8
	if accepted {
		acc = 1
	}
	return s.Send(wire.Feedbag, wire.FeedbagRespondAuthorizeToHost,
		wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
			ScreenName: screenName,
			Accepted:   acc,
			Reason:     reason,
		})
}

// ApproveConnection approves screenName's request to connect AND adds them back
// as a buddy, returning the updated list.
//
// BENCO: the reciprocal add is the ONE deliberate departure from AIM. In AIM,
// approving a request only lets the requester see you; here a connection is
// mutual, so approving someone also connects you to them. The server records
// the matching reciprocal authorization when it processes the 0x1A above, so
// this add is already authorized and stores without a second round trip.
func (s *Session) ApproveConnection(screenName, group string) (BuddyList, error) {
	if err := s.RespondAuthorization(screenName, true, ""); err != nil {
		return BuddyList{}, err
	}
	list, err := s.AddBuddy(screenName, group)
	if err != nil {
		if errors.Is(err, ErrAlreadyBuddy) {
			// Already connected to them — the approval still stands, the reciprocal
			// add is simply redundant.
			return s.BuddyList(), nil
		}
		return BuddyList{}, err
	}
	return list, nil
}

// DeclineConnection declines screenName's request to connect. No reciprocal add.
func (s *Session) DeclineConnection(screenName string) error {
	return s.RespondAuthorization(screenName, false, "")
}

// ReAddBuddyPending re-adds an already-known buddy with the pending
// authorization tag, so the server stores it as a pending row after having
// replied FeedbagStatusAuthRequired. Returns the updated list, in which the
// buddy now reads as Pending.
func (s *Session) ReAddBuddyPending(screenName string) (BuddyList, error) {
	return s.applyEdit(func() ([]editOp, error) { return s.feedbag.MarkBuddyPending(screenName) })
}

// ClearBuddyPending drops the pending tag from a buddy in the local mirror and
// returns the updated list. Used when the server tells us a request we made was
// accepted: the server has already cleared its own pending row, so this only
// reconciles the mirror — no SNAC is sent.
func (s *Session) ClearBuddyPending(screenName string) BuddyList {
	if s.feedbag == nil {
		return s.buddyList
	}
	s.feedbag.ClearBuddyPending(screenName)
	s.buddyList = s.feedbag.BuddyList()
	return s.buddyList
}

// MarkBuddyPending sets the pending authorization tag on an existing buddy and
// returns the insert op to re-store it. Returns nil ops if the buddy is already
// pending (nothing to do) and an error if the buddy isn't on the list.
func (f *Feedbag) MarkBuddyPending(screenName string) ([]editOp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	i := f.findBuddy(screenName)
	if i < 0 {
		return nil, fmt.Errorf("oscar: %q is not on your buddy list", screenName)
	}
	if f.items[i].HasTag(wire.FeedbagAttributesPending) {
		return nil, nil
	}
	buddy := f.items[i]
	// A copy shares the TLV backing slice; give it its own so Set can't disturb
	// the mirror's other view of this item.
	buddy.TLVList = append(wire.TLVList(nil), buddy.TLVList...)
	buddy.Set(wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}))
	f.items[i] = buddy
	return []editOp{
		{wire.FeedbagInsertItem, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{buddy}}},
	}, nil
}

// ClearBuddyPending removes the pending tag from a buddy in the local mirror.
// Reports whether anything changed.
func (f *Feedbag) ClearBuddyPending(screenName string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	i := f.findBuddy(screenName)
	if i < 0 || !f.items[i].HasTag(wire.FeedbagAttributesPending) {
		return false
	}
	buddy := f.items[i]
	buddy.TLVList = append(wire.TLVList(nil), buddy.TLVList...)
	buddy.Remove(wire.FeedbagAttributesPending)
	f.items[i] = buddy
	return true
}
