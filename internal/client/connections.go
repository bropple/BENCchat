package client

import (
	"bytes"
	"errors"
	"sync"

	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// Consensual buddy connections, client layer.
//
// Adding an AIM buddy requires the other person's authorization before presence
// and messaging flow. This file surfaces the two inbound halves to the app —
// "X wants to connect" and "your request was answered" — and lets the app
// approve or decline. The state changes (pending markers) ride the buddy list
// the app already binds to; these callbacks are the notifications on top.

// connectionRequestHandler is notified when someone asks to connect to us.
type connectionRequestHandler func(req oscar.ConnectionRequest)

// connectionResponseHandler is notified when someone answers a request we made.
type connectionResponseHandler func(res oscar.ConnectionResponse)

// connHandlers holds the app-layer callbacks. Guarded by its own mutex because
// they are set once at sign-on but read on the read-loop goroutine.
type connHandlers struct {
	mu       sync.Mutex
	request  connectionRequestHandler
	response connectionResponseHandler
}

// SetConnectionRequestHandler registers the callback for inbound requests.
func (c *Client) SetConnectionRequestHandler(fn connectionRequestHandler) {
	c.conn.mu.Lock()
	c.conn.request = fn
	c.conn.mu.Unlock()
}

// SetConnectionResponseHandler registers the callback for inbound responses.
func (c *Client) SetConnectionResponseHandler(fn connectionResponseHandler) {
	c.conn.mu.Lock()
	c.conn.response = fn
	c.conn.mu.Unlock()
}

// handleConnectionRequest decodes an inbound SNAC(0x13,0x19) and surfaces it.
func (c *Client) handleConnectionRequest(body []byte) {
	req, err := oscar.DecodeConnectionRequest(body)
	if err != nil {
		c.log.Warn("could not decode connection request", "err", err)
		return
	}
	c.conn.mu.Lock()
	fn := c.conn.request
	c.conn.mu.Unlock()
	if fn != nil {
		fn(req)
	}
}

// handleConnectionResponse decodes an inbound SNAC(0x13,0x1B), reconciles the
// buddy list, and surfaces the answer.
func (c *Client) handleConnectionResponse(body []byte) {
	res, err := oscar.DecodeConnectionResponse(body)
	if err != nil {
		c.log.Warn("could not decode connection response", "err", err)
		return
	}

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	// Was this a reply to a request WE had out (they declined), or did they sever
	// an established connection (they removed us)? Both arrive as Accepted=0, so
	// tell them apart by whether the buddy is still marked pending on our side —
	// filled here so the app can notify on a decline but stay silent on a removal.
	if session != nil {
		for _, b := range session.BuddyList().Buddies {
			if state.NormalizeScreenName(b.ScreenName) == state.NormalizeScreenName(res.ScreenName) {
				res.WasPending = b.Pending
				break
			}
		}
	}

	// On accept, the buddy is no longer pending — presence will now flow. The
	// server has already cleared its own pending row; reconcile the mirror and
	// republish so the UI drops the "awaiting acceptance" marker.
	//
	// On DECLINE or REMOVAL (both Accepted=0) the connection is gone, so drop the
	// buddy rather than leaving a dead row. Off the read loop, since a feedbag
	// delete is a network round trip and this handler must not block. The
	// buddy-list refresh that follows clears it from the UI.
	if res.Accepted {
		if session != nil {
			// Record acceptance and clear pending under pendingMu, so a re-add-as-
			// pending racing in from this add's AuthRequired can't publish a stale
			// pending snapshot over this clear (it takes the same lock and re-reads).
			c.markAccepted(res.ScreenName)
			c.pendingMu.Lock()
			c.publishBuddyList(session.ClearBuddyPending(res.ScreenName))
			c.pendingMu.Unlock()
		}
	} else {
		go func() {
			if err := c.RemoveBuddy(res.ScreenName); err != nil {
				c.log.Warn("could not remove severed connection", "screen_name", res.ScreenName, "err", err)
			}
		}()
	}

	c.conn.mu.Lock()
	fn := c.conn.response
	c.conn.mu.Unlock()
	if fn != nil {
		fn(res)
	}
}

// handlePreAuthorized processes a SNAC(0x13,0x15): someone approved a connection
// request we made, but the server had no pending row for us on file (a fast
// approval, before our re-add-as-pending reached the server), so it sent this
// instead of the usual 0x1B. Treat it as an acceptance: clear our pending marker
// and record it so a late re-add can't re-strand them, then notify the app.
func (c *Client) handlePreAuthorized(body []byte) {
	var snac wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy
	if err := wire.UnmarshalBE(&snac, bytes.NewReader(body)); err != nil {
		c.log.Warn("could not decode pre-authorized buddy", "err", err)
		return
	}

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}

	c.markAccepted(snac.ScreenName)
	c.pendingMu.Lock()
	c.publishBuddyList(session.ClearBuddyPending(snac.ScreenName))
	c.pendingMu.Unlock()

	c.conn.mu.Lock()
	fn := c.conn.response
	c.conn.mu.Unlock()
	if fn != nil {
		fn(oscar.ConnectionResponse{ScreenName: snac.ScreenName, Accepted: true})
	}
}

// ApproveConnection approves an inbound request and, per BENCchat's mutual-add
// rule, adds the requester back as a buddy. The updated list is republished.
func (c *Client) ApproveConnection(screenName string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.ApproveConnection(screenName, "")
	})
}

// DeclineConnection declines an inbound request. No reciprocal add.
func (c *Client) DeclineConnection(screenName string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.DeclineConnection(screenName)
}
