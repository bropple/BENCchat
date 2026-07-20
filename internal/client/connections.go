package client

import (
	"errors"
	"sync"

	"github.com/benco-holdings/benchat/internal/oscar"
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

	// On accept, the buddy is no longer pending — presence will now flow. The
	// server has already cleared its own pending row; reconcile the mirror and
	// republish so the UI drops the "awaiting acceptance" marker.
	//
	// On DECLINE the request is over, so the pending buddy is removed rather than
	// left marked pending forever. Off the read loop, since a feedbag delete is a
	// network round trip and this handler must not block. The buddy-list refresh
	// that follows clears it from the UI.
	if res.Accepted {
		c.mu.Lock()
		session := c.session
		c.mu.Unlock()
		if session != nil {
			c.publishBuddyList(session.ClearBuddyPending(res.ScreenName))
		}
	} else {
		go func() {
			if err := c.RemoveBuddy(res.ScreenName); err != nil {
				c.log.Warn("could not remove declined pending buddy", "screen_name", res.ScreenName, "err", err)
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
