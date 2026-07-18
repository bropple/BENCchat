package oscar

import (
	"bytes"
	"context"
	"fmt"

	"github.com/benco-holdings/benchat/internal/wire"
)

// This file adds support for the extra service connections OSCAR uses beyond
// BOS — specifically the ChatNav and per-room Chat connections for multi-user
// chat. The pattern: on the BOS connection, ask for a service (ServiceRequest);
// the server replies (ServiceResponse) with a host + cookie; dial that host and
// run the same OSERVICE handshake BOS uses, presenting the cookie.

// ServiceGrant is a decoded ServiceResponse: where to reconnect and with what.
type ServiceGrant struct {
	FoodGroup uint16 // the service being granted (echoed back)
	Host      string // host:port to dial
	Cookie    []byte // present in the new connection's signon frame
}

// SendReq sends a client-initiated SNAC and returns its request ID, so the
// caller can correlate the asynchronous reply that arrives on the read loop.
// Unlike Send it does not rate-pace — it is for the infrequent request/reply
// handshakes (service requests, room lookups), not message traffic.
func (s *Session) SendReq(fg, sg uint16, body any) (uint32, error) {
	id := s.nextReqID()
	err := s.conn.WriteSNAC(wire.SNACFrame{FoodGroup: fg, SubGroup: sg, RequestID: id}, body)
	return id, err
}

// RequestService asks (on this BOS connection) for access to another service.
// roomInfo is required for a Chat request (it names the room) and nil otherwise.
// Returns the request ID; the ServiceResponse arrives asynchronously.
func (s *Session) RequestService(foodGroup uint16, roomInfo *wire.ServiceReqRoomInfo) (uint32, error) {
	req := wire.SNAC_0x01_0x04_OServiceServiceRequest{FoodGroup: foodGroup}
	if roomInfo != nil {
		var buf bytes.Buffer
		if err := wire.MarshalBE(*roomInfo, &buf); err != nil {
			return 0, fmt.Errorf("oscar: marshal room info: %w", err)
		}
		req.Append(wire.NewTLVBE(wire.OServiceServiceReqTLVRoomInfo, buf.Bytes()))
	}
	return s.SendReq(wire.OService, wire.OServiceServiceRequest, req)
}

// DecodeServiceGrant parses a ServiceResponse into the host + cookie to dial.
func DecodeServiceGrant(body []byte) (ServiceGrant, error) {
	var resp wire.SNAC_0x01_0x05_OServiceServiceResponse
	if err := wire.UnmarshalBE(&resp, bytes.NewReader(body)); err != nil {
		return ServiceGrant{}, fmt.Errorf("oscar: decode service response: %w", err)
	}
	host, ok := resp.String(wire.OServiceTLVTagsReconnectHere)
	if !ok || host == "" {
		return ServiceGrant{}, fmt.Errorf("oscar: service response missing host")
	}
	cookie, ok := resp.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok || len(cookie) == 0 {
		return ServiceGrant{}, fmt.Errorf("oscar: service response missing cookie")
	}
	group, _ := resp.Uint16BE(wire.OServiceTLVTagsGroupID)
	return ServiceGrant{FoodGroup: group, Host: host, Cookie: cookie}, nil
}

// DialService opens a secondary service connection (ChatNav or Chat) using a
// grant's host + cookie, running the shared OSERVICE handshake. The returned
// Session has NOT yet started its read loop or sent ClientOnline — the caller
// wires a Handler, starts Run, then calls GoOnline (in that order, so the room
// state the server pushes right after ClientOnline isn't missed).
func DialService(ctx context.Context, screenName string, grant ServiceGrant, tr ...Transport) (*Session, error) {
	var t Transport
	var port string
	if len(tr) > 0 {
		t = tr[0]
		port = t.redirectPort
	}
	addr := t.redirect(grant.Host, port)
	conn, err := t.dial(ctx, addr, 0)
	if err != nil {
		return nil, fmt.Errorf("oscar: dial service %s: %w", addr, err)
	}
	s := &Session{
		conn:       conn,
		transport:  t,
		authPort:   port,
		screenName: screenName,
		closed:     make(chan struct{}),
	}
	if err := s.handshake(grant.Cookie); err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

// GoOnline sends ClientOnline on a service connection. Exported for the chat
// connections, whose bring-up the client drives step by step (unlike BOS, where
// SignOn does it internally).
func (s *Session) GoOnline() error { return s.goOnline() }
