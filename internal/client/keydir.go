package client

import (
	"crypto/ed25519"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/wire"
)

// Client access to the BENCO device key directory (foodgroup 0xBE00).
//
// This replaces publishing device keys inside the Locate profile. Everything
// here degrades: if the server does not advertise the foodgroup, SupportsKeyDir
// is false and callers keep using profile markers, so BENCchat still works
// against a stock open-oscar-server.

// keyDirTimeout bounds a directory round trip.
//
// A timeout must never be read as "this peer has no keys" — that would make a
// sender fall back to plaintext because the network hiccuped. Callers get a
// distinct ok=false for it.
const keyDirTimeout = 5 * time.Second

// keyDirReply is one decoded directory response.
type keyDirReply struct {
	devices  []e2ee.Device
	refused  []e2ee.Device
	revoked  bool
	restored bool
}

// SupportsKeyDir reports whether the connected server offers the key directory.
func (c *Client) SupportsKeyDir() bool {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	return sess != nil && sess.SupportsKeyDir()
}

// waitKeyDir registers a slot for a request ID and returns it plus a cleanup.
func (c *Client) waitKeyDir(reqID uint32) (chan keyDirReply, func()) {
	ch := make(chan keyDirReply, 1)
	c.e2eeMu.Lock()
	if c.keyDirWait == nil {
		c.keyDirWait = map[uint32]chan keyDirReply{}
	}
	c.keyDirWait[reqID] = ch
	c.e2eeMu.Unlock()
	return ch, func() {
		c.e2eeMu.Lock()
		delete(c.keyDirWait, reqID)
		c.e2eeMu.Unlock()
	}
}

// deliverKeyDir hands a decoded reply to whoever is waiting on that request ID.
func (c *Client) deliverKeyDir(reqID uint32, reply keyDirReply) {
	c.e2eeMu.Lock()
	ch := c.keyDirWait[reqID]
	c.e2eeMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- reply:
	default:
	}
}

// QueryDevices fetches an account's published devices from the directory.
//
// ok is false when the directory is unavailable or the reply does not arrive.
// That is deliberately distinct from an empty device list, which is a real
// answer meaning the account publishes no keys: treating a timeout as "no keys"
// would silently downgrade a conversation to plaintext.
func (c *Client) QueryDevices(screenName string) (devices []e2ee.Device, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return nil, false
	}

	reqID, err := sess.QueryDeviceKeys(screenName)
	if err != nil {
		c.log.Warn("key directory query failed to send", "screen_name", screenName, "err", err)
		return nil, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.devices, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory query timed out", "screen_name", screenName)
		return nil, false
	}
}

// PublishDevices publishes this account's complete device set.
//
// refused carries devices the server declined because they were revoked — a
// machine the user removed announcing itself again. The caller is expected to
// put those in front of the user rather than retrying.
func (c *Client) PublishDevices(devices []e2ee.Device) (refused []e2ee.Device, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return nil, false
	}

	wireDevices := make([]wire.BENCODevice, 0, len(devices))
	for _, d := range devices {
		box := d.Box
		wireDevices = append(wireDevices, wire.BENCODevice{
			BoxKey:  box[:],
			SignKey: []byte(d.Sign),
		})
	}

	reqID, err := sess.PublishDeviceKeys(wireDevices)
	if err != nil {
		c.log.Warn("key directory publish failed to send", "err", err)
		return nil, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.refused, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory publish timed out")
		return nil, false
	}
}

// RevokeDevice removes one of this account's own devices from the directory.
//
// The server tombstones the key, so the removed machine cannot republish itself
// on next sign-on. changed is false when the key was not active, which is not an
// error.
func (c *Client) RevokeDevice(box [32]byte) (changed bool, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return false, false
	}

	reqID, err := sess.RevokeDeviceKey(box[:])
	if err != nil {
		c.log.Warn("key directory revoke failed to send", "err", err)
		return false, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.revoked, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory revoke timed out")
		return false, false
	}
}

// RefreshPeerKeys learns a peer's device keys, preferring the directory.
//
// It falls back to a Locate profile fetch in two cases: the server does not
// offer the directory, or it does and the peer has published nothing there. The
// second case matters during the transition — a peer running an older BENCchat
// still advertises only a profile marker, and treating an empty directory answer
// as "this peer has no keys" would strand the conversation in plaintext.
//
// Blocking, because the directory round trip has to complete before we know
// whether to fall back. Callers run it in a goroutine.
func (c *Client) RefreshPeerKeys(screenName string) {
	if c.SupportsKeyDir() {
		if devices, ok := c.QueryDevices(screenName); ok && len(devices) > 0 {
			// handleKeyDir already cached these; nothing further to do.
			return
		}
	}
	c.RequestUserInfo(screenName)
}

// RestoreDevice lifts a revocation so a removed device can publish again.
//
// This is the exit from what would otherwise be a dead end: a tombstoned device
// republishes on every sign-on, is refused, and the user is told to approve it
// from another machine — which does nothing unless that approval can reach here.
func (c *Client) RestoreDevice(box [32]byte) (changed bool, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return false, false
	}

	reqID, err := sess.RestoreDeviceKey(box[:])
	if err != nil {
		c.log.Warn("key directory restore failed to send", "err", err)
		return false, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.restored, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory restore timed out")
		return false, false
	}
}

// handleKeyDir dispatches an inbound key directory SNAC.
func (c *Client) handleKeyDir(frame wire.SNACFrame, body []byte) {
	switch frame.SubGroup {
	case wire.BENCOKeyDirQueryReply:
		reply, err := oscar.DecodeKeyDirQueryReply(body)
		if err != nil {
			c.log.Warn("bad key directory query reply", "err", err)
			return
		}
		devices := devicesFromWire(reply.Devices)

		// Learn the peer's keys here as well as handing them to the waiter, so a
		// query issued for any reason keeps the send-side cache warm — the same
		// thing the profile path does on a locate reply.
		if !c.isSelf(reply.ScreenName) && len(devices) > 0 {
			c.learnPeerKeys(reply.ScreenName, e2ee.BoxKeysOf(devices))
			c.learnPeerSigningKeys(reply.ScreenName, e2ee.SigningKeysOf(devices))
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{devices: devices})

	case wire.BENCOKeyDirPublishReply:
		reply, err := oscar.DecodeKeyDirPublishReply(body)
		if err != nil {
			c.log.Warn("bad key directory publish reply", "err", err)
			return
		}
		refused := devicesFromWire(reply.Refused)
		if len(refused) > 0 {
			c.log.Info("server refused revoked device keys", "count", len(refused))
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{refused: refused})

	case wire.BENCOKeyDirRevokeReply:
		reply, err := oscar.DecodeKeyDirRevokeReply(body)
		if err != nil {
			c.log.Warn("bad key directory revoke reply", "err", err)
			return
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{revoked: reply.Revoked != 0})

	case wire.BENCOKeyDirRestoreReply:
		reply, err := oscar.DecodeKeyDirRestoreReply(body)
		if err != nil {
			c.log.Warn("bad key directory restore reply", "err", err)
			return
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{restored: reply.Restored != 0})

	case wire.BENCOKeyDirErr:
		// Deliver an empty reply so a waiter fails fast rather than sitting out
		// the full timeout for an error the server already reported.
		c.log.Warn("key directory returned an error", "request_id", frame.RequestID)
		c.deliverKeyDir(frame.RequestID, keyDirReply{})
	}
}

// devicesFromWire converts wire devices, skipping any with a wrong-length key.
//
// The server validates lengths, so a bad one here means a version mismatch or a
// corrupt frame. Dropping it beats copying into a [32]byte and panicking, or
// worse, silently truncating a key and producing undecryptable messages.
func devicesFromWire(in []wire.BENCODevice) []e2ee.Device {
	out := make([]e2ee.Device, 0, len(in))
	for _, d := range in {
		if len(d.BoxKey) != 32 {
			continue
		}
		var box [32]byte
		copy(box[:], d.BoxKey)

		var sign ed25519.PublicKey
		if len(d.SignKey) == ed25519.PublicKeySize {
			sign = ed25519.PublicKey(append([]byte(nil), d.SignKey...))
		}
		out = append(out, e2ee.Device{Box: box, Sign: sign})
	}
	return out
}
