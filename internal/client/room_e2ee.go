package client

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// Group encryption state for chat rooms.
//
// Keys are held per room and keyed by ID, so a rotation doesn't strand the
// scrollback: old keys stay around to open older messages, while new traffic
// uses the current one.

type roomKeys struct {
	// encrypted records that this room is an ENCRYPTED room, separately from
	// whether we hold a usable key. Losing the key must not silently turn the
	// room back into a plaintext one — that would broadcast in the clear into a
	// conversation the user believes is private.
	encrypted bool
	// current is the key new messages are sealed with.
	current e2ee.RoomKey
	// hasCurrent distinguishes "no key" from a zero-valued one.
	hasCurrent bool
	// all maps key ID to key, current and retired.
	all map[string]e2ee.RoomKey
}

type roomCrypto struct {
	mu        sync.Mutex
	rooms     map[string]*roomKeys // by room cookie
	onInvite  roomInviteHandler
	onCatchup catchupHandler
}

func (rc *roomCrypto) get(cookie string) *roomKeys {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.rooms[cookie]
}

func (rc *roomCrypto) ensure(cookie string) *roomKeys {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.rooms == nil {
		rc.rooms = make(map[string]*roomKeys)
	}
	k := rc.rooms[cookie]
	if k == nil {
		k = &roomKeys{all: map[string]e2ee.RoomKey{}}
		rc.rooms[cookie] = k
	}
	return k
}

// SetRoomKey installs a group key for a room and makes it the current one.
// Previous keys are kept so earlier messages still open.
func (c *Client) SetRoomKey(cookie string, key e2ee.RoomKey) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	rk.encrypted = true
	rk.current, rk.hasCurrent = key, true
	rk.all[key.ID()] = key
	c.roomCrypto.mu.Unlock()
}

// MarkRoomEncrypted records that a room is encrypted without supplying a key.
//
// Used when restoring a room we know is encrypted but whose key is missing (or
// still arriving): sending must refuse rather than fall back to plaintext.
func (c *Client) MarkRoomEncrypted(cookie string) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	rk.encrypted = true
	c.roomCrypto.mu.Unlock()
}

// RestoreRoomKeys reinstalls a persisted key set, including retired keys so old
// messages still open.
func (c *Client) RestoreRoomKeys(cookie string, keys map[string]e2ee.RoomKey, currentID string) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	rk.encrypted = true
	for id, k := range keys {
		rk.all[id] = k
	}
	if k, ok := keys[currentID]; ok {
		rk.current, rk.hasCurrent = k, true
	}
	c.roomCrypto.mu.Unlock()
}

// RoomKeySet returns every key we hold for a room, with the current key's ID,
// for persisting.
func (c *Client) RoomKeySet(cookie string) (keys map[string]e2ee.RoomKey, currentID string) {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return nil, ""
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	out := make(map[string]e2ee.RoomKey, len(rk.all))
	for id, k := range rk.all {
		out[id] = k
	}
	if rk.hasCurrent {
		currentID = rk.current.ID()
	}
	return out, currentID
}

// RoomEncrypted reports whether a room is an encrypted room. This is true even
// when we hold no key for it — in which case we cannot read OR write it, which
// is exactly what the caller needs to know.
func (c *Client) RoomEncrypted(cookie string) bool {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return false
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	return rk.encrypted
}

// RoomReadable reports whether we hold a usable key for an encrypted room.
func (c *Client) RoomReadable(cookie string) bool {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return false
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	return rk.hasCurrent
}

// RoomKey returns a room's current group key, for handing to an invitee.
func (c *Client) RoomKey(cookie string) (e2ee.RoomKey, bool) {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return e2ee.RoomKey{}, false
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	if !rk.hasCurrent {
		return e2ee.RoomKey{}, false
	}
	return rk.current, true
}

// ForgetRoomKeys drops a room's keys, e.g. after leaving it.
func (c *Client) ForgetRoomKeys(cookie string) {
	c.roomCrypto.mu.Lock()
	delete(c.roomCrypto.rooms, cookie)
	c.roomCrypto.mu.Unlock()
}

// noteRoomCapabilities records what a room's participants advertise.
//
// Verified live: a chat room's roster carries NO capabilities, even though the
// server builds it from Session.TLVUserInfo() and that ought to union them
// across a user's connections. Capabilities are set on the BOS connection, and
// the room roster does not reflect them.
//
// So this only ever records POSITIVE findings, and never concludes from the
// room roster that somebody lacks support — doing so marked every participant
// as unable to read. The authoritative source is the BOS-side capability cache;
// see RoomNonReaders.
func (c *Client) noteRoomCapabilities(cookie string, users []oscar.ChatUser) {
	for _, u := range users {
		if len(u.Capabilities) == 0 {
			continue
		}
		capable := oscar.HasCapability(u.Capabilities, oscar.CapBENCchat) ||
			oscar.HasCapability(u.Capabilities, oscar.CapSecureIM)
		c.notePeerCapability(u.ScreenName, capable)
	}
}

// notePeerCapability caches what we know about one peer's client, from any
// source that actually carries capabilities (buddy arrivals and locate replies
// on the BOS connection).
func (c *Client) notePeerCapability(screenName string, capable bool) {
	c.e2eeMu.Lock()
	if c.peerCaps == nil {
		c.peerCaps = map[string]bool{}
	}
	c.peerCaps[state.NormalizeScreenName(screenName)] = capable
	c.e2eeMu.Unlock()
}

// peerCapability reports what we know about a peer's client: whether we know at
// all, and if so whether it supports encryption.
func (c *Client) peerCapability(screenName string) (capable, known bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	v, ok := c.peerCaps[state.NormalizeScreenName(screenName)]
	return v, ok
}

// RoomNonReaders lists participants we have positive evidence cannot read an
// encrypted room they are sitting in.
//
// Only people whose client we have actually heard from are listed. Someone we
// know nothing about yet is NOT reported — a wrong "they can't read this" tells
// the user their room is leaking when it isn't, which is worse than a delayed
// warning. Their info is requested in the background so the answer arrives
// shortly.
//
// Even a positive finding is a detection rather than a guarantee: capabilities
// are per-USER, the union across someone's signed-on devices, so a person
// running BENCchat elsewhere and plain AIM here looks capable while the client
// actually in the room cannot decrypt.
func (c *Client) RoomNonReaders(cookie string) []string {
	room, ok := c.store.Room(cookie)
	if !ok {
		return nil
	}
	self := state.NormalizeScreenName(c.store.Self().ScreenName)

	var out []string
	var unknown []string
	for _, p := range room.Participants {
		if state.NormalizeScreenName(p) == self {
			continue
		}
		capable, known := c.peerCapability(p)
		switch {
		case !known:
			unknown = append(unknown, p)
		case !capable:
			out = append(out, p)
		}
	}
	// Fill the gaps for next time. Off the calling goroutine: this runs from a
	// UI query, and a locate request can block on rate pacing.
	if len(unknown) > 0 {
		go func() {
			for _, p := range unknown {
				c.RefreshPeerKeys(p)
			}
		}()
	}
	return out
}

// sealRoomMessage encrypts outbound room text when we hold a key.
func (c *Client) sealRoomMessage(cookie, text string) (string, bool, error) {
	key, ok := c.RoomKey(cookie)
	if !ok {
		// No key. If this is a known encrypted room, REFUSE — sending plaintext
		// into a room the user believes is private is the worst possible
		// outcome, and it looks identical to success. This happens after a
		// restart that lost the key, or before an invitation has been accepted.
		if c.RoomEncrypted(cookie) {
			return "", false, errors.New(
				"client: this is an encrypted room but you don't have its key — nothing was sent. " +
					"Ask someone in the room to invite you again")
		}
		return text, false, nil
	}
	roomName := c.roomName(cookie)
	var env string
	var err error
	if signer, ok := c.signingKey(); ok {
		// Sign as this device so members can tell who actually sent it — the
		// group key alone proves only that SOMEBODY in the room did.
		env, err = e2ee.SealRoomSigned(roomName, text, key, signer)
	} else {
		env, err = e2ee.SealRoom(text, key)
	}
	if err != nil {
		// Fail closed. Falling back to plaintext here would broadcast into a room
		// the user believes is private — the one outcome worse than not sending.
		return "", false, errors.New("client: could not encrypt the room message; nothing was sent")
	}
	return env, true, nil
}

// SetSigningKey installs this device's room-message signing key.
func (c *Client) SetSigningKey(kp e2ee.SigningKeyPair, has bool) {
	c.e2eeMu.Lock()
	c.signKP, c.hasSignKP = kp, has
	c.e2eeMu.Unlock()
}

func (c *Client) signingKey() (e2ee.SigningKeyPair, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.signKP, c.hasSignKP
}

// SigningPublicKey returns this device's public signing key, for publication.
func (c *Client) SigningPublicKey() (ed25519.PublicKey, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.hasSignKP {
		return nil, false
	}
	return c.signKP.Public, true
}

// learnPeerSigningKeys caches the signing keys a peer publishes.
func (c *Client) learnPeerSigningKeys(screenName string, keys []ed25519.PublicKey) {
	c.e2eeMu.Lock()
	if c.peerSignKeys == nil {
		c.peerSignKeys = map[string][]ed25519.PublicKey{}
	}
	if len(keys) > 0 {
		c.peerSignKeys[state.NormalizeScreenName(screenName)] = keys
	}
	c.e2eeMu.Unlock()
	// A message we couldn't attribute before may be attributable now.
	c.reverifyRoomMessages(screenName)
}

// PeerSigningKeys returns the signing keys we hold for a peer.
func (c *Client) PeerSigningKeys(screenName string) []ed25519.PublicKey {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.peerSignKeys[state.NormalizeScreenName(screenName)]
}

// roomName looks up a room's name from its cookie, for the signing context.
func (c *Client) roomName(cookie string) string {
	if room, ok := c.store.Room(cookie); ok {
		return room.Name
	}
	return roomNameFromCookie(cookie)
}

// reverifyRoomMessages is a placeholder for re-checking messages received
// before we knew a sender's signing keys. They currently display as
// unverified until the room is reopened; re-running verification in place
// would need the original envelopes retained.
func (c *Client) reverifyRoomMessages(string) {}

// roomDecode is the outcome of opening an inbound room message.
type roomDecode struct {
	Text      string
	Encrypted bool
	Verified  bool
	Forged    bool
}

// decodeRoomMessage turns inbound room text into what to display.
func (c *Client) decodeRoomMessage(cookie, text string) (string, bool) {
	d := c.decodeRoomMessageFrom(cookie, "", text)
	return d.Text, d.Encrypted
}

// decodeRoomMessageFrom decrypts and, where a signature is present, checks it
// against the claimed sender's published signing keys.
func (c *Client) decodeRoomMessageFrom(cookie, sender, text string) roomDecode {
	if !e2ee.IsRoomEnvelope(text) {
		return roomDecode{Text: text}
	}
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return roomDecode{Text: "🔒 [encrypted room message — you don't have this room's key]"}
	}
	c.roomCrypto.mu.Lock()
	keys := make(map[string]e2ee.RoomKey, len(rk.all))
	for id, k := range rk.all {
		keys[id] = k
	}
	c.roomCrypto.mu.Unlock()

	msg, err := e2ee.OpenRoomSigned(c.roomName(cookie), text, keys, c.PeerSigningKeys(sender))
	if err != nil {
		switch {
		case errors.Is(err, e2ee.ErrUnknownRoomKey):
			// Sent under a key we were never given — before we were invited, or
			// after a rotation we missed.
			return roomDecode{Text: "🔒 [encrypted room message — sent with a key you don't have]"}
		case errors.Is(err, e2ee.ErrForgedSignature):
			// It decrypted, so it came from someone with the group key — but it
			// is NOT signed by the person it claims to be from. Surface the text
			// so the user can see what was put in their mouth, clearly marked.
			return roomDecode{
				Text:      "⚠ [UNVERIFIED — this message is not signed by " + sender + "] " + msg.Text,
				Encrypted: true,
				Forged:    true,
			}
		default:
			return roomDecode{Text: "🔒 [encrypted room message — couldn't decrypt]"}
		}
	}
	return roomDecode{Text: msg.Text, Encrypted: true, Verified: msg.Verified}
}

// onRoomInvite is notified when someone shares a room key with us.
type roomInviteHandler func(from string, inv e2ee.RoomInvite)

// SetRoomInviteHandler registers the callback for inbound room invites.
func (c *Client) SetRoomInviteHandler(fn roomInviteHandler) {
	c.roomCrypto.mu.Lock()
	c.roomCrypto.onInvite = fn
	c.roomCrypto.mu.Unlock()
}

func (c *Client) handleRoomInvite(from, body string) {
	inv, ok := e2ee.DecodeRoomInvite(body)
	if !ok {
		return
	}
	c.roomCrypto.mu.Lock()
	fn := c.roomCrypto.onInvite
	c.roomCrypto.mu.Unlock()
	if fn != nil {
		fn(from, inv)
	}
}

// sendRoomMessageReflected sends and asks the server to echo it back, so a
// caller can compare what arrived against what was sent. Used to verify that
// encrypted payloads survive the server's chat-text rewriting.
func (c *Client) sendRoomMessageReflected(cookie, text string) error {
	c.chatMu.Lock()
	rc := c.rooms[cookie]
	c.chatMu.Unlock()
	if rc == nil {
		return errors.New("client: not in that room")
	}
	wireText, _, err := c.sealRoomMessage(cookie, text)
	if err != nil {
		return err
	}
	return rc.session.SendChatMessageReflected(wireText)
}

// InviteToRoom shares a room's group key with someone over the 1:1 encrypted
// channel.
//
// It refuses to send unless that channel is actually encrypted: handing out a
// group key in the clear would publish the room to anyone watching the wire,
// which defeats the whole arrangement.
func (c *Client) InviteToRoom(screenName, roomName string, key e2ee.RoomKey) error {
	if !c.CanEncryptTo(screenName) {
		return errors.New("client: can't invite them privately — no encryption key for that person yet")
	}
	return c.sendProtocolMessage(screenName, e2ee.EncodeRoomInvite(e2ee.RoomInvite{
		Room: roomName,
		Key:  key,
	}))
}

// sendProtocolMessage sends machine-to-machine traffic — room invitations, the
// group key, catch-up requests and their answers — over the encrypted 1:1
// channel WITHOUT recording it as a conversation message.
//
// These ride the same transport as chat, but they are not something a person
// said. SendMessage stores what it sends so the user sees their own words, and
// that is exactly wrong here: it puts base64 protocol frames in the chat window.
func (c *Client) sendProtocolMessage(to, body string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	peerKeys, ourPriv, ok := c.sealFor(to)
	if !ok {
		return errors.New("client: no encryption key for that person yet")
	}
	env, err := e2ee.SealFor(body, peerKeys, ourPriv)
	if err != nil {
		return err
	}
	_, err = session.SendMessage(to, env, false)
	return err
}

// --- Room catch-up ----------------------------------------------------------

// catchupHandler is notified when a peer answers our request for missed room
// history, or asks us for theirs.
type catchupHandler func(from string, isRequest bool, req e2ee.CatchupRequest, res e2ee.CatchupResponse)

// SetCatchupHandler registers the callback for catch-up traffic.
func (c *Client) SetCatchupHandler(fn catchupHandler) {
	c.roomCrypto.mu.Lock()
	c.roomCrypto.onCatchup = fn
	c.roomCrypto.mu.Unlock()
}

func (c *Client) handleCatchup(from, body string) {
	isReq, req, res, ok := e2ee.DecodeCatchup(body)
	if !ok {
		return
	}
	c.roomCrypto.mu.Lock()
	fn := c.roomCrypto.onCatchup
	c.roomCrypto.mu.Unlock()
	if fn != nil {
		fn(from, isReq, req, res)
	}
}

// RequestCatchup asks a peer what we missed in a room.
//
// Refuses over an unencrypted channel: room history would otherwise cross the
// wire in the clear, which would leak more than the room itself does.
func (c *Client) RequestCatchup(peer, roomName string, since time.Time) error {
	if !c.CanEncryptTo(peer) {
		return errors.New("client: can't ask them privately — no encryption key for that person yet")
	}
	return c.sendProtocolMessage(peer, e2ee.EncodeCatchupRequest(e2ee.CatchupRequest{
		Room:  roomName,
		Since: since,
	}))
}

// SendCatchup answers a peer's request with what we have.
func (c *Client) SendCatchup(peer string, res e2ee.CatchupResponse) error {
	if !c.CanEncryptTo(peer) {
		return errors.New("client: can't answer privately — no encryption key for that person yet")
	}
	body, err := e2ee.EncodeCatchupResponse(res)
	if err != nil {
		return err
	}
	return c.sendProtocolMessage(peer, body)
}

// RoomHistorySince returns this room's messages after a point in time, for
// serving to a returning member.
func (c *Client) RoomHistorySince(cookie string, since time.Time) []e2ee.CatchupMessage {
	room, ok := c.store.Room(cookie)
	if !ok {
		return nil
	}
	self := c.store.Self().ScreenName
	var out []e2ee.CatchupMessage
	for _, m := range room.Messages {
		if !m.At.After(since) {
			continue
		}
		// Never relay a message we couldn't verify ourselves. Passing on a
		// forgery would launder it: the recipient would see it arrive from a
		// member they trust rather than from whoever injected it.
		if m.Forged {
			continue
		}
		from := m.From
		if m.Outgoing && from == "" {
			from = self
		}
		cm := e2ee.CatchupMessage{From: from, At: m.At.Unix()}
		if m.Envelope != "" {
			// Forward the sealed original so the recipient can check the
			// sender's signature for themselves.
			cm.Env = m.Envelope
		} else if m.Encrypted {
			// Encrypted but we no longer hold the envelope (an older message
			// from before envelopes were retained). Relaying the plaintext
			// would be unverifiable, so skip it rather than serve something
			// that cannot be checked.
			continue
		} else {
			cm.Text = m.Text
		}
		out = append(out, cm)
	}
	return out
}

// MergeCatchup folds a peer's answer into the room. Returns how many messages
// were genuinely new.
func (c *Client) MergeCatchup(cookie string, res e2ee.CatchupResponse) int {
	if len(res.Messages) == 0 {
		return 0
	}
	self := state.NormalizeScreenName(c.store.Self().ScreenName)
	msgs := make([]state.Message, 0, len(res.Messages))
	for _, m := range res.Messages {
		msg := state.Message{
			From: m.From,
			At:   time.Unix(m.At, 0),
			// Mark our own recovered messages as outgoing so they render on the
			// right side, as they did when we sent them.
			Outgoing: state.NormalizeScreenName(m.From) == self,
		}
		if m.Env != "" {
			// Decrypt and verify exactly as a live message would be, so history
			// relayed by a member is no more trusted than what they say now.
			d := c.decodeRoomMessageFrom(cookie, m.From, m.Env)
			if d.Forged {
				// Someone served us history signed by the wrong person. Drop it:
				// there is no honest reading of a forged message in a batch we
				// asked for.
				continue
			}
			msg.Text = d.Text
			msg.Encrypted = d.Encrypted
			msg.SenderVerified = d.Verified
			msg.Envelope = m.Env
		} else {
			msg.Text = m.Text
		}
		msgs = append(msgs, msg)
	}
	return c.store.MergeRoomMessages(cookie, msgs)
}
