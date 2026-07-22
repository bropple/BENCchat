package client

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
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

	// out is our own outbound chain for this room, once one has been started.
	// Every sender has their own; ours is the only one we can advance.
	out *e2ee.Chain
	// chainShared records that our current chain has actually been handed to the
	// room. A chain nobody has been given seals messages nobody can read, and
	// relying on the send path to remember to distribute first is exactly the
	// kind of ordering that survives until somebody reorders two lines. Sealing
	// refuses while this is false, so the mistake cannot compile away.
	chainShared bool
	// reservedThrough is the first position our chain has NOT been promised to
	// disk for. Sealing at or past it must reserve more first.
	reservedThrough uint32
	// staleChain marks that our chain must be replaced before we send again.
	//
	// Set when somebody is removed. Rotation is LAZY on purpose: a chain nobody
	// advances gives the removed member nothing, so replacing it before the next
	// send is the earliest point at which it matters, and rooms where nobody
	// speaks cost nothing. Doing it eagerly for every member would be one
	// distribution per member per removal.
	staleChain bool
	// views are the sender chains we can read, by chain ID. A message naming one
	// we do not hold is readable by nobody here — which is the normal state for
	// anything sent before we joined.
	views map[string]e2ee.ChainView
	// seen is the highest position observed on each chain, which is where a
	// newcomer's bundle should start — the views above say how far BACK we may
	// read, which is a different question and the wrong answer to hand over.
	seen map[string]uint32
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

// isEncrypted reports whether a room is an encrypted one, regardless of whether
// we currently hold a usable key for it.
func (rc *roomCrypto) isEncrypted(cookie string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	k := rc.rooms[cookie]
	return k != nil && k.encrypted
}

func (rc *roomCrypto) ensure(cookie string) *roomKeys {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.rooms == nil {
		rc.rooms = make(map[string]*roomKeys)
	}
	k := rc.rooms[cookie]
	if k == nil {
		k = &roomKeys{
			all:   map[string]e2ee.RoomKey{},
			views: map[string]e2ee.ChainView{},
		}
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
	roomName := c.roomName(cookie)

	// Our own chain first, and BEFORE the shared-key check below: holding a
	// chain is a complete answer to "can we seal for this room", and a room that
	// has moved to chains has no shared key to find. Checking for one first
	// would refuse to send into exactly the rooms that work best.
	//
	// The signer is taken before roomCrypto.mu so the two locks are never
	// nested, and the lock is held ACROSS the seal because Next() advances the
	// chain: two concurrent sends outside it would take the same position and
	// seal two different messages at one index.
	if signer, ok := c.signingKey(); ok {
		if rk := c.roomCrypto.get(cookie); rk != nil {
			// Before anything is sealed, not after: the promise has to be on
			// disk before the ciphertext exists, or a crash between the two
			// leaves a position used with nothing recording that it was.
			if err := c.reserveChainPositions(cookie); err != nil {
				return "", false, errors.New(
					"client: couldn't record this room's chain position, so nothing was sent")
			}

			c.roomCrypto.mu.Lock()
			usable := rk.out != nil && !rk.staleChain && rk.chainShared
			var chainEnv string
			var chainErr error
			if usable && rk.out.Index >= rk.reservedThrough {
				// Should be impossible after reserveChainPositions. If it ever
				// is not, refuse rather than seal at a position no record
				// promises — that is the bug this whole scheme exists to make
				// unreachable, and it must fail loudly rather than silently.
				c.roomCrypto.mu.Unlock()
				c.log.Error("refusing to seal past the reserved chain position",
					"room", roomName, "index", rk.out.Index, "reserved", rk.reservedThrough)
				return "", false, errors.New("client: chain position is not reserved; nothing was sent")
			}
			if usable {
				chainEnv, chainErr = e2ee.SealRoomChain(roomName, text, rk.out, signer)
				if chainErr == nil {
					// Our own chain gets a position like anybody else's. Without
					// this, `seen` was never written for chains we own, so a
					// RETIRED one had no position to wind to and went into invite
					// bundles at index zero. Under the lock that already guards
					// the advance, so it cannot disagree with the chain.
					if rk.seen == nil {
						rk.seen = map[string]uint32{}
					}
					if used := rk.out.Index - 1; used >= rk.seen[rk.out.ID] {
						rk.seen[rk.out.ID] = used
					}
				}
			}
			c.roomCrypto.mu.Unlock()
			if usable {
				if chainErr != nil {
					return "", false, errors.New("client: could not encrypt the room message; nothing was sent")
				}
				return chainEnv, true, nil
			}
		}
	}

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

// SigningKeyPair returns this device's signing keypair, for the paths that must
// sign something other than a room message.
func (c *Client) SigningKeyPair() (e2ee.SigningKeyPair, bool) { return c.signingKey() }

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

// reverifyRoomMessages re-checks room messages that arrived before we held the
// sender's signing keys.
//
// Without this, "we have not fetched their keys yet" was indistinguishable from
// "this will never be attributable" — the badge went up on arrival and stayed
// there for the life of the session even after the keys landed a second later.
// The envelopes are retained for exactly this (state.Message.Envelope), so the
// original bytes are re-checked rather than anything being taken on trust.
func (c *Client) reverifyRoomMessages(screenName string) {
	c.store.ReverifyRoomMessages(screenName, func(cookie, envelope string) (verified, forged, ok bool) {
		return c.verifyRoomEnvelope(cookie, screenName, envelope)
	})
}

// verifyRoomEnvelope re-opens a stored envelope purely to re-check its
// signature.
//
// Deliberately NOT decodeRoomMessageFrom: that path drops anything whose message
// ID it has already seen, and every message here is by definition one we have
// already seen. Re-verification would drop the lot.
func (c *Client) verifyRoomEnvelope(cookie, sender, envelope string) (verified, forged, ok bool) {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return false, false, false
	}
	c.roomCrypto.mu.Lock()
	keys := make(map[string]e2ee.RoomKey, len(rk.all))
	for id, k := range rk.all {
		keys[id] = k
	}
	c.roomCrypto.mu.Unlock()

	var msg e2ee.SignedMessage
	var err error
	if e2ee.IsRoomChainEnvelope(envelope) {
		// The chain path is the production path now. Routing everything through
		// OpenRoomSigned meant a v3 envelope returned "not a room envelope", so
		// re-verification silently never resolved — recreating, on the new path,
		// exactly the bug it was written to fix.
		c.roomCrypto.mu.Lock()
		views := make(map[string]e2ee.ChainView, len(rk.views))
		for id, v := range rk.views {
			views[id] = v
		}
		c.roomCrypto.mu.Unlock()
		msg, err = e2ee.OpenRoomChain(c.roomName(cookie), envelope, views, c.PeerSigningKeys(sender))
	} else {
		msg, err = e2ee.OpenRoomSigned(c.roomName(cookie), envelope, keys, c.PeerSigningKeys(sender))
	}
	switch {
	case errors.Is(err, e2ee.ErrForgedSignature):
		return false, true, true
	case err != nil:
		return false, false, false
	}
	return msg.Verified, false, true
}

// roomDecode is the outcome of opening an inbound room message.
type roomDecode struct {
	Text      string
	Encrypted bool
	Verified  bool
	// Signed reports that a signature was present, whether or not we could check
	// it. Distinct from Verified: "not checked yet" and "nothing to check" are
	// different answers and only one of them improves on its own.
	Signed bool
	Forged bool
	// SentAt is when the sender says they sent it, covered by their signature.
	// Zero for anything that carried no stamp, in which case the caller has
	// nothing better than its own clock.
	SentAt time.Time
	// Duplicate marks a message we have already seen — the same signed message
	// arriving twice is the server handing us a copy it kept, not somebody
	// saying the same thing again.
	Duplicate bool
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
		// Plaintext in a room we know is encrypted did not come from a member's
		// BENCchat: sealRoomMessage seals or refuses, it never falls back. So it
		// was injected further down the wire — by the server, which chooses the
		// sender name attached to every chat message and already rewrites chat
		// traffic to implement //roll, or by a walk-in OSCAR client. Mark it.
		// The only other signal is an ABSENT lock, and an absence is not
		// something a reader notices.
		if c.roomCrypto.isEncrypted(cookie) {
			who := sender
			if who == "" {
				who = "the sender"
			}
			return roomDecode{
				Text:   "⚠ [UNENCRYPTED — sent in the clear into an encrypted room, so it did not come from " + who + "'s BENCchat] " + text,
				Forged: true,
			}
		}
		return roomDecode{Text: text}
	}
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return roomDecode{Text: "🔒 [encrypted room message — you don't have this room's key]"}
	}
	if e2ee.IsRoomChainEnvelope(text) {
		return c.decodeRoomChainMessage(cookie, sender, text, rk)
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
	if c.seenBefore(cookie+":"+sender, msg.ID) {
		c.log.Warn("dropping a duplicate room message", "room", c.roomName(cookie), "from", sender)
		return roomDecode{Duplicate: true}
	}
	if msg.Signed && !msg.Verified {
		// A signature we cannot check because we hold none of this sender's
		// signing keys. Go and get them: leaving it is how a server that simply
		// declines key-directory queries keeps every message from somebody
		// permanently unattributable, which looks like an ordinary timing gap.
		// learnPeerSigningKeys re-runs verification on what already arrived.
		go c.RefreshPeerKeys(sender)
	}
	return roomDecode{
		Text: msg.Text, Encrypted: true,
		Verified: msg.Verified, Signed: msg.Signed, SentAt: msg.SentAt,
	}
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
func (c *Client) InviteToRoom(screenName, roomName string, chains []e2ee.ChainView, roster string) error {
	if !c.CanEncryptTo(screenName) {
		return errors.New("client: can't invite them privately — no encryption key for that person yet")
	}
	return c.sendProtocolMessage(screenName, e2ee.EncodeRoomInvite(e2ee.RoomInvite{
		Room:   roomName,
		Chains: chains,
		Roster: roster,
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
	_, _, err = session.SendMessage(to, env, false)
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

// --- Per-sender chains ------------------------------------------------------

// EnsureOutboundChain returns the chain view to hand this room's members, and
// whether it is a fresh chain they have not been given yet.
//
// fresh=true means the caller MUST distribute the view before the next message
// is sent, or nobody will be able to read it. That ordering is the caller's
// because distribution is the app layer's job — it knows the member list, and
// this layer deliberately does not.
func (c *Client) EnsureOutboundChain(cookie string) (view e2ee.ChainView, fresh bool, err error) {
	rk := c.roomCrypto.ensure(cookie)

	c.roomCrypto.mu.Lock()
	needNew := rk.out == nil || rk.staleChain
	c.roomCrypto.mu.Unlock()

	if !needNew {
		c.roomCrypto.mu.Lock()
		defer c.roomCrypto.mu.Unlock()
		return rk.out.View(), false, nil
	}

	// Minted outside the lock: NewChain reads the system random source, and
	// holding a mutex across that is how an unrelated stall becomes a deadlock.
	chain, err := e2ee.NewChain()
	if err != nil {
		return e2ee.ChainView{}, false, err
	}

	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	// Re-check: another send may have started one while we were minting.
	if rk.out != nil && !rk.staleChain {
		return rk.out.View(), false, nil
	}
	rk.out = &chain
	rk.staleChain = false
	rk.chainShared = false // nobody has it yet; sealing stays refused until they do
	rk.reservedThrough = 0 // a new chain has promised nothing yet
	// We can read our own chain, so scrollback of our own messages works the
	// same way everyone else's does rather than through a special case.
	rk.views[chain.ID] = chain.View()
	return chain.View(), true, nil
}

// MarkChainShared records that our chain has reached the room, which is what
// permits sealing under it.
func (c *Client) MarkChainShared(cookie string) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	rk.chainShared = true
	c.roomCrypto.mu.Unlock()
}

// MarkChainStale records that our outbound chain must be replaced before we send
// again, because somebody who held it is no longer welcome to.
func (c *Client) MarkChainStale(cookie string) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	rk.staleChain = true
	c.roomCrypto.mu.Unlock()
}

// LearnChainView installs a sender's chain so their messages can be read.
//
// A view for a chain we already hold is replaced only when the offer reaches
// further back AND is provably the same chain — see e2ee.ChainView.Continues.
//
// "Lower index wins" alone was a hole, and a bad one. Chain IDs ride in the
// clear on every message and nothing binds one to an account, so any participant
// could broadcast their own random state under somebody else's chain ID at index
// zero and permanently replace our view of that person: their real messages then
// failed to decrypt forever, and it persisted. Continuity is what tells the two
// apart, and it needs no trust in the sender — only the chain's real owner can
// produce a state that hashes forward to the one we already hold.
func (c *Client) LearnChainView(cookie string, view e2ee.ChainView) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	rk.encrypted = true

	have, held := rk.views[view.ID]
	switch {
	case !held:
		// Nothing to be continuous with. First sighting is trust-on-first-use,
		// which is the same position every other key in this client starts from.
	case have.Index <= view.Index:
		return // no more read-back than we already have
	case !view.Continues(have):
		c.log.Warn("refusing a chain view that is not continuous with the one we hold",
			"room", c.roomName(cookie), "chain", view.ID,
			"offered_index", view.Index, "held_index", have.Index)
		return
	}
	rk.views[view.ID] = view
}

// ChainViews returns every sender chain we hold for a room.
func (c *Client) ChainViews(cookie string) map[string]e2ee.ChainView {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return nil
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	out := make(map[string]e2ee.ChainView, len(rk.views))
	for id, v := range rk.views {
		out[id] = v
	}
	return out
}

// OutboundChainID reports which chain we are currently sealing with, for tests
// and diagnostics. Empty when we have not started one.
func (c *Client) OutboundChainID(cookie string) string {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return ""
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	if rk.out == nil {
		return ""
	}
	return rk.out.ID
}

// decodeRoomChainMessage opens a message sealed under a sender's chain.
//
// Split from the shared-key path rather than folded into it because the failure
// modes are genuinely different and the user-facing wording has to say which:
// "sent before you joined" is the ratchet working exactly as intended, while
// "we were never given this chain" is somebody's key distribution having gone
// astray and is worth retrying.
func (c *Client) decodeRoomChainMessage(cookie, sender, text string, rk *roomKeys) roomDecode {
	c.roomCrypto.mu.Lock()
	views := make(map[string]e2ee.ChainView, len(rk.views))
	for id, v := range rk.views {
		views[id] = v
	}
	c.roomCrypto.mu.Unlock()

	msg, err := e2ee.OpenRoomChain(c.roomName(cookie), text, views, c.PeerSigningKeys(sender))
	switch {
	case errors.Is(err, e2ee.ErrChainRewind):
		// Sent before we were given this chain. Not an error and not worth
		// chasing: no amount of asking produces a key that was never derivable.
		return roomDecode{Text: "🔒 [sent before you joined this room]"}

	case errors.Is(err, e2ee.ErrUnknownChain):
		// A chain nobody has handed us. Usually a sender who started a new one
		// while we were away, which a request can fix.
		go c.RefreshPeerKeys(sender)
		return roomDecode{Text: "🔒 [encrypted room message — waiting for the sender's key…]"}

	case errors.Is(err, e2ee.ErrForgedSignature):
		return roomDecode{
			Text:      "⚠ [UNVERIFIED — this message is not signed by " + sender + "] " + msg.Text,
			Encrypted: true,
			Signed:    true,
			Forged:    true,
		}

	case err != nil:
		return roomDecode{Text: "🔒 [encrypted room message — couldn't decrypt]"}
	}

	if c.seenBefore(cookie+":"+sender, msg.ID) {
		c.log.Warn("dropping a duplicate room message", "room", c.roomName(cookie), "from", sender)
		return roomDecode{Duplicate: true}
	}
	// Only NOW, after the message authenticated under this chain. Recording it
	// on arrival — before decryption, for any chain ID, from any sender — meant
	// an unauthenticated wire value drove where an invite bundle starts and how
	// far retention winds a view. One undecryptable message from a walk-in was
	// enough to set a position of 0xFFFFFFFF, which wrapped the bundle's +1 back
	// to zero and handed the next newcomer the room's whole history; a smaller
	// value permanently blinded a member instead. A position that cannot be
	// reached without the chain key cannot do either.
	if chainID, index, ok := e2ee.RoomEnvelopeChain(text); ok {
		c.noteChainPosition(cookie, chainID, index)
	}

	if msg.Signed && !msg.Verified {
		go c.RefreshPeerKeys(sender)
	}
	return roomDecode{
		Text: msg.Text, Encrypted: true,
		Verified: msg.Verified, Signed: msg.Signed, SentAt: msg.SentAt,
	}
}

// RoomChainState exports a room's chain state for persistence.
//
// The outbound chain is exported ADVANCED TO ITS RESERVATION, not to the
// position actually reached. A restore then resumes at a position that has never
// sealed anything, which is what makes a crash — or a clean quit, which used to
// lose just as much — unable to reuse an index. Up to a block of positions is
// burned; recipients simply ratchet past them.
func (c *Client) RoomChainState(cookie string) (out string, views map[string]string, seen map[string]uint32, reserved uint32, shared bool) {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return "", nil, nil, 0, false
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()

	if rk.out != nil {
		reserved = rk.reservedThrough
		if reserved < rk.out.Index {
			reserved = rk.out.Index
		}
		stored := *rk.out
		if wound, ok := stored.AdvanceChain(reserved); ok {
			stored = wound
		}
		out = e2ee.EncodeChain(stored)
		shared = rk.chainShared
	}
	views = make(map[string]string, len(rk.views))
	for id, v := range rk.views {
		views[id] = e2ee.EncodeChainView(v)
	}
	seen = make(map[string]uint32, len(rk.seen))
	for id, n := range rk.seen {
		seen[id] = n
	}
	return out, views, seen, reserved, shared
}

// RestoreChainState reinstalls persisted chain state after sign-on.
//
// A room whose state is present but undecodable is still marked encrypted. That
// is the important half: losing the state must mean "refuse to send" rather than
// "this is an ordinary room", or the client broadcasts in the clear into a
// conversation everybody believes is private.
func (c *Client) RestoreChainState(cookie, out string, views map[string]string, seen map[string]uint32, reserved uint32, shared bool) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()
	rk.encrypted = true

	if out != "" {
		if chain, err := e2ee.DecodeChain(out); err == nil {
			rk.out = &chain
			// Whether it reached the room is a stored FACT now, not an inference
			// from the file existing. The old assumption — persisted implies
			// sent implies shared — was false at both steps, and a reformed room
			// persisted an unshared chain and then refused to send forever.
			rk.chainShared = shared
			rk.reservedThrough = reserved
			if rk.reservedThrough < chain.Index {
				rk.reservedThrough = chain.Index
			}
			// Our own view goes in at the restored position first; the loop below
			// then reinstalls the persisted view, which reaches further back and
			// is what keeps our own scrollback readable. That ordering is
			// load-bearing, and the continuity check makes it safe rather than
			// merely lucky.
			rk.views[chain.ID] = chain.View()
		} else {
			// A chain we cannot decode must not be replaced silently here: a
			// fresh one would seal messages nobody has been given the view for.
			// Leaving it nil makes the next send mint and distribute one properly.
			c.log.Warn("could not restore a room's outbound chain", "room", cookie, "err", err)
		}
	}
	for id, enc := range views {
		v, err := e2ee.DecodeChainView(enc)
		if err != nil || v.ID != id {
			c.log.Warn("could not restore a room chain view", "room", cookie, "chain", id, "err", err)
			continue
		}
		if have, ok := rk.views[id]; ok && have.Index <= v.Index {
			continue
		}
		rk.views[id] = v
	}
	for id, n := range seen {
		if rk.seen == nil {
			rk.seen = map[string]uint32{}
		}
		if n > rk.seen[id] {
			rk.seen[id] = n
		}
	}
}

// noteChainPosition records how far a chain has got, for handing a newcomer a
// bundle that starts at "now" rather than at the earliest we may read.
func (c *Client) noteChainPosition(cookie, chainID string, index uint32) {
	rk := c.roomCrypto.ensure(cookie)
	c.roomCrypto.mu.Lock()
	if rk.seen == nil {
		rk.seen = map[string]uint32{}
	}
	if index >= rk.seen[chainID] {
		rk.seen[chainID] = index
	}
	c.roomCrypto.mu.Unlock()
}

// ChainBundleFor builds what a newcomer needs: every chain we can read, each
// wound forward to where the conversation has actually got to.
//
// The winding is the whole point and it is why `seen` is tracked separately from
// the views. A view says how far BACK we may read; handing that over would give
// a newcomer our own read-back, which is precisely the history chains exist to
// withhold. What they should get is "from the next message onward".
func (c *Client) ChainBundleFor(cookie string) []e2ee.ChainView {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return nil
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()

	out := make([]e2ee.ChainView, 0, len(rk.views))
	for id, v := range rk.views {
		// Every chain goes through the SAME winding, including our own. The
		// special case that used to sit here — "our own chain is already at now"
		// — was true only of the CURRENT one. A chain we retired stayed in the
		// map, stopped matching rk.out.ID, and fell through to a `seen` entry
		// that was never written for our own chains, so it was bundled at index
		// zero and handed every newcomer our whole pre-rotation history. Deleting
		// the special case is the fix; sealRoomMessage now records our position
		// like anybody else's.
		n, known := rk.seen[id]
		if !known {
			// We do not know where this chain has got to, so we cannot wind it
			// to "now". Dropping it costs the newcomer readability until its
			// owner next broadcasts; shipping it unwound would cost them nothing
			// and cost us the entire history.
			continue
		}
		// uint64 so a poisoned position cannot wrap the +1 back to zero and
		// present an unwound view as a wound one.
		target := uint64(n) + 1
		if target > uint64(^uint32(0)) {
			continue
		}
		if uint32(target) <= v.Index {
			out = append(out, v) // already at or past where we would wind it
			continue
		}
		wound, ok := v.Advance(uint32(target))
		if !ok {
			// Refused to move — too far to hash. Fail closed.
			c.log.Warn("dropping a chain from an invite bundle: cannot wind it forward",
				"room", c.roomName(cookie), "chain", id, "from", v.Index, "to", target)
			continue
		}
		out = append(out, wound)
	}
	return out
}

// SetRoomMembersFunc tells the client how to look up who is in a room.
//
// Membership lives in the app layer, but chain distribution has to happen on the
// send path down here — a message sealed under a chain nobody has been given is
// unreadable, and the only moment that is certainly before the message is just
// before it. A callback keeps the membership model where it belongs.
func (c *Client) SetRoomMembersFunc(fn func(cookie string) []string) {
	c.e2eeMu.Lock()
	c.roomMembersFn = fn
	c.e2eeMu.Unlock()
}

// roomMembersFunc returns the membership lookup, if the app layer installed one.
func (c *Client) roomMembersFunc() func(string) []string {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.roomMembersFn
}

func (c *Client) roomMembers(cookie string) []string {
	c.e2eeMu.Lock()
	fn := c.roomMembersFn
	c.e2eeMu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(cookie)
}

// ensureRoomChainDistributed starts an outbound chain if needed and broadcasts
// it into the room before anything is sealed under it.
//
// Ordering is the requirement: the broadcast must land BEFORE the first message
// on the new chain, or every recipient sees a message naming a chain they were
// never given. Broadcasting into the room rather than fanning out 1:1 costs one
// message instead of one per member, and the person a rotation excluded receives
// it like everybody else and can open nothing.
func (c *Client) ensureRoomChainDistributed(cookie string) error {
	// Only for rooms somebody DECIDED were encrypted. Running unconditionally
	// meant typing into an ordinary public room minted a chain, broadcast a
	// key-distribution blob into it, and sealed everything after — so a room
	// became encrypted by being used, non-BENCchat occupants saw base64 noise,
	// and CreateEncryptedRoom stopped meaning anything.
	if !c.RoomEncrypted(cookie) {
		return nil
	}
	view, fresh, err := c.EnsureOutboundChain(cookie)
	if err != nil {
		return err
	}
	if !fresh {
		return nil
	}

	members := c.roomMembers(cookie)
	self := state.NormalizeScreenName(c.store.Self().ScreenName)
	var recipients [][32]byte
	for _, m := range members {
		if state.NormalizeScreenName(m) == self {
			continue
		}
		keys, ok := c.PeerKeys(m)
		if !ok {
			// Somebody whose device keys we have never fetched cannot be sealed
			// to. Say so rather than dropping them silently into a room they can
			// no longer read.
			c.log.Warn("no device keys for a room member; they will not receive the new chain",
				"room", c.roomName(cookie), "member", m)
			continue
		}
		recipients = append(recipients, keys...)
	}
	if len(recipients) == 0 {
		// A room with nobody else in it. Nothing to distribute, so the chain is
		// as shared as it can be and sealing may proceed.
		c.MarkChainShared(cookie)
		return nil
	}

	ourPriv, ok := c.ourPrivateKey()
	if !ok {
		return errors.New("client: no encryption key, so the room chain can't be shared")
	}

	c.chatMu.Lock()
	rc := c.rooms[cookie]
	c.chatMu.Unlock()
	if rc == nil {
		return errors.New("client: not in that room")
	}

	// Chunk rather than truncate: a room too big for one message is a room that
	// needs several, and dropping the overflow would leave those members unable
	// to read with nothing to show for it.
	per := e2ee.MaxChainSlotsPerBroadcast()
	for start := 0; start < len(recipients); start += per {
		end := start + per
		if end > len(recipients) {
			end = len(recipients)
		}
		body, berr := e2ee.EncodeChainBroadcast(view, recipients[start:end], ourPriv)
		if berr != nil {
			return berr
		}
		if serr := rc.session.SendChatMessage(body); serr != nil {
			return serr
		}
	}
	c.MarkChainShared(cookie)
	return nil
}

// ourPrivateKey returns this device's encryption private key.
func (c *Client) ourPrivateKey() ([32]byte, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeHasKP {
		return [32]byte{}, false
	}
	return c.e2eeKP.Private, true
}

// handleChainBroadcast learns a sender's chain from an in-room distribution.
func (c *Client) handleChainBroadcast(cookie, sender, body string) {
	// A chain from somebody we never gave this room to is not a chain we want to
	// be able to read. Installing one lets a walk-in who knows the room name
	// speak into an encrypted room under their own name, rendering as ordinary
	// chat rather than as the injection the plaintext check catches.
	if fn := c.roomMembersFunc(); fn != nil {
		self := state.NormalizeScreenName(c.store.Self().ScreenName)
		want := state.NormalizeScreenName(sender)
		member := want == self
		for _, m := range fn(cookie) {
			if state.NormalizeScreenName(m) == want {
				member = true
				break
			}
		}
		if !member {
			c.log.Warn("ignoring a room chain broadcast from a non-member",
				"room", c.roomName(cookie), "from", sender)
			return
		}
	}

	senderPubs, ok := c.PeerKeys(sender)
	if !ok {
		// We cannot open it without knowing which key sealed it. Fetch and let
		// the sender's next broadcast land, rather than guessing.
		go c.RefreshPeerKeys(sender)
		return
	}
	ourKeys, ok := c.ourKeyPairs()
	if !ok {
		return
	}
	view, err := e2ee.DecodeChainBroadcast(body, ourKeys, senderPubs)
	switch {
	case errors.Is(err, e2ee.ErrNoSlotForUs):
		// Nothing here for us. The ordinary result of a rotation that left this
		// account out, and not worth a warning: the room will simply stop being
		// readable, which the message placeholders already say.
		return
	case err != nil:
		c.log.Warn("could not open a room chain broadcast", "room", c.roomName(cookie), "from", sender, "err", err)
		return
	}
	c.LearnChainView(cookie, view)
	c.reverifyRoomMessages(sender)
}

// ourKeyPairs is this device's encryption keypair, as the slot opener wants it.
func (c *Client) ourKeyPairs() ([]e2ee.KeyPair, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeHasKP {
		return nil, false
	}
	return []e2ee.KeyPair{c.e2eeKP}, true
}

// chainReservationBlock is how many chain positions are promised to disk at
// once.
//
// A block rather than a write per message, but NOT for the reason it looks like:
// a file write per message would be about a millisecond at human typing speed
// and perfectly affordable. The reason is that a per-send write puts the
// invariant in call-site discipline, and call-site discipline is exactly what
// already failed here — the previous design assumed a save that no code path
// performed, and shutdown flushed history while never touching room keys.
//
// Burning up to a block of positions on an unclean exit costs nothing:
// recipients ratchet forward and the skip cap is three orders of magnitude
// larger.
const chainReservationBlock = 64

// reserveChainPositions makes the durable promise that must exist before any
// ciphertext sealed at the current position leaves this process:
//
//	a record on disk whose reservation is strictly greater than the index used.
//
// Called from the seal itself rather than from a caller, so that no future
// reordering of the send path can leave it out.
func (c *Client) reserveChainPositions(cookie string) error {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return nil
	}
	c.roomCrypto.mu.Lock()
	need := rk.out != nil && rk.out.Index >= rk.reservedThrough
	var want uint32
	if need {
		want = rk.out.Index + chainReservationBlock
	}
	c.roomCrypto.mu.Unlock()
	if !need {
		return nil
	}

	// The persist callback reaches back into the app layer, which reads this
	// client — so it must not run under roomCrypto.mu.
	c.e2eeMu.Lock()
	persist := c.persistChainFn
	c.e2eeMu.Unlock()
	if persist == nil {
		// Nothing to persist through (tests, or a client with no app layer).
		// Record the reservation so behaviour is otherwise identical.
		c.roomCrypto.mu.Lock()
		if want > rk.reservedThrough {
			rk.reservedThrough = want
		}
		c.roomCrypto.mu.Unlock()
		return nil
	}

	c.roomCrypto.mu.Lock()
	if want > rk.reservedThrough {
		rk.reservedThrough = want
	}
	c.roomCrypto.mu.Unlock()

	if err := persist(cookie); err != nil {
		// Roll the promise back: we did not make it, so we must not act as
		// though we had.
		c.roomCrypto.mu.Lock()
		if rk.reservedThrough == want {
			rk.reservedThrough = rk.out.Index
		}
		c.roomCrypto.mu.Unlock()
		return err
	}
	return nil
}

// persistChain invokes the durable-write hook, if one is installed.
func (c *Client) persistChain(cookie string) error {
	c.e2eeMu.Lock()
	fn := c.persistChainFn
	c.e2eeMu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(cookie)
}

// SetPersistChainFunc installs the durable-write hook the reservation needs.
func (c *Client) SetPersistChainFunc(fn func(cookie string) error) {
	c.e2eeMu.Lock()
	c.persistChainFn = fn
	c.e2eeMu.Unlock()
}

// chainRetention is how many positions back a chain view is kept readable.
//
// This is the room half of forward secrecy, and it is the whole of it: a chain
// advances by a one-way hash, so a view wound forward genuinely cannot open what
// it passed. Without this the mechanism exists and nothing uses it — a view sits
// at the earliest position it was ever given and opens the room's entire life,
// which is exactly what makes a stolen room file worth so much.
//
// Nothing is lost by winding it on. Scrollback comes from the history file,
// which stores decrypted text under a different key; chain views are needed only
// to open CIPHERTEXT, and the only ciphertext that arrives late is a catch-up
// envelope forwarded by another member. That is bounded by the catch-up window,
// which is bounded by when we joined.
//
// Generous on purpose, because winding forward is irreversible: too small and a
// legitimate catch-up renders as "sent before you joined" forever. Two thousand
// positions is far past any window anybody asks for, and still turns "the room's
// entire history" into "the recent past".
const chainRetention = 2000

// PruneChainViews winds each view forward so it can no longer open messages more
// than chainRetention positions old, and reports how many moved.
//
// Only peer chains move. Our own view is regenerated from the outbound chain at
// its current position on every restore, so it is already as far forward as it
// goes.
func (c *Client) PruneChainViews(cookie string) int {
	rk := c.roomCrypto.get(cookie)
	if rk == nil {
		return 0
	}
	c.roomCrypto.mu.Lock()
	defer c.roomCrypto.mu.Unlock()

	moved := 0
	for id, v := range rk.views {
		if rk.out != nil && id == rk.out.ID {
			continue
		}
		seen, ok := rk.seen[id]
		if !ok || seen < chainRetention {
			// We do not know where this chain has got to, or it has not run far
			// enough for anything to be old yet. Winding forward on a guess
			// would destroy readability we are entitled to.
			continue
		}
		floor := seen - chainRetention
		if v.Index >= floor {
			continue
		}
		wound, ok := v.Advance(floor)
		if !ok {
			continue // refused to move; do not count it as pruned
		}
		rk.views[id] = wound
		moved++
	}
	return moved
}

// --- Signed rosters ---------------------------------------------------------

// rosterHandler is notified when a roster arrives and its signature checks out.
// Whether to ACT on it is the app layer's decision — the epoch and the owner
// rule live where membership does.
type rosterHandler func(cookie string, r e2ee.Roster)

// SetRosterHandler registers the callback for verified inbound rosters.
func (c *Client) SetRosterHandler(fn rosterHandler) {
	c.e2eeMu.Lock()
	c.onRoster = fn
	c.e2eeMu.Unlock()
}

// SignRosterBody signs a roster and renders it for the wire, for the paths that
// carry one inside something else — an invite, where the recipient is not in the
// room yet and so cannot be sent one directly.
func (c *Client) SignRosterBody(r e2ee.Roster) (string, error) {
	signer, ok := c.signingKey()
	if !ok {
		return "", errors.New("client: no signing key, so a roster can't be authenticated")
	}
	signed, err := e2ee.SignRoster(r, signer)
	if err != nil {
		return "", err
	}
	return e2ee.EncodeRoster(signed)
}

// VerifiedRoster parses a roster carried inside an invite and checks it against
// the sender.
//
// Returns false for anything it cannot stand behind — malformed, unsigned, or
// signed by somebody other than the person who sent it. A caller must not fall
// back to trusting the contents anyway; an unverifiable membership claim is
// worth exactly nothing.
func (c *Client) VerifiedRoster(sender, body string) (e2ee.Roster, bool) {
	if body == "" {
		return e2ee.Roster{}, false
	}
	r, err := e2ee.DecodeRoster(body)
	if err != nil {
		return e2ee.Roster{}, false
	}
	if state.NormalizeScreenName(r.Author) != state.NormalizeScreenName(sender) {
		return e2ee.Roster{}, false
	}
	if err := e2ee.VerifyRoster(r, c.PeerSigningKeys(r.Author)); err != nil {
		return e2ee.Roster{}, false
	}
	return r, true
}

// SendRoster signs a roster and delivers it to each member over the 1:1
// encrypted channel.
//
// One message per member, and NOT an in-room broadcast, which is the opposite of
// how chain distribution works. Two reasons, both about what the server sees. A
// roster names people who are not in the room — members who are offline, and
// the person just removed — so broadcasting it in the clear would hand the
// server a membership list it does not otherwise have, on top of the occupancy
// it can already observe. And a roster is rare: it moves on an invite or a
// removal, not on the send path, so the per-member cost that made broadcasting
// worth it for chains does not apply here.
//
// Delivering to somebody twice would be harmless — a roster is a complete list
// at an epoch, not a delta, so applying one is idempotent.
func (c *Client) SendRoster(r e2ee.Roster, to []string) error {
	body, err := c.SignRosterBody(r)
	if err != nil {
		return err
	}
	self := state.NormalizeScreenName(c.store.Self().ScreenName)
	var failed []string
	for _, sn := range to {
		if state.NormalizeScreenName(sn) == self {
			continue
		}
		if err := c.sendProtocolMessage(sn, body); err != nil {
			c.log.Debug("could not deliver a roster", "peer", sn, "err", err)
			failed = append(failed, sn)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("client: could not reach %s", strings.Join(failed, ", "))
	}
	return nil
}

// handleRoster verifies an inbound roster and hands it up.
//
// The 1:1 channel is the ONLY way one arrives. That matters: it means the sender
// is already authenticated to their encryption key before the roster's own
// signature is checked, and it means a roster body pasted into a room is inert.
func (c *Client) handleRoster(sender, body string) {
	r, err := e2ee.DecodeRoster(body)
	if err != nil {
		c.log.Warn("bad roster", "from", sender, "err", err)
		return
	}
	// The author is what the signature binds; the OSCAR sender name is chosen by
	// the server and proves nothing on its own. They must agree, or a server
	// could relay somebody's genuine roster as though a different person had
	// sent it — and authority here turns on WHO signed.
	if state.NormalizeScreenName(r.Author) != state.NormalizeScreenName(sender) {
		c.log.Warn("discarding a roster whose author is not its sender",
			"sender", sender, "author", r.Author)
		return
	}
	keys := c.PeerSigningKeys(r.Author)
	if len(keys) == 0 {
		// Not a verdict — we simply cannot check it yet. Fetch, and let the next
		// copy land rather than acting on a membership claim we could not verify.
		go c.RefreshPeerKeys(r.Author)
		return
	}
	if err := e2ee.VerifyRoster(r, keys); err != nil {
		c.log.Warn("discarding a roster that does not verify", "author", r.Author, "err", err)
		return
	}

	cookie, ok := c.roomCookieByName(r.Room)
	if !ok {
		// A roster for a room we are not in. Nothing to apply it to, and nothing
		// worth remembering: joining later hands us a current one with the invite.
		return
	}

	c.e2eeMu.Lock()
	fn := c.onRoster
	c.e2eeMu.Unlock()
	if fn != nil {
		fn(cookie, r)
	}
}

// roomCookieByName finds a joined room by name.
func (c *Client) roomCookieByName(name string) (string, bool) {
	want := state.NormalizeScreenName(name)
	for _, r := range c.store.Rooms() {
		if state.NormalizeScreenName(r.Name) == want && r.Joined {
			return r.Cookie, true
		}
	}
	return "", false
}
