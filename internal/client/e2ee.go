package client

import (
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
)

// SetE2EEKeyPair installs our end-to-end keypair (loaded from the OS secret store
// on sign-on). With a keypair present we can decrypt inbound messages regardless
// of whether outbound encryption is on.
func (c *Client) SetE2EEKeyPair(kp e2ee.KeyPair, has bool) {
	c.e2eeMu.Lock()
	c.e2eeKP = kp
	c.e2eeHasKP = has
	c.e2eeMu.Unlock()
}

// SetOwnDeviceKeys installs this ACCOUNT's full published device set — ours plus
// any other machine signed in to it.
//
// Kept apart from the peer cache on purpose. learnFromManifest deliberately does
// not file our own screen name as a peer, because that would record a trust entry
// against ourselves and then warn us that our own key had changed the moment a
// second device published. But sent-message sync needs exactly those keys, and
// reading them out of a cache that is never populated is a silent no-op — the
// sync would simply never fire, and nothing would say so.
func (c *Client) SetOwnDeviceKeys(keys [][32]byte) {
	c.e2eeMu.Lock()
	c.ownDeviceKeys = keys
	c.e2eeMu.Unlock()
}

// ownDevices returns the account's device set and our private key.
func (c *Client) ownDevices() (keys [][32]byte, ourPriv [32]byte, ok bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeHasKP || len(c.ownDeviceKeys) == 0 {
		return nil, [32]byte{}, false
	}
	return c.ownDeviceKeys, c.e2eeKP.Private, true
}

// EncryptionPrivateKey returns this device's box private key, for the paths that
// seal outside the ordinary message flow.
func (c *Client) EncryptionPrivateKey() ([32]byte, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeHasKP {
		return [32]byte{}, false
	}
	return c.e2eeKP.Private, true
}

// SetE2EEOn toggles whether outbound messages are encrypted (when the peer's key
// is known).
func (c *Client) SetE2EEOn(on bool) {
	c.e2eeMu.Lock()
	c.e2eeOn = on
	c.e2eeMu.Unlock()
}

// learnPeerKeys caches the set of device public keys a peer publishes. Simple
// TOFU: the latest set seen is kept.
func (c *Client) learnPeerKeys(screenName string, keys [][32]byte) {
	if len(keys) == 0 {
		return
	}
	c.e2eeMu.Lock()
	key := state.NormalizeScreenName(screenName)
	prev := c.e2eeKeys[key]
	c.e2eeKeys[key] = keys
	c.e2eeKeysAt[key] = time.Now()
	onChange := c.onPeerKey
	c.e2eeMu.Unlock()

	// Anything that arrived from them before this point is decryptable now.
	c.retryPendingDecrypts(screenName)

	// Tell the app layer, which owns the persistent record of what we've seen
	// before and decides whether this warrants warning the user. `prev` only
	// covers this session's cache, so a first sighting here may still be a
	// change relative to what's on disk — that call isn't ours to make.
	if onChange != nil {
		onChange(screenName, keys, prev)
	}
}

// SetPeerKeyHandler registers a callback invoked whenever a peer's device set is
// learned. prev is this session's previously cached set, if any.
func (c *Client) SetPeerKeyHandler(fn func(screenName string, keys, prev [][32]byte)) {
	c.e2eeMu.Lock()
	c.onPeerKey = fn
	c.e2eeMu.Unlock()
}

// PeerKeys returns the peer's currently-known device keys (from TOFU
// discovery). Used by the app layer to compute and verify safety numbers.
func (c *Client) PeerKeys(screenName string) ([][32]byte, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	k, ok := c.e2eeKeys[state.NormalizeScreenName(screenName)]
	return k, ok && len(k) > 0
}

// OurPublicKey returns our own public key and whether a keypair is loaded.
func (c *Client) OurPublicKey() ([32]byte, bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.e2eeKP.Public, c.e2eeHasKP
}

// CanEncryptTo reports whether a message to screenName will be encrypted: E2EE
// is on and we hold at least one of the peer's published device keys.
func (c *Client) CanEncryptTo(screenName string) bool {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeOn || !c.e2eeHasKP {
		return false
	}
	k, ok := c.e2eeKeys[state.NormalizeScreenName(screenName)]
	return ok && len(k) > 0
}

// e2eeReady reports whether this client CAN encrypt at all — E2EE is on and we
// hold our own keypair — regardless of whether we know any given peer's keys.
// It is what tells the send path that fetching a peer's manifest is worth a try
// rather than plaintext being a foregone conclusion.
func (c *Client) e2eeReady() bool {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	return c.e2eeOn && c.e2eeHasKP
}

// peerKeyTTL bounds how long a cached device set is used without re-checking it
// against the directory.
//
// This is the window in which a device its owner has already removed still
// receives everything we send. Short enough that the window is a coffee break
// rather than however long the app happens to stay open; long enough that a
// conversation is not paying a directory round trip every few messages.
const peerKeyTTL = 20 * time.Minute

// peerKeysStale reports whether a peer's cached device set is old enough to be
// worth re-reading. True for a peer we have never checked.
func (c *Client) peerKeysStale(screenName string) bool {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	at, ok := c.e2eeKeysAt[state.NormalizeScreenName(screenName)]
	return !ok || time.Since(at) > peerKeyTTL
}

// markPeerKeysChecked restarts a peer's staleness clock without changing their
// keys, so a refresh already in flight doesn't get queued again behind every
// message sent while it runs.
func (c *Client) markPeerKeysChecked(screenName string) {
	c.e2eeMu.Lock()
	c.e2eeKeysAt[state.NormalizeScreenName(screenName)] = time.Now()
	c.e2eeMu.Unlock()
}

// forgetPeerKeys drops every cached device set. Called on sign-off.
func (c *Client) forgetPeerKeys() {
	c.e2eeMu.Lock()
	c.e2eeKeys = make(map[string][][32]byte)
	c.e2eeKeysAt = make(map[string]time.Time)
	c.e2eeMu.Unlock()
}

// EnsurePeerKeys fetches a peer's manifest if we do not already have their keys,
// or if what we have is stale, so a conversation shows its lock state and
// encrypts from the first message rather than after the first reply. Blocking;
// callers that must not stall (the UI opening a conversation) should run it in a
// goroutine.
func (c *Client) EnsurePeerKeys(screenName string) {
	if !c.e2eeReady() {
		return
	}
	if c.CanEncryptTo(screenName) && !c.peerKeysStale(screenName) {
		return
	}
	c.RefreshPeerKeys(screenName)
}

// sealFor returns the parameters to encrypt a message to screenName, or
// ok=false to send plaintext (E2EE off, no keypair, or the peer's keys
// unknown). Every one of the peer's devices is a recipient, so the message is
// readable on all of their machines rather than only the one that published
// most recently.
func (c *Client) sealFor(screenName string) (peerKeys [][32]byte, ourPriv [32]byte, ok bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeOn || !c.e2eeHasKP {
		return
	}
	k, has := c.e2eeKeys[state.NormalizeScreenName(screenName)]
	if !has || len(k) == 0 {
		return
	}
	return k, c.e2eeKP.Private, true
}

// openFrom returns the parameters to decrypt a message from screenName, or
// ok=false when we lack our keypair or the sender's keys. Decryption doesn't
// require outbound encryption to be on.
//
// The whole sender device set comes back because NaCl box authenticates against
// a specific sender key: with the sender on several machines we don't know which
// one sealed a given message, so each candidate has to be tried.
func (c *Client) openFrom(screenName string) (senderKeys [][32]byte, ourPriv [32]byte, ok bool) {
	c.e2eeMu.Lock()
	defer c.e2eeMu.Unlock()
	if !c.e2eeHasKP {
		return
	}
	k, has := c.e2eeKeys[state.NormalizeScreenName(screenName)]
	if !has || len(k) == 0 {
		return
	}
	return k, c.e2eeKP.Private, true
}

// openWithAny tries every candidate sender key against an envelope, returning
// the plaintext from whichever authenticates.
func openWithAny(envelope string, senderKeys [][32]byte, ourPriv [32]byte) (e2ee.Stamped, bool) {
	for _, sk := range senderKeys {
		if plain, err := e2ee.OpenAny(envelope, sk, ourPriv); err == nil {
			return plain, true
		}
	}
	return e2ee.Stamped{}, false
}

// decodeIncoming returns the display text, whether it decrypted, and — when it
// did not — the raw envelope, so the message can be recovered once the sender's
// key arrives rather than being stranded behind a placeholder.
func (c *Client) decodeIncoming(from, body string) (text string, encrypted bool, cipher string) {
	text, encrypted, cipher, _ = c.decodeIncomingStamped(from, body)
	return text, encrypted, cipher
}

// decodeIncomingStamped is decodeIncoming plus the sender's own claim about when
// they sent the message.
//
// That claim is sealed, so it cannot be forged without the sending key, and it
// is what makes a replay visible: a server redelivering last month's message
// gets it rendered with last month's timestamp rather than as something said
// just now. Zero when the sender told us nothing — a legacy envelope, or a
// plaintext message — in which case the caller falls back to its own clock.
func (c *Client) decodeIncomingStamped(from, body string) (text string, encrypted bool, cipher string, sentAt time.Time) {
	if !e2ee.IsEnvelopeAny(body) {
		return body, false, "", time.Time{}
	}
	senderKeys, ourPriv, ok := c.openFrom(from)
	if !ok {
		go c.RefreshPeerKeys(from) // learn their keys, then retry via learnPeerKeys
		return "🔒 [encrypted message — waiting for the sender's key…]", false, body, time.Time{}
	}
	if plain, opened := openWithAny(body, senderKeys, ourPriv); opened {
		if c.seenBefore(from, plain.ID) {
			// An exact duplicate. Not merely odd — the same sealed message
			// arriving twice is the server handing us a copy it kept.
			c.log.Warn("dropping a duplicate message", "from", from)
			return "", false, "", time.Time{}
		}
		return plain.Text, true, "", plain.SentAt
	}
	// Keep the envelope. This is also what a message sealed before the sender
	// knew about this device looks like, and re-fetching their keys may add the
	// sender key that opens it.
	go c.RefreshPeerKeys(from)
	return "🔒 [encrypted message — couldn't decrypt]", false, body, time.Time{}
}

// seenBefore records a message ID and reports whether it had already arrived.
//
// Bounded and in memory: this catches the replay that is worth catching — the
// same message delivered twice in a session — without pretending to be a durable
// ledger. A replay that survives a restart is caught by its timestamp instead,
// which is the defence that does not depend on remembering anything.
func (c *Client) seenBefore(from string, id [16]byte) bool {
	var zero [16]byte
	if id == zero {
		return false // a legacy envelope carried no ID; nothing to compare
	}
	return c.seenKeyBefore(state.NormalizeScreenName(from) + ":" + string(id[:]))
}

// seenKeyBefore is seenBefore over an arbitrary key, for traffic whose identity
// is derived rather than carried — sync copies, whose ID is a hash of the copy
// itself.
func (c *Client) seenKeyBefore(key string) bool {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if c.seenIDs == nil {
		c.seenIDs = make(map[string]bool, seenIDsMax)
	}
	if c.seenIDs[key] {
		return true
	}
	if len(c.seenIDs) >= seenIDsMax {
		// Cheap eviction: drop everything rather than track an order. The set
		// exists to catch a burst of duplicates, and losing it costs one missed
		// duplicate at the boundary, not correctness.
		c.seenIDs = make(map[string]bool, seenIDsMax)
	}
	c.seenIDs[key] = true
	return false
}

// seenIDsMax bounds the duplicate set. Large enough to span any plausible burst
// of redelivery, small enough that it is never a memory concern.
const seenIDsMax = 4096

// retryPendingDecrypts re-attempts any of this peer's messages that arrived
// before we held their key. Called whenever a key is learned.
func (c *Client) retryPendingDecrypts(screenName string) {
	senderKeys, ourPriv, ok := c.openFrom(screenName)
	if !ok {
		return
	}
	c.store.DecryptPending(screenName, func(cipher string) (string, bool) {
		plain, opened := openWithAny(cipher, senderKeys, ourPriv)
		if !opened {
			return "", false
		}
		// A message recovered late can be protocol traffic, not chat: a room
		// invitation that arrived before we held the sender's key would
		// otherwise be surfaced as text and never acted on — the invitation
		// silently lost, with a wall of base64 shown to the user instead.
		// Protocol traffic recovered late is still protocol traffic: act on it
		// and drop the message entirely rather than leaving a placeholder where
		// the user expects something a person said. An empty result tells the
		// store to remove it.
		if e2ee.IsRoomInvite(plain.Text) {
			c.handleRoomInvite(screenName, plain.Text)
			return "", true
		}
		if e2ee.IsCatchup(plain.Text) {
			c.handleCatchup(screenName, plain.Text)
			return "", true
		}
		return plain.Text, true
	})
}

// setLocateCapsProbe installs a test hook fired with the capabilities carried
// by each locate reply. Test-only: production code reads capabilities from the
// store, not from a callback.
func (c *Client) setLocateCapsProbe(fn func(screenName string, caps []oscar.Capability)) {
	c.e2eeMu.Lock()
	c.locateCapsProbe = fn
	c.e2eeMu.Unlock()
}

// --- Sent-message sync ------------------------------------------------------

// syncSentMessage sends a copy of an outbound message to our own other devices.
//
// Best effort and deliberately silent on failure: the message itself has already
// gone, and failing to mirror it to a laptop is not a reason to tell the user
// their message did not send. It is logged, not surfaced.
//
// Gated on the account actually having another device. Every sync costs a second
// outbound message against the same rate limiter as the first, and a
// single-device account — which is most of them — would otherwise pay double for
// a copy nothing will ever read.
func (c *Client) syncSentMessage(to, text string) {
	c.e2eeMu.Lock()
	self := c.selfNormalized
	signer, hasSigner := c.signKP, c.hasSignKP
	c.e2eeMu.Unlock()
	if self == "" || !hasSigner {
		return
	}
	// Never mirror a message we sent to ourselves. It already reached every
	// device, and a sync of a sync is a loop with a network hop in it.
	if state.NormalizeScreenName(to) == self {
		return
	}

	ourKeys, ourPriv, ok := c.ownDevices()
	if !ok || len(ourKeys) < 2 {
		// Fewer than two device keys means this device is the only one, so
		// there is nobody to tell.
		return
	}

	body, err := e2ee.EncodeSentCopy(e2ee.SentCopy{
		Origin: e2ee.SignerID(signer.Public),
		Peer:   to,
		Text:   text,
		SentAt: time.Now().Unix(),
	})
	if err != nil {
		c.log.Warn("could not encode a sent-message copy", "err", err)
		return
	}
	env, err := e2ee.SealFor(body, ourKeys, ourPriv)
	if err != nil {
		c.log.Warn("could not seal a sent-message copy", "err", err)
		return
	}

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}
	// To ourselves. The server relays an inbound message to every instance of
	// the recipient, which is precisely the fan-out we want and the reason this
	// needs no new infrastructure.
	if _, _, err := session.SendMessage(self, env, false); err != nil {
		c.log.Debug("could not deliver a sent-message copy", "err", err)
	}
}

// applySentCopy records a message another of our devices sent.
//
// The sender check is the whole trust story here: the envelope was sealed to our
// own device keys and authenticated against the sender's, so only somebody
// holding one of THIS ACCOUNT's device private keys could have produced it. A
// copy claiming to come from anyone else is not a sync, it is somebody trying to
// write into our conversations.
func (c *Client) applySentCopy(from, body string) {
	c.e2eeMu.Lock()
	self := c.selfNormalized
	signer, hasSigner := c.signKP, c.hasSignKP
	c.e2eeMu.Unlock()
	if state.NormalizeScreenName(from) != self {
		c.log.Warn("discarding a sent-message copy that did not come from us", "from", from)
		return
	}

	sc, err := e2ee.DecodeSentCopy(body)
	if err != nil {
		c.log.Warn("bad sent-message copy", "err", err)
		return
	}
	// Our own copy, come back around. Harmless to receive and wrong to apply:
	// the message is already in this device's store, and adding it again would
	// show the user everything they said twice.
	if hasSigner && sc.Origin == e2ee.SignerID(signer.Public) {
		return
	}
	// The same copy twice — a redelivery, or two connections briefly overlapping
	// — must not put the message in the conversation twice.
	id := e2ee.SentCopyID(sc)
	if c.seenKeyBefore("sync:" + id) {
		c.log.Debug("dropping a duplicate sent-message copy")
		return
	}

	at := time.Unix(sc.SentAt, 0)
	if !e2ee.PlausibleSendTime(at, time.Now()) {
		// Clamped rather than refused. The stamp is another of our own devices'
		// clocks, which can be wrong without anything being wrong, and dropping
		// the message over it would lose real content to a timezone bug.
		c.log.Debug("a sent-message copy carried an implausible time; using now", "at", at)
		at = time.Now()
	}

	c.store.AddMessage(state.Message{
		From:      c.store.Self().ScreenName,
		To:        sc.Peer,
		Text:      sc.Text,
		At:        at,
		Outgoing:  true,
		Encrypted: true,
		// No cookie: this is not a send from THIS device, so there is no
		// acknowledgement coming and nothing to track. The ID is derived from
		// the copy rather than assigned, so it is stable across devices.
		ID: id,
	})
}
