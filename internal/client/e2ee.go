package client

import (
	"errors"
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
func openWithAny(envelope string, senderKeys [][32]byte, ourPriv [32]byte) (string, bool) {
	for _, sk := range senderKeys {
		if plain, err := e2ee.OpenAny(envelope, sk, ourPriv); err == nil {
			return plain, true
		}
	}
	return "", false
}

// decodeIncoming returns the display text, whether it decrypted, and — when it
// did not — the raw envelope, so the message can be recovered once the sender's
// key arrives rather than being stranded behind a placeholder.
func (c *Client) decodeIncoming(from, body string) (text string, encrypted bool, cipher string) {
	if !e2ee.IsEnvelopeAny(body) {
		return body, false, ""
	}
	senderKeys, ourPriv, ok := c.openFrom(from)
	if !ok {
		go c.RequestUserInfo(from) // learn their keys, then retry via learnPeerKeys
		return "🔒 [encrypted message — waiting for the sender's key…]", false, body
	}
	if plain, opened := openWithAny(body, senderKeys, ourPriv); opened {
		return plain, true, ""
	}
	// Keep the envelope. This is also what a message sealed before the sender
	// knew about this device looks like, and re-fetching their profile may add
	// the sender key that opens it.
	go c.RequestUserInfo(from)
	return "🔒 [encrypted message — couldn't decrypt]", false, body
}

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
		if e2ee.IsRoomInvite(plain) {
			c.handleRoomInvite(screenName, plain)
			return "", true
		}
		if e2ee.IsCatchup(plain) {
			c.handleCatchup(screenName, plain)
			return "", true
		}
		return plain, true
	})
}

// ownKeyReply carries what this account currently has published in its profile.
type ownKeyReply struct {
	keys [][32]byte
	has  bool
}

// deliverOwnKey hands a self-directed locate reply to a waiting
// FetchOwnPublishedKey, if any. Non-blocking: with nobody waiting it's dropped.
func (c *Client) deliverOwnKey(keys [][32]byte, has bool) {
	c.e2eeMu.Lock()
	ch := c.ownKeyWait
	c.e2eeMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- ownKeyReply{keys: keys, has: has}:
	default:
	}
}

// FetchOwnPublishedKeys asks the server which device keys this account
// currently advertises. That set is what we merge our own key into, so a second
// machine adds itself rather than overwriting the first. Returns has=false if
// nothing is published or the reply doesn't arrive in time — the caller must
// treat a timeout as "unknown", never as "nothing there".
func (c *Client) FetchOwnPublishedKeys(timeout time.Duration) (keys [][32]byte, has bool, ok bool) {
	self := c.store.Self().ScreenName
	if self == "" || !c.SignedOn() {
		return nil, false, false
	}

	ch := make(chan ownKeyReply, 1)
	c.e2eeMu.Lock()
	c.ownKeyWait = ch
	c.e2eeMu.Unlock()
	defer func() {
		c.e2eeMu.Lock()
		c.ownKeyWait = nil
		c.e2eeMu.Unlock()
	}()

	c.RequestUserInfo(self)
	select {
	case r := <-ch:
		return r.keys, r.has, true
	case <-time.After(timeout):
		return nil, false, false
	}
}

// setLocateCapsProbe installs a test hook fired with the capabilities carried
// by each locate reply. Test-only: production code reads capabilities from the
// store, not from a callback.
func (c *Client) setLocateCapsProbe(fn func(screenName string, caps []oscar.Capability)) {
	c.e2eeMu.Lock()
	c.locateCapsProbe = fn
	c.e2eeMu.Unlock()
}

// SetDeviceMessageHandler registers the handler for device-linking traffic
// arriving from this account's other sessions.
func (c *Client) SetDeviceMessageHandler(fn func(kind string, keys [][32]byte)) {
	c.e2eeMu.Lock()
	c.onDeviceMessage = fn
	c.e2eeMu.Unlock()
}

func (c *Client) handleDeviceMessage(body string) {
	kind, keys, ok := e2ee.DecodeDeviceMessage(body)
	if !ok {
		return
	}
	c.e2eeMu.Lock()
	fn := c.onDeviceMessage
	c.e2eeMu.Unlock()
	if fn != nil {
		fn(kind, keys)
	}
}

// SendDeviceMessage sends device-linking traffic to our own account, which the
// server relays to every other signed-on session.
//
// Deliberately bypasses SendMessage: it must not be encrypted (a device that
// hasn't linked yet is precisely the one whose key nobody holds) and must not
// be recorded as a conversation message.
func (c *Client) SendDeviceMessage(kind string, keys [][32]byte) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	self := c.store.Self().ScreenName
	if self == "" {
		return errors.New("client: own screen name unknown")
	}
	_, err := session.SendMessage(self, e2ee.EncodeDeviceMessage(kind, keys), false)
	return err
}
