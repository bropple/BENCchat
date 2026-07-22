package client

import (
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// Client access to the BENCO device key directory (foodgroup 0xBE00).
//
// This replaced publishing device keys inside the Locate profile, and is now the
// only place they live. If the server does not advertise the foodgroup,
// SupportsKeyDir is false and there is nowhere left to publish or read keys —
// callers report that rather than silently degrading to plaintext.
//
// In v2 the unit of exchange is a signed MANIFEST, not a device list, and this
// layer never opens one. Manifest bytes go out exactly as the signer produced
// them and come back exactly as received; deciding whether a manifest is
// trustworthy is internal/e2ee's job, reached through the verifier hook below.
// Re-encoding a manifest anywhere on this path would invalidate its signature.

// keyDirTimeout bounds a directory round trip.
//
// A timeout must never be read as "this peer has no keys" — that would make a
// sender fall back to plaintext because the network hiccuped. Callers get a
// distinct ok=false for it, separate from a reply that legitimately says the
// account has published nothing.
const keyDirTimeout = 5 * time.Second

// SignedManifest is a manifest exactly as the directory returned it.
//
// Manifest and Signature are carried together and untouched because they are
// only meaningful as a pair: the signature covers those bytes and no
// re-serialization of them. Present is false for an account that has published
// nothing, which is a real answer rather than a failure.
type SignedManifest struct {
	ScreenName string
	Present    bool
	Manifest   []byte
	SigAlg     uint8
	Signature  []byte
}

// IdentityBackup is the encrypted account identity key as stored on the server.
//
// The KDF parameters travel with the blob rather than being assumed, so the
// work factor can be raised later without stranding backups made under the old
// one. Present is false for an account that has never bootstrapped an identity
// — which is how a client tells a first run from a new device being linked.
type IdentityBackup struct {
	Present bool
	KDF     uint8
	Params  []byte
	Salt    []byte
	Blob    []byte
}

// ManifestVerifier checks a manifest's signature over the bytes AS RECEIVED and
// returns the devices it names.
//
// It is a function type so that this package never links against signature
// code: the plumbing carries bytes, internal/e2ee decides whether they are
// worth believing. An implementation is expected to be built on
// e2ee.VerifyManifest, which is where the actual signature check lives — a hook
// rather than a direct call because choosing WHICH identity key to verify
// against is a trust-store question, and the trust store is not down here.
//
// An implementation must verify before decoding, and must
// apply the counter rule (never accept a counter below the highest already seen
// for that account) — this layer cannot do either, because it holds no trust
// store and no notion of what a peer's identity is supposed to be.
//
// Returning ok=false means the manifest is not to be believed at all, and no
// keys are learned from it.
type ManifestVerifier func(sm SignedManifest) (devices []e2ee.Device, ok bool)

// SetManifestVerifier installs the hook that decides whether a received
// manifest is trustworthy. Until it is set, no inbound manifest teaches this
// client anything.
func (c *Client) SetManifestVerifier(v ManifestVerifier) {
	c.e2eeMu.Lock()
	c.verifyManifest = v
	c.e2eeMu.Unlock()
}

// keyDirReply is one decoded directory response.
//
// It is a union across the four reply subgroups rather than four channels,
// because correlation is by request ID and a waiter already knows which kind of
// answer it asked for.
type keyDirReply struct {
	manifest SignedManifest

	// Publish. counter is what the server holds after the call, which is what
	// makes a lost race actionable: a client refused as stale learns the value
	// it has to beat instead of having to re-query for it.
	accepted bool
	counter  uint64

	stored bool
	backup IdentityBackup
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

// QueryManifest fetches an account's signed manifest from the directory.
//
// ok is false when the directory is unavailable or the reply does not arrive.
// That is deliberately distinct from a reply whose Present is false, which is a
// real answer meaning the account has published nothing: treating a timeout as
// "no keys" would silently downgrade a conversation to plaintext.
//
// The returned bytes are unverified. Callers must run them past a
// ManifestVerifier before believing anything in them.
func (c *Client) QueryManifest(screenName string) (SignedManifest, bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return SignedManifest{}, false
	}

	reqID, err := sess.QueryManifest(screenName)
	if err != nil {
		c.log.Warn("key directory query failed to send", "screen_name", screenName, "err", err)
		return SignedManifest{}, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.manifest, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory query timed out", "screen_name", screenName)
		return SignedManifest{}, false
	}
}

// PublishManifest publishes this account's signed device manifest.
//
// manifest must be the exact bytes that were signed. accepted is false when the
// server refused it — most usefully because the counter did not advance, which
// means another device published first; counter then carries what the server
// holds, so the caller can re-sign above it rather than guess.
func (c *Client) PublishManifest(manifest []byte, sigAlg uint8, signature []byte) (accepted bool, counter uint64, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return false, 0, false
	}

	reqID, err := sess.PublishManifest(manifest, sigAlg, signature)
	if err != nil {
		c.log.Warn("key directory publish failed to send", "err", err)
		return false, 0, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.accepted, r.counter, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("key directory publish timed out")
		return false, 0, false
	}
}

// PutIdentityBackup stores this account's encrypted identity key.
//
// The blob is opaque here: this layer neither derives the wrapping key nor
// checks that the parameters are sane, because it cannot — the recovery phrase
// never reaches it, and neither does the server's.
func (c *Client) PutIdentityBackup(kdf uint8, params, salt, blob []byte) (stored bool, ok bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return false, false
	}

	reqID, err := sess.PutIdentityBackup(kdf, params, salt, blob)
	if err != nil {
		c.log.Warn("identity backup store failed to send", "err", err)
		return false, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.stored, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("identity backup store timed out")
		return false, false
	}
}

// GetIdentityBackup fetches this account's encrypted identity key.
//
// ok=false is a failed round trip, and must not be confused with a successful
// reply whose Present is false. The second means "this account has never
// bootstrapped an identity" and drives the first-run flow; acting on the first
// as if it were the second would generate a fresh identity and orphan every
// device already trusting the old one.
func (c *Client) GetIdentityBackup() (IdentityBackup, bool) {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil || !sess.SupportsKeyDir() {
		return IdentityBackup{}, false
	}

	reqID, err := sess.GetIdentityBackup()
	if err != nil {
		c.log.Warn("identity backup fetch failed to send", "err", err)
		return IdentityBackup{}, false
	}
	ch, done := c.waitKeyDir(reqID)
	defer done()

	select {
	case r := <-ch:
		return r.backup, true
	case <-time.After(keyDirTimeout):
		c.log.Warn("identity backup fetch timed out")
		return IdentityBackup{}, false
	}
}

// peerKeyLookup is why a peer's device keys are, or are not, in hand after
// asking the directory for them.
//
// The distinction that matters is absent vs unavailable. Collapsing them is how
// a server that simply declines to answer key lookups reads a conversation it
// has no key for: every send falls back to plaintext, and the only signal to the
// user is a lock that never appears.
type peerKeyLookup int

const (
	// peerKeysFound: verified keys are cached and encryption can proceed.
	peerKeysFound peerKeyLookup = iota
	// peerKeysAbsent: the directory answered, and this account has published
	// nothing. Not a BENCchat user, or one that never turned E2EE on. Plaintext
	// is correct here and is the only thing that will ever work.
	peerKeysAbsent
	// peerKeysUnavailable: no usable answer — timed out, could not be sent, or a
	// manifest arrived that taught us nothing. Says nothing about whether the
	// peer has keys, so it must not be treated as though it said they have none.
	peerKeysUnavailable
)

// RefreshPeerKeys learns a peer's device keys from the directory.
//
// The trailing Locate fetch is no longer a key-learning fallback: profiles stop
// carrying keys as of the commit that made the directory the sole source, and
// handleLocate does not parse them. It survives because the same round trip also
// refreshes capabilities, away text and profile text, which the UI wants anyway
// when a conversation turns out to have no keys.
//
// Blocking, because the directory round trip has to complete first. Callers run
// it in a goroutine.
func (c *Client) RefreshPeerKeys(screenName string) peerKeyLookup {
	c.markPeerKeysChecked(screenName)

	c.e2eeMu.Lock()
	probe := c.keyLookupProbe
	c.e2eeMu.Unlock()
	if probe != nil {
		return probe(screenName)
	}

	if !c.SupportsKeyDir() {
		// The server carries no key directory at all, so nobody has keys and no
		// retry changes that. Reported as absent rather than unavailable on
		// purpose: it is a property of the whole deployment, visible everywhere
		// at once (no locks, no safety numbers, anywhere), not a per-peer answer
		// that might be different in a moment. Refusing every send against such
		// a server would be a worse failure than sending as it always has.
		c.RequestUserInfo(screenName)
		return peerKeysAbsent
	}

	sm, ok := c.QueryManifest(screenName)
	switch {
	case !ok:
		// Timed out, or the query could not be sent. NOT an answer.
		c.RequestUserInfo(screenName)
		return peerKeysUnavailable
	case !sm.Present:
		c.RequestUserInfo(screenName)
		// "This account has published nothing" is an unauthenticated byte, and
		// treating it as fact is the other half of the downgrade this function
		// exists to stop. Refusing to answer is now caught; answering FALSELY
		// was not — a server that says "no keys" for somebody we have already
		// held keys for still got a plaintext send.
		//
		// We cannot verify the claim, but we can notice it contradicts what we
		// have seen. A peer we have never heard of may genuinely have published
		// nothing; a peer we hold a record for has not un-published between two
		// sign-ons, and if they somehow have, refusing to send is the safe way
		// to be wrong.
		if c.peerKnownToHavePublished(screenName) {
			c.log.Warn("refusing to treat a peer we have keys for as having none",
				"screen_name", screenName)
			return peerKeysUnavailable
		}
		return peerKeysAbsent
	}

	// A manifest came back. handleKeyDir already ran it past the verifier and
	// cached the keys if it passed, so whether we now hold keys is the answer:
	// a manifest that failed its signature, or lost to the counter rule, taught
	// us nothing and must not be mistaken for the account having published none.
	if _, held := c.PeerKeys(screenName); held {
		return peerKeysFound
	}
	c.log.Warn("a manifest arrived but taught us no keys", "screen_name", screenName)
	return peerKeysUnavailable
}

// handleKeyDir dispatches an inbound key directory SNAC.
func (c *Client) handleKeyDir(frame wire.SNACFrame, body []byte) {
	switch frame.SubGroup {
	case wire.BENCOKeyDirAttestChallenge:
		c.answerAttestChallenge(body)

	case wire.BENCOKeyDirAttestReply:
		reply, err := oscar.DecodeKeyDirAttestReply(body)
		if err != nil {
			c.log.Warn("bad device attestation reply", "err", err)
			return
		}
		if reply.Accepted == 0 {
			// The session is not proven. The server decides what that costs —
			// it may simply close the connection — but say so, because the
			// alternative is a session that silently stops working.
			c.log.Warn("the server did not accept this device's attestation")
			c.store.Notify(state.NoticeWarn,
				"This device couldn't prove itself to the server. If it was removed "+
					"from your account, link it again with your recovery key.")
		}

	case wire.BENCOKeyDirQueryReply:
		reply, err := oscar.DecodeKeyDirQueryReply(body)
		if err != nil {
			c.log.Warn("bad key directory query reply", "err", err)
			return
		}
		sm := SignedManifest{
			ScreenName: reply.ScreenName,
			Present:    reply.Present != 0,
			Manifest:   reply.Manifest,
			SigAlg:     reply.SigAlg,
			Signature:  reply.Signature,
		}
		c.learnFromManifest(sm)
		c.deliverKeyDir(frame.RequestID, keyDirReply{manifest: sm})

	case wire.BENCOKeyDirPublishReply:
		reply, err := oscar.DecodeKeyDirPublishReply(body)
		if err != nil {
			c.log.Warn("bad key directory publish reply", "err", err)
			return
		}
		if reply.Accepted == 0 {
			// Worth logging rather than only returning: the usual cause is
			// another device of ours having published at a higher counter, and
			// that is a fact about the account, not about this call.
			c.log.Info("key directory refused a manifest", "server_counter", reply.Counter)
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{
			accepted: reply.Accepted != 0,
			counter:  reply.Counter,
		})

	case wire.BENCOKeyDirPutBackupReply:
		reply, err := oscar.DecodeKeyDirPutBackupReply(body)
		if err != nil {
			c.log.Warn("bad identity backup store reply", "err", err)
			return
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{stored: reply.Stored != 0})

	case wire.BENCOKeyDirGetBackupReply:
		reply, err := oscar.DecodeKeyDirGetBackupReply(body)
		if err != nil {
			c.log.Warn("bad identity backup fetch reply", "err", err)
			return
		}
		c.deliverKeyDir(frame.RequestID, keyDirReply{backup: IdentityBackup{
			Present: reply.Present != 0,
			KDF:     reply.KDF,
			Params:  reply.Params,
			Salt:    reply.Salt,
			Blob:    reply.Blob,
		}})

	case wire.BENCOKeyDirErr:
		// Deliver an empty reply so a waiter fails fast rather than sitting out
		// the full timeout for an error the server already reported.
		c.log.Warn("key directory returned an error", "request_id", frame.RequestID)
		c.deliverKeyDir(frame.RequestID, keyDirReply{})
	}
}

// learnFromManifest caches a peer's device keys off a query reply.
//
// This runs on every query, not just ones a caller is waiting on, so that a
// lookup made for any reason keeps the send-side cache warm — the same thing the
// profile path used to do on a locate reply.
//
// It goes through the verifier and does nothing without one. A manifest that
// has not been checked is exactly as good as one the server invented, and the
// whole point of v2 is that the server does not get to decide who our peers'
// devices are.
func (c *Client) learnFromManifest(sm SignedManifest) {
	if !sm.Present {
		return
	}
	c.e2eeMu.Lock()
	verify := c.verifyManifest
	c.e2eeMu.Unlock()
	if verify == nil {
		c.log.Warn("dropping a manifest: no verifier installed", "screen_name", sm.ScreenName)
		return
	}
	devices, ok := verify(sm)
	if !ok {
		c.log.Warn("manifest failed verification", "screen_name", sm.ScreenName)
		return
	}

	// Our own screen name is deliberately not filed as a peer. A self-query
	// answers with our own account, and treating that like anyone else's would
	// record a trust entry against ourselves and then warn us that our own key
	// had changed the moment a second device published.
	if c.isSelf(sm.ScreenName) || len(devices) == 0 {
		return
	}
	c.learnPeerKeys(sm.ScreenName, e2ee.BoxKeysOf(devices))
	c.learnPeerSigningKeys(sm.ScreenName, e2ee.SigningKeysOf(devices))
}

// answerAttestChallenge proves which device this session is.
//
// The server asks because a password proves an ACCOUNT and not which of its
// devices is talking — without this, a device removed from the manifest keeps
// signing in with the same password and nothing on the server can tell.
//
// A challenge we cannot answer is left unanswered rather than answered badly.
// There is nothing useful to send without the signing key, and an empty or
// invented response would look like an attestation failure rather than like a
// device that has not finished setting itself up.
func (c *Client) answerAttestChallenge(body []byte) {
	ch, err := oscar.DecodeKeyDirAttestChallenge(body)
	if err != nil {
		c.log.Warn("bad device attestation challenge", "err", err)
		return
	}
	// The nonce is the other field the server chooses in what we are about to
	// sign. Pinning its length leaves the server able to vary 32 random bytes
	// and nothing else — without this it can choose the length too, and between
	// that and the screen name it has a signing oracle over bytes of its
	// choosing.
	if len(ch.Nonce) != e2ee.AttestNonceLen {
		c.log.Warn("refusing a device challenge with an implausible nonce",
			"len", len(ch.Nonce), "want", e2ee.AttestNonceLen)
		return
	}
	signer, ok := c.signingKey()
	if !ok {
		c.log.Warn("cannot answer a device challenge: no signing key on this device")
		return
	}

	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess == nil {
		return
	}

	// The name WE signed on as, not the one the server echoed back. Two separate
	// reasons, and both bite:
	//
	// The server verifies against its own normalized form — lowercased, spaces
	// stripped — while the store holds the string the user typed, echoed back
	// verbatim. Signing the display form fails attestation for every account
	// with a capital or a space, which under enforce is a permanent lockout
	// presenting as a mystery disconnect rather than an auth failure.
	//
	// And taking it from the server at all hands the server one of the two
	// variable fields in what this device signs.
	c.e2eeMu.Lock()
	self := c.selfNormalized
	c.e2eeMu.Unlock()
	if self == "" {
		c.log.Warn("cannot answer a device challenge: no signed-on account name")
		return
	}

	sig := e2ee.SignAttestation(self, ch.Nonce, signer.Private)
	if err := sess.AttestDevice(signer.Public, sig); err != nil {
		c.log.Warn("could not answer the device challenge", "err", err)
	}
}

// peerKnownToHavePublished reports whether we have ever held device keys for a
// peer, from this session's cache or from the persisted trust record.
//
// The trust store is the durable half and the one that matters: the cache is
// empty on the first send after a restart, which is precisely when a hostile
// "they have no keys" would be believed.
func (c *Client) peerKnownToHavePublished(screenName string) bool {
	if _, ok := c.PeerKeys(screenName); ok {
		return true
	}
	c.e2eeMu.Lock()
	fn := c.peerHistoryFn
	c.e2eeMu.Unlock()
	return fn != nil && fn(screenName)
}

// SetPeerHistoryFunc installs the lookup that says whether a peer has ever been
// seen to publish keys. The record lives in the app layer's trust store; this
// layer only needs the answer.
func (c *Client) SetPeerHistoryFunc(fn func(screenName string) bool) {
	c.e2eeMu.Lock()
	c.peerHistoryFn = fn
	c.e2eeMu.Unlock()
}
