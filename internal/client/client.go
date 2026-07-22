// Package client joins the OSCAR protocol layer to the protocol-agnostic state
// model.
//
// It is the only place that knows about both: it translates inbound SNACs into
// Store mutations, and turns UI intents ("send this message") into SNACs. The
// UI talks to a Client and a Store, never to oscar or wire — which is what lets
// a headless consumer reuse everything below this line.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// Client is a signed-on (or signed-off) OSCAR client.
type Client struct {
	store *state.Store
	log   *slog.Logger

	mu      sync.Mutex
	session *oscar.Session
	cancel  context.CancelFunc
	// lastSearch is the email of the in-flight user search; the reply doesn't
	// echo the query, so it's remembered here to label the result.
	lastSearch string

	// Chat rooms run on their own connections. chatNav is the shared ChatNav
	// connection (opened on first room join); rooms holds one Chat connection per
	// joined room, keyed by room cookie. serviceReply/navReply carry the async
	// request/reply bodies back to the serialized JoinRoom flow. Guarded by chatMu
	// (joinMu serializes the multi-step join itself).
	chatMu        sync.Mutex
	chatNav       *oscar.Session
	chatNavCancel context.CancelFunc
	rooms         map[string]*roomConn
	joinMu        sync.Mutex
	serviceReply  chan []byte
	navReply      chan []byte

	// End-to-end encryption. e2eeKP/e2eeHasKP is our keypair (loaded on sign-on if
	// one exists); e2eeOn is whether to encrypt outbound (decryption always
	// happens when we have a keypair). e2eeKeys caches peers' public keys learned
	// from the key directory. Guarded by e2eeMu.
	e2eeMu    sync.Mutex
	e2eeOn    bool
	e2eeHasKP bool
	e2eeKP    e2ee.KeyPair
	// e2eeKeys maps a peer to the SET of device keys they publish — one account
	// can be signed in from several machines, each with its own key.
	e2eeKeys map[string][][32]byte
	// e2eeKeysAt records when each peer's set was last checked against the
	// directory, so a stale one can be re-fetched.
	//
	// Nothing else expires this cache. A peer who removes a device publishes a
	// new manifest without it, but we only ever re-read a manifest on a cache
	// MISS or a failed decrypt — and a removed device decrypts our messages
	// perfectly well, so neither fires. Without a clock here, a client left
	// running keeps encrypting to a device its owner removed for as long as the
	// process happens to stay up, which is unbounded.
	e2eeKeysAt map[string]time.Time
	// onPeerKey is notified when a peer's device set is learned, so the app layer
	// can compare it against the persisted record and warn on a change.
	onPeerKey func(screenName string, keys, prev [][32]byte)
	// seenIDs are the message IDs already delivered this session, for dropping a
	// message the server hands us twice. Guarded by seenMu, and deliberately
	// separate from e2eeMu: this is touched on every inbound message and has no
	// business contending with key lookups.
	seenMu  sync.Mutex
	seenIDs map[string]bool
	// locateCapsProbe is a test hook; see setLocateCapsProbe.
	locateCapsProbe func(screenName string, caps []oscar.Capability)
	// onRoster is notified when a verified roster arrives. Guarded by e2eeMu.
	onRoster rosterHandler
	// peerHistoryFn reports whether a peer has ever been seen to publish keys,
	// so a server claiming otherwise can be disbelieved. Guarded by e2eeMu.
	peerHistoryFn func(screenName string) bool
	// persistChainFn durably writes a room's chain state before positions on it
	// are used; see reserveChainPositions. Guarded by e2eeMu.
	persistChainFn func(cookie string) error
	// selfNormalized is the account name we signed on AS, normalized, kept apart
	// from the server's echo in the store. Guarded by e2eeMu.
	selfNormalized string
	// roomMembersFn looks up who is in a room. Membership lives in the app layer;
	// the send path needs it here to distribute a new chain before sealing under
	// it. Guarded by e2eeMu.
	roomMembersFn func(cookie string) []string
	// keyLookupProbe, when set, stands in for the directory round trip in
	// RefreshPeerKeys. A test hook: the difference between "answered: nothing
	// published" and "would not answer" decides whether a send goes out in the
	// clear, and that is worth testing without a live server. See
	// setKeyLookupProbe.
	keyLookupProbe func(screenName string) peerKeyLookup
	// profileProbe, when set, receives every locate reply. LookupProfile uses it
	// to catch a one-shot profile fetch for someone who isn't a buddy (the store
	// only retains buddies' profiles). Guarded by e2eeMu.
	profileProbe func(screenName, profile, away string, hasProfile bool)
	// accepted (guarded by acceptedMu) is the set of buddies whose connection was
	// approved this session, normalized. It settles a race: an add whose server
	// AuthRequired triggers a "re-add as pending" can otherwise land AFTER the
	// acceptance cleared the pending tag, stranding a connected buddy showing
	// "pending". Both paths consult this set so the acceptance always wins.
	acceptedMu sync.Mutex
	accepted   map[string]bool
	// sends tracks outbound messages awaiting the server's acknowledgement, so one
	// the server rejected — or silently dropped, which is exactly what exceeding a
	// rate limit looks like from here — gets marked "not sent" instead of sitting
	// in the log looking delivered. Keyed by request ID (how an error correlates)
	// and by cookie (how an ack does). Guarded by sendMu.
	sendMu        sync.Mutex
	sendsByReq    map[uint32]*pendingSend
	sendsByCookie map[uint64]*pendingSend
	// pendingMu serializes the two paths that publish a buddy's pending state —
	// the re-add-as-pending goroutine and the acceptance handler — so neither can
	// publish a stale snapshot over the other. Held only around the decide+publish,
	// never around a network send.
	pendingMu sync.Mutex
	// keyDirWait correlates device key directory replies to their requests.
	// Keyed by request ID because several queries can be outstanding at once —
	// one per peer whose keys we want. See keydir.go.
	keyDirWait map[uint32]chan keyDirReply
	// verifyManifest checks a signed manifest and returns the devices it names.
	// It is a hook rather than a call because verification is internal/e2ee's
	// job and this package must not decide what to trust. Nil means no verifier
	// has been installed, in which case no manifest is ever learned from —
	// fail closed, since an unverified device set is exactly what v2 exists to
	// refuse. See SetManifestVerifier.
	verifyManifest ManifestVerifier

	// signKP is this device's room-message signing key, and peerSignKeys caches
	// the signing keys each peer publishes. Guarded by e2eeMu.
	signKP       e2ee.SigningKeyPair
	hasSignKP    bool
	peerSignKeys map[string][]ed25519.PublicKey

	// peerCaps caches what each peer's client advertises, keyed by normalized
	// screen name. Populated from buddy arrivals and locate replies — the BOS
	// paths that actually carry capabilities. Guarded by e2eeMu.
	peerCaps map[string]bool

	// chatProbe is a test hook fired with each decoded chat roster.
	chatProbe func(users []oscar.ChatUser)

	// roomCrypto holds per-room group keys and participant capability findings.
	roomCrypto roomCrypto

	// conn holds the consensual-connection callbacks (someone wants to connect /
	// a request we made was answered). See connections.go.
	conn connHandlers

	// OnDisconnect is called when the session ends, with the reason. It fires
	// for both clean sign-offs (io.EOF) and faults.
	OnDisconnect func(error)
}

// New returns a Client that publishes into store.
func New(store *state.Store, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		store:        store,
		log:          log,
		rooms:        make(map[string]*roomConn),
		serviceReply: make(chan []byte, 1),
		navReply:     make(chan []byte, 1),
		e2eeKeys:     make(map[string][][32]byte),
		e2eeKeysAt:   make(map[string]time.Time),
	}
}

// Secure reports whether the live session is encrypted in transit.
func (c *Client) Secure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil && c.session.Secure()
}

// SignedOn reports whether a session is currently live.
func (c *Client) SignedOn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil
}

// SignOn authenticates against addr and brings up a BOS session, populating the
// store with the buddy list and starting the read loop.
func (c *Client) SignOn(ctx context.Context, addr string, creds oscar.Credentials, tr ...oscar.Transport) error {
	if c.SignedOn() {
		return errors.New("client: already signed on")
	}

	res, err := oscar.Login(ctx, addr, creds, tr...)
	if err != nil {
		return err
	}

	session, err := oscar.SignOn(ctx, res)
	if err != nil {
		return err
	}

	// Publish identity and the buddy list before the read loop starts, so the
	// first presence updates land on a populated list rather than racing it.
	c.store.SetSelf(res.ScreenName)

	// Remember what we asked to BE, normalized, independent of what the server
	// echoed back. Everything user-facing uses the server's form because that
	// carries the casing a person recognises — but a device attestation must be
	// signed over a name WE chose, not one the server handed us. Otherwise the
	// server picks one of the two variable fields in what our device signs, and
	// a signing oracle over attacker-chosen bytes is exactly how a signature
	// obtained in one context gets rebuilt into another.
	c.e2eeMu.Lock()
	c.selfNormalized = state.NormalizeScreenName(creds.ScreenName)
	c.e2eeMu.Unlock()

	c.publishBuddyList(session.BuddyList())

	session.Handler = c.handleSNAC

	runCtx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.session = session
	c.cancel = cancel
	c.mu.Unlock()

	go c.run(runCtx, session)
	return nil
}

// run drives the read loop and reports why it ended.
func (c *Client) run(ctx context.Context, session *oscar.Session) {
	err := session.Run(ctx)

	c.mu.Lock()
	// Only tear down if this is still the current session: a re-sign-on could
	// have replaced it while the old loop was unwinding.
	if c.session == session {
		c.session = nil
		c.cancel = nil
	}
	c.mu.Unlock()

	_ = session.Close()
	// Chat connections are useless without BOS — tear them down too.
	c.closeAllChat()
	c.store.Reset()

	switch {
	case errors.Is(err, io.EOF), errors.Is(err, oscar.ErrClosed), errors.Is(err, context.Canceled):
		c.log.Info("session ended")
	default:
		c.log.Error("session ended unexpectedly", "err", err)
	}
	if c.OnDisconnect != nil {
		c.OnDisconnect(err)
	}
}

// SignOff tears down the session. It is safe to call when already signed off.
func (c *Client) SignOff() error {
	c.mu.Lock()
	session, cancel := c.session, c.cancel
	c.session, c.cancel = nil, nil
	c.mu.Unlock()

	if session == nil {
		return nil
	}
	if cancel != nil {
		cancel()
	}
	// Peers' device sets belong to the session that learned them. Keeping them
	// across a sign-off would carry one account's view of who holds which keys
	// into the next account signed on here, and would let a set learned before
	// the disconnect outlive whatever changed while we were away.
	c.forgetPeerKeys()
	return session.Close()
}

// SendMessage sends an instant message and records it in the store.
//
// The message is stored optimistically rather than on the server's ack: the ack
// only confirms the server accepted it, and a user expects to see what they
// typed appear immediately.
func (c *Client) SendMessage(to, text string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	if text == "" {
		return errors.New("client: message is empty")
	}

	wireText, encrypted, err := c.sealOutbound(to, text)
	if err != nil {
		return err
	}

	cookie, reqID, err := session.SendMessage(to, wireText, false)
	if err != nil {
		return err
	}
	c.store.AddMessage(state.Message{
		From:      c.store.Self().ScreenName,
		To:        to,
		Text:      text,
		At:        time.Now(),
		Outgoing:  true,
		Encrypted: encrypted,
		Cookie:    cookie,
		ID:        strconv.FormatUint(cookie, 16),
	})
	c.trackSend(to, cookie, reqID)
	return nil
}

// ResendMessage re-sends a message that failed, removing the failed row so the
// thread doesn't accumulate a dead copy beside the real one. Deliberately manual:
// there's no server-side de-duplication, so an automatic retry after a lost
// acknowledgement would post the message twice.
func (c *Client) ResendMessage(to, id string) error {
	text, ok := c.store.TakeMessage(to, id)
	if !ok {
		return errors.New("client: that message is no longer here to resend")
	}
	return c.SendMessage(to, text)
}

// ackTimeout is how long a sent message waits for the server's acknowledgement
// before it's treated as lost. Generous, because a false "not sent" on a message
// that did arrive is worse than a slow one: the send itself has already cleared
// the client's rate pacing by the time this starts.
const ackTimeout = 15 * time.Second

// pendingSend is one outbound message waiting to be confirmed by the server.
type pendingSend struct {
	to     string
	cookie uint64
	reqID  uint32
	timer  *time.Timer
}

// trackSend registers an outbound message and starts the clock on its
// acknowledgement. If none arrives before ackTimeout, the message is marked not
// sent — the server discards rate-limited SNACs without a word, so silence is
// the only evidence we get.
func (c *Client) trackSend(to string, cookie uint64, reqID uint32) {
	p := &pendingSend{to: to, cookie: cookie, reqID: reqID}

	c.sendMu.Lock()
	if c.sendsByReq == nil {
		c.sendsByReq = map[uint32]*pendingSend{}
		c.sendsByCookie = map[uint64]*pendingSend{}
	}
	c.sendsByReq[reqID] = p
	c.sendsByCookie[cookie] = p
	c.sendMu.Unlock()

	p.timer = time.AfterFunc(ackTimeout, func() {
		if _, ok := c.takeSendByCookie(cookie); ok {
			c.store.SetMessageNotSent(to, cookie, true)
			c.log.Warn("message never acknowledged — marking not sent",
				"to", to, "hint", "server drops SNACs that exceed a rate limit")
		}
	})
}

// takeSendByReq removes a pending send by request ID (how an ICBM error is
// correlated), reporting whether it was still pending — so only the first of
// ack, error or timeout acts on it.
func (c *Client) takeSendByReq(reqID uint32) (*pendingSend, bool) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	p, ok := c.sendsByReq[reqID]
	if !ok {
		return nil, false
	}
	c.dropSendLocked(p)
	return p, true
}

// takeSendByCookie is takeSendByReq keyed by cookie (how an ack is correlated).
func (c *Client) takeSendByCookie(cookie uint64) (*pendingSend, bool) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	p, ok := c.sendsByCookie[cookie]
	if !ok {
		return nil, false
	}
	c.dropSendLocked(p)
	return p, true
}

func (c *Client) dropSendLocked(p *pendingSend) {
	delete(c.sendsByReq, p.reqID)
	delete(c.sendsByCookie, p.cookie)
	if p.timer != nil {
		p.timer.Stop()
	}
}

// sealOutbound decides what actually goes on the wire for a 1:1 message, and
// mirrors sealRoomMessage so both paths answer the same question the same way.
//
// Two situations look similar and only one of them is normal:
//
//   - We hold NO keys for this peer. They are not a BENCchat user, or E2EE is
//     off. Plaintext is the correct answer and the UI shows no lock.
//   - We hold keys and cannot USE them. That is a bug, and falling back to
//     plaintext would transmit in the clear to someone the UI is at that moment
//     showing a lock for. Nothing is sent.
//
// The second case is not reachable today — sealFor guarantees a non-empty
// recipient set, which is the only error SealFor returns short of the system
// random source failing. It is here because "encrypt, or quietly don't" is the
// wrong shape for this decision regardless of whether the branch currently
// fires, and because anything fallible added to this path later (post-quantum
// encapsulation, say) lands exactly here.
func (c *Client) sealOutbound(to, text string) (wireText string, encrypted bool, err error) {
	peerKeys, ourPriv, ok := c.sealFor(to)
	if ok && c.peerKeysStale(to) {
		// Re-read a set we have been using for a while. Nothing else expires it,
		// and the case it exists for — the peer removed a device — is invisible
		// from here: a removed device decrypts everything we send to it, so no
		// failure ever prompts a re-fetch.
		//
		// Asynchronous on purpose. This bounds how long a removed device keeps
		// receiving; it is not a correctness gate on THIS message, so it must not
		// put a directory round trip in front of the user pressing send.
		go c.RefreshPeerKeys(to)
	}
	if !ok && c.e2eeReady() {
		// We hold no keys for this peer YET. That is the normal state for the
		// first message to someone: nothing has fetched their manifest, because
		// key learning used to ride on the profile the old scheme fetched on
		// conversation open, and that trigger went away with the profile. Without
		// this, the first message -- and every message, since the peer is in the
		// same position and never sends us an encrypted one to learn from --
		// goes in the clear forever. So look once: query and verify their
		// manifest, then decide. RefreshPeerKeys is a no-op once keys are cached,
		// so only the first send to a peer pays the round trip.
		if c.RefreshPeerKeys(to) == peerKeysUnavailable {
			// The directory gave no answer. "I could not find out" is not "they
			// have no keys", and sending plaintext on it is exactly how a server
			// that declines key lookups gets to read a conversation — the only
			// hint to the user would be a lock that never appeared. Refuse; the
			// message is kept and a retry encrypts once the directory answers.
			c.log.Warn("refusing to send in the clear: key directory gave no answer", "to", to)
			return "", false, errors.New(
				"client: couldn't check whether this conversation can be encrypted, " +
					"so nothing was sent — try again in a moment")
		}
		peerKeys, ourPriv, ok = c.sealFor(to)
	}
	if !ok {
		// Genuinely no keys: not a BENCchat user, or E2EE is off. Plaintext, no lock.
		return text, false, nil
	}
	env, serr := e2ee.SealFor(text, peerKeys, ourPriv)
	if serr != nil {
		c.log.Error("e2ee seal failed; refusing to send in the clear", "to", to, "err", serr)
		return "", false, errors.New(
			"client: this conversation is encrypted but the message could not be " +
				"encrypted — nothing was sent")
	}
	return env, true, nil
}

// AddBuddy adds screenName to group (or the default group if empty) and
// republishes the updated list.
func (c *Client) AddBuddy(screenName, group string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.AddBuddy(screenName, group)
	})
}

// markAccepted records that screenName's connection was approved this session.
func (c *Client) markAccepted(screenName string) {
	key := state.NormalizeScreenName(screenName)
	c.acceptedMu.Lock()
	if c.accepted == nil {
		c.accepted = map[string]bool{}
	}
	c.accepted[key] = true
	c.acceptedMu.Unlock()
}

// wasAccepted reports whether screenName's connection was approved this session.
func (c *Client) wasAccepted(screenName string) bool {
	c.acceptedMu.Lock()
	defer c.acceptedMu.Unlock()
	return c.accepted[state.NormalizeScreenName(screenName)]
}

// forgetAccepted clears the accepted mark, so a fresh add after a removal goes
// through the pending flow again rather than being treated as still connected.
func (c *Client) forgetAccepted(screenName string) {
	c.acceptedMu.Lock()
	delete(c.accepted, state.NormalizeScreenName(screenName))
	c.acceptedMu.Unlock()
}

// RemoveBuddy removes screenName from the list. If the buddy is already gone —
// the other party removed us, so our mirror no longer has them but the store may
// still show them — it reconciles the store to the mirror and reports success:
// the end state the caller wants is already true, and surfacing "not on your
// buddy list" as a failure would just strand a dead row on screen.
func (c *Client) RemoveBuddy(screenName string) error {
	c.forgetAccepted(screenName)
	err := c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.RemoveBuddy(screenName)
	})
	if errors.Is(err, oscar.ErrNotABuddy) {
		c.mu.Lock()
		session := c.session
		c.mu.Unlock()
		if session != nil {
			c.publishBuddyList(session.BuddyList())
		}
		return nil
	}
	return err
}

// RenameBuddy sets (or clears, with an empty alias) a buddy's local nickname.
func (c *Client) RenameBuddy(screenName, alias string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.RenameBuddy(screenName, alias)
	})
}

// MoveBuddy moves a buddy to a different group without severing the connection.
func (c *Client) MoveBuddy(screenName, group string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.MoveBuddy(screenName, group)
	})
}

// GroupInfo is a buddy group and how many buddies are filed under it.
type GroupInfo struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Groups lists the buddy groups with member counts, in feedbag order.
func (c *Client) Groups() []GroupInfo {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return nil
	}
	bl := session.BuddyList()
	counts := map[string]int{}
	for _, b := range bl.Buddies {
		counts[b.Group]++
	}
	out := make([]GroupInfo, 0, len(bl.Groups))
	for _, g := range bl.Groups {
		out = append(out, GroupInfo{Name: g, Count: counts[g]})
	}
	return out
}

// RenameGroup renames a buddy group. Members follow automatically.
func (c *Client) RenameGroup(oldName, newName string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.RenameGroup(oldName, newName)
	})
}

// DeleteGroup removes a group. Any members are moved to the default group (which
// auto-prunes the now-empty group); an already-empty group is deleted directly.
func (c *Client) DeleteGroup(name string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	var members []string
	for _, b := range session.BuddyList().Buddies {
		if strings.EqualFold(b.Group, name) {
			members = append(members, b.ScreenName)
		}
	}
	if len(members) == 0 {
		return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
			return s.DeleteGroup(name)
		})
	}
	for _, sn := range members {
		if err := c.MoveBuddy(sn, oscar.DefaultGroupName); err != nil {
			return err
		}
	}
	return nil
}

// BlockedUsers returns the screen names on the deny list, which may include
// people who aren't buddies. Empty when signed off.
func (c *Client) BlockedUsers() []string {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return nil
	}
	return session.BuddyList().Blocked
}

// BlockBuddy blocks a user.
func (c *Client) BlockBuddy(screenName string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.BlockBuddy(screenName)
	})
}

// UnblockBuddy unblocks a user.
func (c *Client) UnblockBuddy(screenName string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.UnblockBuddy(screenName)
	})
}

// SetProfile sets our profile text.
func (c *Client) SetProfile(text string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.SetProfile(text)
}

// FindUser searches for the account registered to an email address. The result
// arrives as an EventSearchResult.
func (c *Client) FindUser(email string) error {
	c.mu.Lock()
	session := c.session
	c.lastSearch = email
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.FindByEmail(email)
}

// WarnUser sends a warning to a buddy. The result (or rejection) arrives as a
// notice on the read loop.
func (c *Client) WarnUser(screenName string, anonymous bool) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.WarnUser(screenName, anonymous)
}

// RequestUserInfo fetches a buddy's profile and away message. Results land on
// the buddy in the store asynchronously.
func (c *Client) RequestUserInfo(screenName string) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return
	}
	if err := session.RequestUserInfo(screenName); err != nil {
		c.log.Debug("user-info request failed", "err", err)
	}
}

// SetAway sets or clears our away message. An empty message means "back".
func (c *Client) SetAway(message string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	if err := session.SetAway(message); err != nil {
		return err
	}
	c.store.SetAway(message)
	return nil
}

// editList runs a buddy-list mutation and republishes the result to the store.
func (c *Client) editList(edit func(*oscar.Session) (oscar.BuddyList, error)) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("client: not signed on")
	}
	list, err := edit(session)
	if err != nil {
		return err
	}
	c.publishBuddyList(list)
	return nil
}

// SendTyping reports our typing state to the other party. Failures are not
// worth surfacing to the user — a lost typing notification is invisible.
func (c *Client) SendTyping(to string, typing bool) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return
	}
	event := wire.ICBMEventTyped
	if typing {
		event = wire.ICBMEventTyping
	}
	if err := session.SendTyping(to, event); err != nil {
		c.log.Debug("typing notification failed", "err", err)
	}
}

// publishBuddyList maps a protocol-level buddy list into the store.
func (c *Client) publishBuddyList(list oscar.BuddyList) {
	buddies := make([]state.Buddy, 0, len(list.Buddies))
	for _, b := range list.Buddies {
		buddies = append(buddies, state.Buddy{
			ScreenName: b.ScreenName,
			Group:      b.Group,
			Alias:      b.Alias,
			Blocked:    b.Blocked,
			Pending:    b.Pending,
		})
	}
	c.store.ReplaceBuddyList(buddies, list.Groups)
}

// handleSNAC dispatches one inbound SNAC. It runs on the session read loop, so
// it must not block.
func (c *Client) handleSNAC(frame wire.SNACFrame, body []byte) {
	switch frame.FoodGroup {
	case wire.OService:
		c.handleOService(frame, body)
	case wire.Buddy:
		c.handleBuddy(frame, body)
	case wire.ICBM:
		c.handleICBM(frame, body)
	case wire.Feedbag:
		c.handleFeedbag(frame, body)
	case wire.Locate:
		c.handleLocate(frame, body)
	case wire.UserLookup:
		c.handleUserLookup(frame, body)
	case wire.ODir:
		c.handleODir(frame, body)
	case wire.Admin:
		c.handleAdmin(frame, body)
	case wire.BENCOKeyDir:
		c.handleKeyDir(frame, body)
	case wire.BART:
		c.handleBART(frame, body)
	}
	// Everything else — rate-limit changes, MOTD, stats intervals — is safely
	// ignorable. Unknown SNACs are normal traffic, not errors.
}

// handleLocate records a buddy's fetched profile and/or away text. Only the
// fields the reply actually carried are updated, so a profile-only query can't
// wipe a previously fetched away message and vice versa.
func (c *Client) handleLocate(frame wire.SNACFrame, body []byte) {
	if frame.SubGroup != wire.LocateUserInfoReply {
		return
	}
	reply, err := oscar.DecodeLocateReply(body)
	if err != nil {
		c.log.Warn("could not decode locate reply", "err", err)
		return
	}
	if reply.HasAway {
		c.store.SetBuddyAwayMessage(reply.ScreenName, reply.Away)
	}
	c.e2eeMu.Lock()
	probe := c.locateCapsProbe
	c.e2eeMu.Unlock()
	if probe != nil {
		probe(reply.ScreenName, reply.Capabilities)
	}
	if len(reply.Capabilities) > 0 {
		capable := oscar.HasCapability(reply.Capabilities, oscar.CapBENCchat) ||
			oscar.HasCapability(reply.Capabilities, oscar.CapSecureIM)
		c.store.SetBuddyCapabilities(reply.ScreenName, capable, true)
		c.notePeerCapability(reply.ScreenName, capable)
	}
	if reply.HasProfile {
		// Profiles no longer carry keys — the key directory is the only source.
		// Markers are still stripped for display, because an account that has
		// not republished since the change still has one sitting in its bio.
		c.store.SetBuddyProfile(reply.ScreenName, e2ee.StripMarkerAll(reply.Profile))
	}
	c.e2eeMu.Lock()
	pp := c.profileProbe
	c.e2eeMu.Unlock()
	if pp != nil {
		pp(reply.ScreenName, e2ee.StripMarkerAll(reply.Profile), reply.Away, reply.HasProfile)
	}
}

// LookupProfile does a one-shot profile+away fetch for a screen name that need
// not be a buddy — used to preview a connection requester before accepting. It
// returns whatever the first locate reply carries, or empty strings if none
// arrives before the deadline (a profile that was never set looks the same).
func (c *Client) LookupProfile(ctx context.Context, screenName string) (profile, away string, err error) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return "", "", errors.New("client: not signed on")
	}
	want := state.NormalizeScreenName(screenName)

	type result struct{ profile, away string }
	ch := make(chan result, 1)
	c.e2eeMu.Lock()
	c.profileProbe = func(sn, prof, aw string, _ bool) {
		if state.NormalizeScreenName(sn) != want {
			return
		}
		select {
		case ch <- result{prof, aw}:
		default:
		}
	}
	c.e2eeMu.Unlock()
	defer func() {
		c.e2eeMu.Lock()
		c.profileProbe = nil
		c.e2eeMu.Unlock()
	}()

	c.RequestUserInfo(screenName)

	select {
	case r := <-ch:
		return r.profile, r.away, nil
	case <-time.After(6 * time.Second):
		return "", "", nil
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

// isSelf reports whether a screen name is the signed-on account.
func (c *Client) isSelf(screenName string) bool {
	self := c.store.Self().ScreenName
	return self != "" && state.NormalizeScreenName(self) == state.NormalizeScreenName(screenName)
}

// handleFeedbag routes inbound feedbag traffic: edit acknowledgements and the
// consensual-connection SNACs (someone wants to connect / an answer to a
// request we made).
func (c *Client) handleFeedbag(frame wire.SNACFrame, body []byte) {
	switch frame.SubGroup {
	case wire.FeedbagStatus:
		c.handleFeedbagStatus(frame, body)
	case wire.FeedbagRequestAuthorizeToClient:
		c.handleConnectionRequest(body)
	case wire.FeedbagRespondAuthorizeToClient:
		c.handleConnectionResponse(body)
	case wire.FeedbagPreAuthorizedBuddy:
		c.handlePreAuthorized(body)
	case wire.FeedbagInsertItem, wire.FeedbagUpdateItem, wire.FeedbagDeleteItem:
		// A change made on ANOTHER of our sessions, relayed by the server so this
		// device stays in sync — a block, add, remove, rename or move done on a
		// different open client. Only server-initiated pushes are applied; our own
		// edits come back as a FeedbagStatus, handled above.
		if frame.RequestID&wire.ReqIDFromServer != 0 {
			c.handleRelayedFeedbag(frame, body)
		}
	}
}

// handleRelayedFeedbag applies a feedbag insert/update/delete pushed from another
// of the account's sessions and republishes the buddy list so the UI reflects it
// live, without waiting for a reconnect.
func (c *Client) handleRelayedFeedbag(frame wire.SNACFrame, body []byte) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}

	var items []wire.FeedbagItem
	switch frame.SubGroup {
	case wire.FeedbagInsertItem:
		var snac wire.SNAC_0x13_0x08_FeedbagInsertItem
		if err := wire.UnmarshalBE(&snac, bytes.NewReader(body)); err != nil {
			c.log.Warn("could not decode relayed feedbag insert", "err", err)
			return
		}
		items = snac.Items
	case wire.FeedbagUpdateItem:
		var snac wire.SNAC_0x13_0x09_FeedbagUpdateItem
		if err := wire.UnmarshalBE(&snac, bytes.NewReader(body)); err != nil {
			c.log.Warn("could not decode relayed feedbag update", "err", err)
			return
		}
		items = snac.Items
	case wire.FeedbagDeleteItem:
		var snac wire.SNAC_0x13_0x0A_FeedbagDeleteItem
		if err := wire.UnmarshalBE(&snac, bytes.NewReader(body)); err != nil {
			c.log.Warn("could not decode relayed feedbag delete", "err", err)
			return
		}
		c.publishBuddyList(session.ApplyServerDelete(snac.Items))
		return
	}
	c.publishBuddyList(session.ApplyServerUpsert(items))
}

// handleFeedbagStatus observes the server's acknowledgement of a buddy-list
// edit. The edit is applied optimistically at send time, so this is
// confirmation rather than the source of truth — except for the auth-required
// case, which the client must act on.
func (c *Client) handleFeedbagStatus(frame wire.SNACFrame, body []byte) {
	var status wire.SNAC_0x13_0x0E_FeedbagStatus
	if err := wire.UnmarshalBE(&status, bytes.NewReader(body)); err != nil {
		return
	}
	authRequired := false
	for _, code := range status.Results {
		switch code {
		case wire.FeedbagStatusSuccess:
		case wire.FeedbagStatusAuthRequired:
			authRequired = true
		default:
			c.log.Warn("buddy-list edit rejected", "code", code)
		}
	}

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return
	}
	// Was this the reply to a buddy add we tracked? If not, nothing more to do.
	target, ok := session.TakeAuthTarget(frame.RequestID)
	if !ok || !authRequired {
		return
	}

	// The server refused to store the buddy until the target authorizes. Re-add
	// it WITH the pending tag so a pending row is kept and the buddy shows as
	// "awaiting acceptance". Done off the read loop: the re-add SNAC can block on
	// rate pacing, which must never stall the read loop.
	go func() {
		// If the target already accepted (a fast approval that raced ahead of this
		// AuthRequired), don't re-mark them pending — just make sure they're clear.
		if c.wasAccepted(target) {
			c.pendingMu.Lock()
			c.publishBuddyList(session.ClearBuddyPending(target))
			c.pendingMu.Unlock()
			return
		}
		list, err := session.ReAddBuddyPending(target)
		if err != nil {
			c.log.Warn("pending re-add failed", "buddy", target, "err", err)
			return
		}
		// Decide-and-publish under the lock, reading the CURRENT mirror: if an
		// acceptance landed while we were re-adding, publish the cleared list, not
		// the stale pending snapshot we just took.
		c.pendingMu.Lock()
		if c.wasAccepted(target) {
			list = session.ClearBuddyPending(target)
		}
		c.publishBuddyList(list)
		c.pendingMu.Unlock()
		c.log.Info("buddy add awaiting authorization", "buddy", target)
	}()
}

func (c *Client) handleBuddy(frame wire.SNACFrame, body []byte) {
	switch frame.SubGroup {
	case wire.BuddyArrived:
		info, err := oscar.DecodeUserInfo(body)
		if err != nil {
			c.log.Warn("could not decode buddy arrival", "err", err)
			return
		}
		presence, idleSince := presenceOf(info)
		c.store.UpdatePresence(info.ScreenName, presence, "", idleSince, info.SignedOn)
		c.noteCapabilities(info)
		c.updateBuddyIcon(info)

	case wire.BuddyDeparted:
		info, err := oscar.DecodeUserInfo(body)
		if err != nil {
			c.log.Warn("could not decode buddy departure", "err", err)
			return
		}
		c.store.UpdatePresence(info.ScreenName, state.PresenceOffline, "", time.Time{}, time.Time{})
	}
}

// noteCapabilities records what a buddy's client says it can do, so the UI can
// tell "this person's client can't encrypt" apart from "we haven't heard".
//
// A client that advertises capabilities but neither the standard SECURE_IM one
// nor BENCchat's own is one we can state won't encrypt. Silence stays unknown:
// plenty of clients advertise nothing at all.
func (c *Client) noteCapabilities(info oscar.UserInfo) {
	known := len(info.Capabilities) > 0
	capable := oscar.HasCapability(info.Capabilities, oscar.CapBENCchat) ||
		oscar.HasCapability(info.Capabilities, oscar.CapSecureIM)
	c.store.SetBuddyCapabilities(info.ScreenName, capable, known)
	if known {
		c.notePeerCapability(info.ScreenName, capable)
	}
}

// updateBuddyIcon reconciles a buddy's advertised icon with what we have. It
// records the hash (or clears it), and when the hash is new and its bytes aren't
// cached yet, kicks off an async BART download. Runs on the read-loop goroutine,
// so the actual request is dispatched to a goroutine — Session.Send can block on
// rate pacing, which must never stall the read loop.
func (c *Client) updateBuddyIcon(info oscar.UserInfo) {
	if len(info.IconHash) != 16 {
		c.store.SetBuddyIcon(info.ScreenName, "", nil) // no icon / cleared
		return
	}
	hashHex := hex.EncodeToString(info.IconHash)
	c.store.SetBuddyIcon(info.ScreenName, hashHex, nil) // record hash; bytes may follow
	if c.store.HaveIcon(hashHex) {
		return // already downloaded this exact icon
	}
	sn, typ, flags, hash := info.ScreenName, info.IconType, info.IconFlags, info.IconHash
	go func() {
		c.mu.Lock()
		session := c.session
		c.mu.Unlock()
		if session == nil {
			return
		}
		if err := session.RequestBuddyIcon(sn, typ, flags, hash); err != nil {
			c.log.Warn("buddy icon request failed", "buddy", sn, "err", err)
		}
	}()
}

// handleBART records the image bytes from a buddy-icon download. A not-found or
// cleared item comes back with empty data and is ignored.
func (c *Client) handleBART(frame wire.SNACFrame, body []byte) {
	if frame.SubGroup != wire.BARTDownloadReply {
		return // BARTErr and anything else: nothing to store
	}
	icon, err := oscar.DecodeBARTDownloadReply(body)
	if err != nil {
		c.log.Warn("could not decode BART reply", "err", err)
		return
	}
	if len(icon.Data) == 0 || len(icon.Hash) != 16 {
		return
	}
	c.store.SetBuddyIcon(icon.ScreenName, hex.EncodeToString(icon.Hash), icon.Data)
}

// systemSenders are screen names reserved for the server's own notifications
// rather than for people. "AOL System Msg" is what real AIM used;
// open-oscar-server sends "OOS System Msg". Both are recognised so a
// differently-branded server still routes to the notice log.
//
// The names are normalized, so spacing and casing don't matter.
var systemSenders = map[string]bool{
	"aolsystemmsg": true,
	"oossystemmsg": true,
}

// isSystemSender reports whether a message came from the server itself.
func isSystemSender(from string) bool {
	return systemSenders[state.NormalizeScreenName(from)]
}

func (c *Client) handleICBM(frame wire.SNACFrame, body []byte) {
	switch frame.SubGroup {
	case wire.ICBMChannelMsgToClient:
		msg, ok, err := oscar.DecodeIncomingMessage(body)
		if err != nil {
			c.log.Warn("could not decode inbound message", "err", err)
			return
		}
		if !ok {
			return // not a plain IM (e.g. a rendezvous request)
		}
		// Offline messages carry their original send time; live ones don't.
		at := msg.SentAt
		if at.IsZero() {
			at = time.Now()
		}
		// The server sends its own notices (offline-message counts,
		// multi-instance sign-on) as ordinary IMs from a reserved screen name.
		// They belong in the notice log: filed as a conversation they look like
		// a buddy you could reply to, and nothing is listening on the far end.
		if isSystemSender(msg.From) {
			c.store.NotifyFrom(state.NoticeInfo, msg.From, msg.Text)
			return
		}
		// Decrypt if it's an E2EE envelope; otherwise it's plaintext as-is.
		text, encrypted, cipher, sentAt := c.decodeIncomingStamped(msg.From, msg.Text)
		if text == "" && cipher == "" && !encrypted {
			return // a duplicate the server handed us twice; already logged
		}
		// A room invite is machine-to-machine: it carries a group key, not
		// something a person typed, so it must never land in a conversation.
		if encrypted && e2ee.IsRoomInvite(text) {
			c.handleRoomInvite(msg.From, text)
			return
		}
		// A membership statement, not something a person said.
		if encrypted && e2ee.IsRoster(text) {
			c.handleRoster(msg.From, text)
			return
		}
		// Catch-up traffic is likewise machine-to-machine.
		if encrypted && e2ee.IsCatchup(text) {
			c.handleCatchup(msg.From, text)
			return
		}
		// Prefer the sender's own sealed claim about when they sent it. Stamping
		// the arrival instead is what let a replayed message read as something
		// said just now: the server chooses when to deliver, so a timestamp it
		// controls tells you nothing. Falls back to arrival when the sender said
		// nothing (plaintext, or an older client) or claimed a time far enough
		// ahead of ours to sort wrongly forever.
		if e2ee.PlausibleSendTime(sentAt, at) {
			at = sentAt
		}
		c.store.AddMessage(state.Message{
			From:         msg.From,
			To:           c.store.Self().ScreenName,
			Text:         text,
			At:           at,
			AutoResponse: msg.AutoResponse,
			Encrypted:    encrypted,
			Cipher:       cipher,
		})

	case wire.ICBMClientEvent:
		ev, err := oscar.DecodeTypingEvent(body)
		if err != nil {
			c.log.Warn("could not decode typing event", "err", err)
			return
		}
		c.store.NotifyTyping(ev.From, ev.Event == wire.ICBMEventTyping)

	case wire.ICBMEvilReply:
		res, err := oscar.DecodeWarnResult(body)
		if err != nil {
			return
		}
		c.store.Notify(state.NoticeInfo, fmt.Sprintf("Warning sent — their level is now %s.", pct(res.NewLevel)))

	case wire.ICBMHostAck:
		// The server accepted a message we sent. Clearing the pending entry stops
		// its timer, so it won't later be marked "not sent".
		var ack wire.SNAC_0x04_0x0C_ICBMHostAck
		if err := wire.UnmarshalBE(&ack, bytes.NewReader(body)); err != nil {
			return
		}
		c.takeSendByCookie(ack.Cookie)

	case wire.ICBMErr:
		// The body is a bare error code, and it doesn't name the message it refers
		// to — but the request ID does, so the rejected message can be flagged.
		if p, ok := c.takeSendByReq(frame.RequestID); ok {
			c.store.SetMessageNotSent(p.to, p.cookie, true)
		}
		// ErrorCodeNotLoggedOn is heavily overloaded server-side: the consensual-
		// connection gate, a block, and "offline and won't take offline messages"
		// all return it. So describe the possibilities rather than asserting one.
		msg := "The server rejected that action."
		if len(body) >= 2 {
			switch binary.BigEndian.Uint16(body[:2]) {
			case wire.ErrorCodeRateToHost:
				msg = "You're sending too fast — that message wasn't delivered. " +
					"Wait a moment, then resend it."
			case wire.ErrorCodeNotLoggedOn, wire.ErrorCodeInLocalPermitDeny:
				msg = "Couldn't send that message — you may not be connected to this person, " +
					"they may have blocked you, or they're offline and not accepting messages."
			}
		}
		c.store.Notify(state.NoticeError, msg)
	}
}

// handleUserLookup handles a user-search reply or "no match" error.
func (c *Client) handleUserLookup(frame wire.SNACFrame, body []byte) {
	c.mu.Lock()
	query := c.lastSearch
	c.mu.Unlock()

	switch frame.SubGroup {
	case wire.UserLookupFindReply:
		name, err := oscar.DecodeFindReply(body)
		if err != nil || name == "" {
			c.store.SearchResult(query, "", false)
			return
		}
		c.store.SearchResult(query, name, true)
	case wire.UserLookupErr:
		// No match (the server replies with a bare error code here).
		c.store.SearchResult(query, "", false)
	}
}

// handleODir surfaces a directory (name) search's results to the UI.
func (c *Client) handleODir(frame wire.SNACFrame, body []byte) {
	if frame.SubGroup != wire.ODirInfoReply {
		return
	}
	results, ok, err := oscar.DecodeDirReply(body)
	if err != nil {
		c.log.Warn("could not decode directory reply", "err", err)
		c.store.DirectoryResult(nil, false)
		return
	}
	entries := make([]state.DirEntry, 0, len(results))
	for _, r := range results {
		entries = append(entries, state.DirEntry{
			ScreenName: r.ScreenName,
			FirstName:  r.FirstName,
			LastName:   r.LastName,
			City:       r.City,
			State:      r.State,
			Country:    r.Country,
		})
	}
	c.store.DirectoryResult(entries, ok)
}

// SearchDirectory searches the user directory by name. At least one of first or
// last name must be non-empty; results arrive via an EventDirectoryResult.
func (c *Client) SearchDirectory(firstName, lastName string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	if firstName == "" && lastName == "" {
		return errors.New("client: enter a first or last name to search")
	}
	return session.SearchDirectoryByName(firstName, lastName)
}

// handleAdmin surfaces the result of an account change (password/email) as a
// notice.
func (c *Client) handleAdmin(frame wire.SNACFrame, body []byte) {
	if frame.SubGroup != wire.AdminInfoChangeReply {
		return
	}
	res, err := oscar.DecodeAdminChangeReply(body)
	if err != nil {
		return
	}
	if res.OK {
		c.store.Notify(state.NoticeInfo, "Account updated.")
	} else {
		c.store.Notify(state.NoticeError, res.Message)
	}
}

// ChangePassword changes the account password.
func (c *Client) ChangePassword(oldPassword, newPassword string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.ChangePassword(oldPassword, newPassword)
}

// ChangeEmail changes the account email address.
func (c *Client) ChangeEmail(email string) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return errors.New("client: not signed on")
	}
	return session.ChangeEmail(email)
}

// handleOService handles a warning delivered to us.
func (c *Client) handleOService(frame wire.SNACFrame, body []byte) {
	// A service grant (for a ChatNav/Chat connection) is routed to the waiting
	// JoinRoom flow rather than handled here.
	if frame.SubGroup == wire.OServiceServiceResponse {
		trySend(c.serviceReply, body)
		return
	}
	if frame.SubGroup != wire.OServiceEvilNotification {
		return
	}
	n, err := oscar.DecodeWarnedNotification(body)
	if err != nil {
		return
	}
	c.store.SetSelfWarning(n.NewLevel)
	who := "anonymous"
	if n.From != "" {
		who = n.From
	}
	c.store.Notify(state.NoticeWarn, fmt.Sprintf("You were warned by %s. Your level is now %s.", who, pct(n.NewLevel)))
}

// pct renders a warning level (tenths of a percent) as a percentage string.
func pct(level uint16) string {
	return fmt.Sprintf("%d%%", level/10)
}

// presenceOf maps protocol user info onto the state model's single presence
// value.
//
// A buddy can be both away and idle at once; away wins, because it is the
// deliberate signal and idle is merely inferred from inactivity.
func presenceOf(info oscar.UserInfo) (state.Presence, time.Time) {
	var idleSince time.Time
	if info.IdleMinutes > 0 {
		idleSince = time.Now().Add(-time.Duration(info.IdleMinutes) * time.Minute)
	}

	switch {
	case info.Away:
		return state.PresenceAway, idleSince
	case info.IdleMinutes > 0:
		return state.PresenceIdle, idleSince
	default:
		return state.PresenceOnline, time.Time{}
	}
}
