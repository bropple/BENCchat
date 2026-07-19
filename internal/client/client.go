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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	// from their profiles. Guarded by e2eeMu.
	e2eeMu    sync.Mutex
	e2eeOn    bool
	e2eeHasKP bool
	e2eeKP    e2ee.KeyPair
	// e2eeKeys maps a peer to the SET of device keys they publish — one account
	// can be signed in from several machines, each with its own key.
	e2eeKeys map[string][][32]byte
	// onPeerKey is notified when a peer's device set is learned, so the app layer
	// can compare it against the persisted record and warn on a change.
	onPeerKey func(screenName string, keys, prev [][32]byte)
	// locateCapsProbe is a test hook; see setLocateCapsProbe.
	locateCapsProbe func(screenName string, caps []oscar.Capability)
	// ownKeyWait receives a self-directed locate reply for FetchOwnPublishedKeys.
	ownKeyWait chan ownKeyReply
	// onDeviceMessage handles device-linking traffic from our own other sessions.
	onDeviceMessage func(kind string, keys [][32]byte)
	// keyDirWait correlates device key directory replies to their requests.
	// Keyed by request ID because several queries can be outstanding at once —
	// one per peer whose keys we want. See keydir.go.
	keyDirWait map[uint32]chan keyDirReply

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

	// Encrypt when E2EE is on and we hold the peer's key; otherwise send
	// plaintext so non-BENCchat peers still work. We store the plaintext locally
	// (so we see what we typed) and mark it encrypted for the lock indicator.
	wireText, encrypted := text, false
	if peerKeys, ourPriv, ok := c.sealFor(to); ok {
		if env, err := e2ee.SealFor(text, peerKeys, ourPriv); err == nil {
			wireText, encrypted = env, true
		} else {
			c.log.Warn("e2ee seal failed; sending plaintext", "err", err)
		}
	}

	if _, err := session.SendMessage(to, wireText, false); err != nil {
		return err
	}
	c.store.AddMessage(state.Message{
		From:      c.store.Self().ScreenName,
		To:        to,
		Text:      text,
		At:        time.Now(),
		Outgoing:  true,
		Encrypted: encrypted,
	})
	return nil
}

// AddBuddy adds screenName to group (or the default group if empty) and
// republishes the updated list.
func (c *Client) AddBuddy(screenName, group string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.AddBuddy(screenName, group)
	})
}

// RemoveBuddy removes screenName from the list.
func (c *Client) RemoveBuddy(screenName string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.RemoveBuddy(screenName)
	})
}

// RenameBuddy sets (or clears, with an empty alias) a buddy's local nickname.
func (c *Client) RenameBuddy(screenName, alias string) error {
	return c.editList(func(s *oscar.Session) (oscar.BuddyList, error) {
		return s.RenameBuddy(screenName, alias)
	})
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

// RequestAwayMessage fetches a buddy's away message. The result arrives
// asynchronously and lands on the buddy in the store. Failures are logged, not
// returned — a missing away message is not worth interrupting the UI over.
func (c *Client) RequestAwayMessage(screenName string) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return
	}
	if err := session.RequestAwayMessage(screenName); err != nil {
		c.log.Debug("away-message request failed", "err", err)
	}
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
		devices, hasPub := e2ee.ExtractDevices(reply.Profile)
		pubs := e2ee.BoxKeysOf(devices)
		// A reply about ourselves is not a peer: routing it through learnPeerKey
		// would file a trust entry against our own account and warn us that our
		// own key had changed. It goes to whoever is checking what this account
		// currently has published — see FetchOwnPublishedKey.
		if c.isSelf(reply.ScreenName) {
			c.deliverOwnKey(pubs, hasPub)
			return
		}
		// A peer's profile may carry their E2EE public key in a hidden marker;
		// learn it and strip it so it isn't shown as profile text.
		if hasPub {
			c.learnPeerKeys(reply.ScreenName, pubs)
			c.learnPeerSigningKeys(reply.ScreenName, e2ee.SigningKeysOf(devices))
		}
		c.store.SetBuddyProfile(reply.ScreenName, e2ee.StripMarkerAll(reply.Profile))
	}
}

// isSelf reports whether a screen name is the signed-on account.
func (c *Client) isSelf(screenName string) bool {
	self := c.store.Self().ScreenName
	return self != "" && state.NormalizeScreenName(self) == state.NormalizeScreenName(screenName)
}

// handleFeedbag observes the server's acknowledgement of a buddy-list edit. The
// edit is applied optimistically at send time, so this is confirmation rather
// than the source of truth — but a non-success code is worth logging.
func (c *Client) handleFeedbag(frame wire.SNACFrame, body []byte) {
	if frame.SubGroup != wire.FeedbagStatus {
		return
	}
	var status wire.SNAC_0x13_0x0E_FeedbagStatus
	if err := wire.UnmarshalBE(&status, bytes.NewReader(body)); err != nil {
		return
	}
	for _, code := range status.Results {
		switch code {
		case wire.FeedbagStatusSuccess:
		case wire.FeedbagStatusAuthRequired:
			// The buddy exists but requires authorization before presence flows.
			c.log.Info("buddy added; awaiting authorization")
		default:
			c.log.Warn("buddy-list edit rejected", "code", code)
		}
	}
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
		// Device-linking traffic is machine-to-machine chatter between this
		// account's own sessions. It must be intercepted before anything stores
		// it, or the user sees protocol noise in a conversation with themselves.
		if c.isSelf(msg.From) && e2ee.IsDeviceMessage(msg.Text) {
			c.handleDeviceMessage(msg.Text)
			return
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
		text, encrypted, cipher := c.decodeIncoming(msg.From, msg.Text)
		// A room invite is machine-to-machine: it carries a group key, not
		// something a person typed, so it must never land in a conversation.
		if encrypted && e2ee.IsRoomInvite(text) {
			c.handleRoomInvite(msg.From, text)
			return
		}
		// Catch-up traffic is likewise machine-to-machine.
		if encrypted && e2ee.IsCatchup(text) {
			c.handleCatchup(msg.From, text)
			return
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

	case wire.ICBMErr:
		// An ICBM error can be a rejected message or a rejected warning; the SNAC
		// doesn't say which. Surface it as a notice rather than guessing.
		c.store.Notify(state.NoticeError, "The server rejected that action (you can only warn someone who has messaged you recently).")
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
