package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/config"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/history"
	"github.com/benco-holdings/benchat/internal/oscar"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/tray"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the bridge between the Go protocol/state layers and the web frontend.
// Methods on App are bound into JS by Wails; the frontend calls them and
// listens for events App emits back. Per CLAUDE.md's layering, the UI never
// touches FLAP/SNAC — it only speaks to this bridge, which in turn speaks only
// to the client and state layers.
type App struct {
	ctx    context.Context
	cfg    config.Config
	store  *state.Store
	client *client.Client
	// keyDir is the key directory as the identity flows see it. Always the
	// client above outside tests; see keyDirectory for why it is an interface.
	keyDir keyDirectory

	// Local history orchestration. histAccount is the signed-on screen name whose
	// history we're persisting ("" when signed off); histTimer debounces saves so
	// a burst of messages writes the file once. Guarded by histMu.
	histMu      sync.Mutex
	histAccount string
	histTimer   *time.Timer
	// histKey seals the account's history file at rest. A nil key means history
	// persistence is OFF for this session — the key could not be read, or the
	// file could not be decrypted with it. Saving anyway is not an option: the
	// only ways to do it are to write plaintext (which defeats the point) or to
	// seal with a fresh key (which orphans the history already on disk).
	histKey *[32]byte
	// histNoticeShown keeps the explanation for that to one per sign-on. Saves
	// are debounced every couple of seconds, so a keyring that is down would
	// otherwise become an unending stream of identical notices.
	histNoticeShown bool

	// End-to-end encryption: our current public key (for publishing in the
	// profile) and whether a keypair is loaded. The private key never lives here
	// — it's in the OS secret store and the client.
	e2eePub    [32]byte
	e2eeHasKey bool
	// e2eeDevices is this account's full published device set (ours plus any
	// other machine signed in to the same account). Guarded by trustMu.
	e2eeDevices [][32]byte
	// signPub is this device's public signing key for room messages.
	signPub    ed25519.PublicKey
	hasSignKey bool

	// trust holds the signed-on account's peer records — verified identities,
	// last-seen device sets and manifest counter high-water marks — loaded on
	// sign-on. Guarded by trustMu since UI calls read/write it off the main loop.
	//
	// trustMu also guards the key-directory session state below it. One lock
	// because the verifier touches all of it in a single pass, and because a
	// counter and the identity it belongs to must never be read apart.
	trustMu sync.Mutex
	trust   trust.Store
	// selfIdentity is this account's own identity pin (public key + counter
	// high-water mark), lazily loaded — selfIdentityLoaded distinguishes "not
	// read yet" from "read, and this account has none".
	selfIdentity       trust.Identity
	selfIdentityLoaded bool
	// manifestSeen memoizes the last manifest verified per account, so that
	// verifying the same bytes twice is not mistaken for a rollback.
	manifestSeen map[string]manifestMemo
	// manifestIssuedAt is when our own current manifest was signed. Advisory:
	// nothing rejects a manifest on it (proposal §4).
	manifestIssuedAt uint64
	// linked is whether this device appears in the account's current signed
	// manifest. Losing it, having had it, is a removal (proposal §6).
	linked bool
	// identityFlow is which first-run flow the UI should be showing; see
	// IdentityState.
	identityFlow string

	// pending is a first run that has been generated but deliberately NOT
	// persisted: the identity keypair and recovery key exist here, in memory
	// only, between being shown to the user and being acknowledged. Proposal
	// §12's ordering depends on this never reaching disk or the server before
	// the acknowledgement. Guarded by identityMu, which is never held across a
	// network call.
	identityMu sync.Mutex
	pending    *pendingIdentity
	// rotation is a recovery-key re-key in flight (proposal §10), held under the
	// same lock and for the same reason: the NEW key has been shown but the
	// re-sealed backup has deliberately NOT been uploaded, because uploading it
	// first would strand an account whose owner never finished saving the key.
	rotation *pendingRotation

	// System tray. Icons are injected from main (embedded assets). quitting
	// distinguishes a real quit (tray "Quit") from a window close, which hides to
	// the tray instead of exiting.
	trayIcons tray.Icons
	tray      *tray.Tray
	quitting  atomic.Bool

	// members tracks who has been deliberately given each encrypted room's key,
	// and pendingInvites holds room keys offered to us but not yet accepted.
	members        roomMembers
	pendingMu      sync.Mutex
	pendingInvites map[string]e2ee.RoomInvite
	// pendingInviteFrom records who offered each invitation, so an accepted room
	// starts with that person as a known member to ask for history.
	pendingInviteFrom map[string]string

	// desktopIcon is the app icon (PNG) written into the icon theme on Linux so
	// the desktop entry — and thus the window/taskbar icon — resolves to it.
	desktopIcon []byte
}

// NewApp constructs the App, loading persisted config (falling back to the
// live deployment's defaults on first run).
func NewApp() *App {
	cfg, err := config.Load()
	if err != nil {
		// A bad config file shouldn't prevent startup; fall back to defaults
		// and surface the problem once the UI is up.
		cfg = config.Default()
	}

	store := state.NewStore()
	c := client.New(store, slog.Default())
	return &App{
		cfg:    cfg,
		store:  store,
		client: c,
		keyDir: c,
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Forward every state change to the frontend as a single event stream. The
	// UI re-reads what it needs through the bound getters rather than trying to
	// reconstruct state from a sequence of deltas.
	a.store.Subscribe(func(e state.Event) {
		runtime.EventsEmit(ctx, "state:event", e)
		// A new message (1:1 or room) means history changed; save it (debounced).
		if e.Kind == state.EventMessage || e.Kind == state.EventRoomMessage {
			a.scheduleHistorySave()
		}
	})

	a.client.OnDisconnect = func(err error) {
		// The store is already reset by the time this fires, so stop any pending
		// save and drop the account — a stray flush must not overwrite the file
		// with the now-empty store. (flushHistory also skips an empty set.)
		a.histMu.Lock()
		a.histAccount = ""
		// The key goes with the session it was loaded for. Keeping it around
		// would leave a stale key paired with whatever account signs on next.
		a.histKey = nil
		if a.histTimer != nil {
			a.histTimer.Stop()
			a.histTimer = nil
		}
		a.histMu.Unlock()
		a.emitStatus(disconnectStatus(err))
	}

	// On Linux, install a desktop entry + themed icon so KDE/GNOME resolve the
	// window and taskbar icon to the R. Triy mark (needed on Wayland especially).
	a.installDesktopEntry()

	// Bring up the tray icon now that we have a context to drive the window.
	a.startTray()
}

func (a *App) shutdown(ctx context.Context) {
	// Remove the tray icon so it doesn't linger after the process exits.
	a.stopTray()
	// Persist history before we tear down — SignOff resets the store, so this
	// must run first to capture the final scrollback.
	a.flushHistory()
	// Send the courtesy FLAP signoff and close the socket before the process
	// exits, rather than dropping the TCP connection on the floor.
	_ = a.client.SignOff()
}

// transport builds the connection settings for a sign-on from config. The
// choice is made once here and then carried by the session, so the BOS
// reconnect and chat connections can't silently drop to plaintext.
func (a *App) transport() oscar.Transport {
	return oscar.Transport{
		TLS:                a.cfg.TLSOn(),
		InsecureSkipVerify: a.cfg.TLSInsecure,
	}
}

// SessionStatus is a sign-on lifecycle update pushed to the UI.
type SessionStatus struct {
	// State is one of: "signing-on", "online", "offline", "error".
	State   string `json:"state"`
	Message string `json:"message"`
	Server  string `json:"server"`
}

func (a *App) emitStatus(s SessionStatus) {
	if a.ctx == nil {
		return
	}
	s.Server = a.cfg.Address()
	runtime.EventsEmit(a.ctx, "session:status", s)
}

// disconnectStatus renders why a session ended. A clean sign-off and a dropped
// socket look very different to a user, so they must not be reported the same.
func disconnectStatus(err error) SessionStatus {
	var signoff *oscar.SignoffError

	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, oscar.ErrClosed), errors.Is(err, context.Canceled):
		return SessionStatus{State: "offline", Message: "Signed off."}
	case errors.As(err, &signoff):
		return SessionStatus{State: "error", Message: signoff.Error()}
	default:
		return SessionStatus{State: "error", Message: "Connection lost: " + err.Error()}
	}
}

// --- Bound methods (callable from the frontend) ---

// ServerSettings is the subset of config the sign-on screen reads and writes.
type ServerSettings struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// TLS reports whether connections use TLS, and TLSInsecure whether
	// certificate verification is disabled (a testing-only escape hatch).
	TLS            bool   `json:"tls"`
	TLSInsecure    bool   `json:"tlsInsecure"`
	LastScreenName string `json:"lastScreenName"`
	// Remembered reports whether a password is saved for auto-login, so the
	// sign-on form can reflect the "stay signed in" state.
	Remembered bool `json:"remembered"`
}

// GetServerSettings returns the current server address and remembered screen
// name for prefilling the sign-on form.
func (a *App) GetServerSettings() ServerSettings {
	return ServerSettings{
		Host:           a.cfg.AuthHost,
		Port:           a.cfg.AuthPort,
		LastScreenName: a.cfg.LastScreenName,
		TLS:            a.cfg.TLSOn(),
		TLSInsecure:    a.cfg.TLSInsecure,
		Remembered:     a.cfg.RememberedScreenName != "",
	}
}

// SaveServerSettings persists a new server address. Returns an error string
// (empty on success) so the frontend can show it inline.
func (a *App) SaveServerSettings(host string, port int) string {
	if host == "" {
		return "server host cannot be empty"
	}
	if port <= 0 || port > 65535 {
		return "server port must be between 1 and 65535"
	}
	a.cfg.AuthHost = host
	a.cfg.AuthPort = port
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// SignIn authenticates and brings up a session. It returns an error string
// (empty on success) for inline display, and also emits session:status events
// so the UI can track progress.
//
// When remember is set, the password is saved to the OS secret store for
// auto-login; otherwise any previously saved password for this account is
// cleared. BENCchat never keeps the password itself — only the OS secret store
// does, encrypted.
func (a *App) SignIn(screenName string, password string, remember bool) string {
	if screenName == "" {
		return "screen name is required"
	}
	if password == "" {
		return "password is required"
	}
	if !a.cfg.HasServer() {
		return "no server set — use “Change server” below to enter your OSCAR server address"
	}
	if err := a.doSignOn(screenName, password, remember); err != nil {
		msg := signOnErrorMessage(err)
		if hint := transportHint(err, a.cfg.TLSOn()); hint != "" {
			msg += "\n\n" + hint
		}
		a.emitStatus(SessionStatus{State: "error", Message: msg})
		return msg
	}
	a.emitStatus(SessionStatus{State: "online", Message: "Signed on."})
	return ""
}

// AutoSignIn tries to sign in with a remembered password on launch. On success
// it emits the normal "online" status the UI navigates on; on failure it stays
// quiet (dropping to the sign-on screen) and forgets a definitively-bad
// password so it can't loop the same failure every launch.
func (a *App) AutoSignIn() {
	sn := a.cfg.RememberedScreenName
	if sn == "" {
		return
	}
	pw, err := secret.Retrieve(sn)
	if err != nil || pw == "" {
		a.forgetRemembered()
		return
	}
	if err := a.doSignOn(sn, pw, true); err != nil {
		var loginErr *oscar.LoginError
		if errors.As(err, &loginErr) {
			a.forgetRemembered() // the saved password is wrong; stop trying it
		}
		a.emitStatus(SessionStatus{State: "offline", Message: ""})
		return
	}
	a.emitStatus(SessionStatus{State: "online", Message: "Signed on."})
}

// doSignOn is the shared sign-on core: restore history, connect, then remember
// or forget the password. It emits "signing-on" but leaves the success/failure
// status to the caller (which differs for manual vs auto sign-in).
func (a *App) doSignOn(screenName, password string, remember bool) error {
	a.emitStatus(SessionStatus{State: "signing-on", Message: "Connecting…"})

	// Establish the key that seals this account's history BEFORE reading the
	// file: Load needs it to decrypt, and every later save needs it too.
	a.setupHistoryKey(screenName)

	// Restore local history BEFORE signing on, so offline messages delivered
	// during sign-on append onto the existing scrollback rather than replacing it.
	// Rooms come back as re-joinable "recents" with their past messages.
	if a.cfg.HistoryOn() {
		if d, err := history.Load(screenName, a.historyKey()); err != nil {
			// A file we cannot read is NOT the same as no file. Carrying on as if
			// the history were empty would leave the next save free to overwrite
			// a real (merely undecryptable) file with nothing, turning a recoverable
			// problem — wrong key, damaged file — into permanent data loss.
			slog.Default().Warn("could not load chat history", "err", err)
			a.disableHistoryPersistence(
				"Your saved message history couldn't be read, so BENCchat has stopped " +
					"saving history for this session. It will NOT overwrite the existing " +
					"file — if your keychain was locked, unlock it and sign in again.")
		} else {
			d = history.Prune(d, a.retentionCutoff())
			a.store.RestoreConversations(d.Conversations)
			a.store.RestoreRooms(d.Rooms)
		}
	}

	if err := a.client.SignOn(a.ctx, a.cfg.Address(), oscar.Credentials{
		ScreenName: screenName,
		Password:   password,
	}, a.transport()); err != nil {
		return err
	}

	// Persist this account's history and start saving new messages.
	a.histMu.Lock()
	a.histAccount = screenName
	a.histMu.Unlock()
	a.scheduleHistorySave()

	// Load (or, if enabling, mint) this account's E2EE keypair and publish our
	// public key in the profile. Best-effort — never blocks sign-on.
	a.setupE2EE(screenName)

	a.cfg.LastScreenName = screenName
	if remember {
		if err := secret.Store(screenName, password); err != nil {
			slog.Default().Warn("could not save password to the OS secret store", "err", err)
			a.cfg.RememberedScreenName = ""
		} else {
			a.cfg.RememberedScreenName = screenName
		}
	} else {
		_ = secret.Clear(screenName)
		a.cfg.RememberedScreenName = ""
	}
	_ = config.Save(a.cfg)
	return nil
}

// forgetRemembered clears any saved auto-login credential.
func (a *App) forgetRemembered() {
	if a.cfg.RememberedScreenName == "" {
		return
	}
	_ = secret.Clear(a.cfg.RememberedScreenName)
	a.cfg.RememberedScreenName = ""
	_ = config.Save(a.cfg)
}

// signOnErrorMessage renders a sign-on failure for a human.
func signOnErrorMessage(err error) string {
	// A server-side rejection (bad password, suspended account) already carries a
	// user-appropriate message; anything else is a network or protocol fault and
	// needs the detail to be diagnosable.
	var loginErr *oscar.LoginError
	if errors.As(err, &loginErr) {
		return loginErr.Error()
	}
	return "Could not sign on: " + err.Error()
}

// transportHint explains the two ways a port and the TLS setting can disagree.
// Both fail in a way that reads like a network fault while actually being a
// one-checkbox misconfiguration, so the error says which checkbox.
//
// Plaintext at a TLS port is the quiet one: the connection succeeds, then both
// ends wait — stunnel for a ClientHello, us for a FLAP hello — until the read
// times out. Nothing in "i/o timeout" suggests the transport is the problem.
func transportHint(err error, tlsOn bool) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	if !tlsOn {
		// A timeout mid-handshake, having already connected. A genuinely
		// unreachable host fails to dial instead, and reads that time out later
		// in a live session don't come through sign-on.
		if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timeout") {
			return "The server accepted the connection but sent nothing back. " +
				"That usually means this port expects TLS — turn on “Require an " +
				"encrypted connection (TLS)” in Settings and try again."
		}
		return ""
	}

	// A certificate that doesn't check out is a different problem from a port
	// that doesn't speak TLS at all, and pointing at the wrong one sends people
	// off disabling verification when the port was the issue.
	if strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") {
		return "TLS connected but the server's certificate was rejected. Check " +
			"that the address matches the certificate's name."
	}
	if strings.Contains(msg, "first record does not look like a TLS handshake") ||
		strings.Contains(msg, "tls: ") {
		return "This port doesn't speak TLS. Use the server's TLS port, or turn " +
			"off “Require an encrypted connection (TLS)” in Settings — which " +
			"sends your login and buddy list in the clear."
	}
	return ""
}

// SignOff tears down the session.
func (a *App) SignOff() {
	// Flush history before SignOff resets the store; a user-initiated sign-off is
	// the clean case where we want the final scrollback captured synchronously.
	a.flushHistory()
	// An explicit sign-off forgets the saved password so we don't auto-login next
	// launch — the "unless they explicitly log out" contract.
	a.forgetRemembered()
	// Anything generated for a first run that never completed goes with the
	// session, key and all. It was never written anywhere (proposal §12), so
	// dropping it costs nothing and leaving it would keep an identity private
	// key alive in a process that has no account to use it on.
	a.CancelIdentitySetup()
	// Likewise a re-key that was never confirmed: the stored backup is still the
	// one the CURRENT key opens (proposal §10), so nothing is lost by dropping
	// it, and the identity key it was holding stops existing.
	a.CancelRecoveryKeyRotation()
	a.setIdentityFlow("unavailable")
	_ = a.client.SignOff()
	a.emitStatus(SessionStatus{State: "offline", Message: "Signed off."})
}

// SignedOn reports whether a session is live, so the UI can restore the right
// screen after a reload.
func (a *App) SignedOn() bool { return a.client.SignedOn() }

// GetSelf returns our own identity and presence.
func (a *App) GetSelf() state.Self { return a.store.Self() }

// GetBuddies returns the buddy list, ordered for display.
func (a *App) GetBuddies() []state.Buddy { return a.store.Buddies() }

// GetBuddyIcon returns a buddy's icon as a data URL the UI can drop straight
// into an <img src>, or "" if the buddy has no icon or its bytes haven't
// downloaded yet. Serving it on demand (rather than inlining it into every
// Buddy) keeps the frequent buddy-list payloads small — icons are a few KB each.
// The content type is sniffed from the bytes; anything that isn't an image is
// refused so a malformed BART blob can't become an arbitrary data URL.
func (a *App) GetBuddyIcon(screenName string) string {
	data := a.store.BuddyIconData(screenName)
	if len(data) == 0 {
		return ""
	}
	mime := http.DetectContentType(data)
	if !strings.HasPrefix(mime, "image/") {
		return ""
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}

// GetConversation returns one message thread. A thread that hasn't been started
// yet returns empty rather than an error — opening a new chat window is normal.
func (a *App) GetConversation(screenName string) state.Conversation {
	c, ok := a.store.Conversation(screenName)
	if !ok {
		return state.Conversation{
			Key:        state.NormalizeScreenName(screenName),
			ScreenName: screenName,
			Messages:   []state.Message{},
		}
	}
	return c
}

// GetConversations returns all threads, most recently active first.
func (a *App) GetConversations() []state.Conversation { return a.store.Conversations() }

// SendMessage sends an instant message. Returns an error string (empty on
// success).
func (a *App) SendMessage(to string, text string) string {
	if err := a.client.SendMessage(to, text); err != nil {
		return err.Error()
	}
	return ""
}

// SetTyping reports our typing state to the other party.
func (a *App) SetTyping(to string, typing bool) { a.client.SendTyping(to, typing) }

// AddBuddy adds a buddy to the list. group may be empty for the default group.
// Returns an error string (empty on success).
func (a *App) AddBuddy(screenName string, group string) string {
	if err := a.client.AddBuddy(screenName, group); err != nil {
		return err.Error()
	}
	return ""
}

// RemoveBuddy removes a buddy from the list.
func (a *App) RemoveBuddy(screenName string) string {
	if err := a.client.RemoveBuddy(screenName); err != nil {
		return err.Error()
	}
	return ""
}

// RenameBuddy sets or clears a buddy's local alias.
func (a *App) RenameBuddy(screenName string, alias string) string {
	if err := a.client.RenameBuddy(screenName, alias); err != nil {
		return err.Error()
	}
	return ""
}

// BlockBuddy blocks a user.
func (a *App) BlockBuddy(screenName string) string {
	if err := a.client.BlockBuddy(screenName); err != nil {
		return err.Error()
	}
	return ""
}

// UnblockBuddy unblocks a user.
func (a *App) UnblockBuddy(screenName string) string {
	if err := a.client.UnblockBuddy(screenName); err != nil {
		return err.Error()
	}
	return ""
}

// MarkRead clears a conversation's unread badge.
func (a *App) MarkRead(screenName string) { a.store.MarkRead(screenName) }

// SetAway sets or clears our away message (empty message = back). Returns an
// error string (empty on success).
func (a *App) SetAway(message string) string {
	if err := a.client.SetAway(message); err != nil {
		return err.Error()
	}
	return ""
}

// RequestUserInfo fetches a buddy's profile and away message; results arrive as
// state:events.
func (a *App) RequestUserInfo(screenName string) { a.client.RequestUserInfo(screenName) }

// SetProfile sets our profile text. The bio is persisted and combined with the
// hidden E2EE key marker (when encryption is on) before being sent, so toggling
// E2EE later can rebuild the on-wire profile. Returns an error string (empty on
// success).
func (a *App) SetProfile(text string) string {
	a.cfg.Profile = text
	_ = config.Save(a.cfg)
	if err := a.client.SetProfile(a.wireProfile()); err != nil {
		return err.Error()
	}
	return ""
}

// WarnUser warns a buddy. The result/rejection arrives as a state notice event.
// Returns an error string (empty on success).
func (a *App) WarnUser(screenName string, anonymous bool) string {
	if err := a.client.WarnUser(screenName, anonymous); err != nil {
		return err.Error()
	}
	return ""
}

// FindUser searches for the account registered to an email address. The result
// arrives as a searchResult state event. Returns an error string.
func (a *App) FindUser(email string) string {
	if err := a.client.FindUser(email); err != nil {
		return err.Error()
	}
	return ""
}

// SearchDirectory searches the user directory by name (first and/or last). The
// matching users arrive as an EventDirectoryResult state event. Returns an error
// string for immediate (pre-send) failures such as an empty query.
func (a *App) SearchDirectory(firstName string, lastName string) string {
	if err := a.client.SearchDirectory(firstName, lastName); err != nil {
		return err.Error()
	}
	return ""
}

// --- Chat rooms ---

// JoinRoom joins (creating if needed) a chat room by name. This performs the
// multi-connection OSCAR chat handshake and blocks until the Chat connection is
// up, so the UI should show progress while awaiting it. On success the room
// arrives via EventRoomChanged. Returns an error string on failure.
func (a *App) JoinRoom(name string) string {
	if err := a.client.JoinRoom(name); err != nil {
		return err.Error()
	}
	return ""
}

// LeaveRoom closes a room's connection. The room's removal arrives as an
// EventRoomChanged with a nil room.
func (a *App) LeaveRoom(cookie string) { a.client.LeaveRoom(cookie) }

// SendRoomMessage sends a message to a joined room. Returns an error string on
// failure (e.g. not in the room).
func (a *App) SendRoomMessage(cookie string, text string) string {
	if err := a.client.SendRoomMessage(cookie, text); err != nil {
		return err.Error()
	}
	return ""
}

// GetRooms returns the chat rooms — those currently joined and re-joinable
// recents restored from history.
func (a *App) GetRooms() []state.Room { return a.store.Rooms() }

// ForgetRoom removes a recent (not-joined) room from the list and from saved
// history. To leave a room you're still in, use LeaveRoom.
func (a *App) ForgetRoom(cookie string) {
	a.store.RemoveRoom(cookie)
	a.flushHistory()
}

// GetRoom returns one room's snapshot (empty if not joined).
func (a *App) GetRoom(cookie string) state.Room {
	r, _ := a.store.Room(cookie)
	return r
}

// ChangePassword changes the account password. The result arrives as a notice
// state event. Returns an error string for immediate (pre-send) failures.
func (a *App) ChangePassword(oldPassword string, newPassword string) string {
	if err := a.client.ChangePassword(oldPassword, newPassword); err != nil {
		return err.Error()
	}
	return ""
}

// ChangeEmail changes the account email address.
func (a *App) ChangeEmail(email string) string {
	if err := a.client.ChangeEmail(email); err != nil {
		return err.Error()
	}
	return ""
}

// --- Preferences (theme + sound) ---

// Preferences is the appearance/behavior settings the UI reads on load. It is
// separate from ServerSettings so a settings panel can load everything at once.
type Preferences struct {
	Theme                config.Theme `json:"theme"`
	SoundEnabled         bool         `json:"soundEnabled"`
	SoundPack            string       `json:"soundPack"`
	MutedSounds          []string     `json:"mutedSounds"`
	HistoryEnabled       bool         `json:"historyEnabled"`
	HistoryRetentionDays int          `json:"historyRetentionDays"`
	E2EEEnabled          bool         `json:"e2eeEnabled"`
	Profile              string       `json:"profile"`
	CustomFrame          bool         `json:"customFrame"`
}

// GetPreferences returns the persisted theme, sound, history, and encryption
// settings.
func (a *App) GetPreferences() Preferences {
	return Preferences{
		Theme:                a.cfg.Theme,
		SoundEnabled:         a.cfg.SoundOn(),
		SoundPack:            a.cfg.SoundPack,
		MutedSounds:          a.cfg.MutedSounds,
		HistoryEnabled:       a.cfg.HistoryOn(),
		HistoryRetentionDays: a.cfg.HistoryRetentionDays,
		E2EEEnabled:          a.cfg.E2EEOn(),
		Profile:              a.cfg.Profile,
		CustomFrame:          a.cfg.CustomFrame,
	}
}

// --- Local chat history ---

// setupHistoryKey loads (or, for an account that has never had one, generates)
// the key that encrypts this account's history file, for the duration of the
// session.
//
// The rules are setupE2EE's, for the same reason. A keyring read that FAILED and
// a store that holds nothing are different answers, and only one of them means
// "generate a key". Minting one on failure would seal new history under a key
// that has nothing to do with the file already on disk — and since the old key
// is then overwritten in the keyring, every message the user has ever saved
// becomes permanently unreadable. A transiently locked keychain must not be able
// to do that.
//
// So a failed read disables history persistence for the session instead. Nothing
// is written, and in particular nothing is written in the clear: personal
// messages sitting readable on disk is the thing this whole mechanism exists to
// prevent, so there is no plaintext fallback.
func (a *App) setupHistoryKey(screenName string) {
	a.histMu.Lock()
	a.histKey = nil
	a.histNoticeShown = false
	a.histMu.Unlock()

	// With history saving off, no file will be read or written, so there is no
	// reason to reach for the keychain — or to make the user unlock one — on
	// behalf of a feature they have turned off. SetHistoryEnabled runs this again
	// if they turn it back on.
	if !a.cfg.HistoryOn() {
		return
	}

	stored, err := secret.RetrieveHistoryKey(screenName)
	if err != nil {
		slog.Default().Warn("could not read the history key from the secret store", "err", err)
		a.disableHistoryPersistence(
			"Message history won't be saved this session: your keychain couldn't be " +
				"reached, so BENCchat can't load the key your saved history is encrypted " +
				"with. It will NOT create a new one — that would make everything already " +
				"saved unreadable. Unlock your keychain and sign in again.")
		return
	}

	if stored != "" {
		raw, derr := base64.StdEncoding.DecodeString(stored)
		if derr == nil && len(raw) == 32 {
			var k [32]byte
			copy(k[:], raw)
			a.setHistoryKey(&k)
			return
		}
		// A stored value we can't make sense of is the failed-read case wearing a
		// different hat: there IS a key, we just can't use it, and replacing it
		// would strand the file it wrote.
		slog.Default().Warn("the stored history key is unusable", "err", derr, "len", len(raw))
		a.disableHistoryPersistence(
			"Message history won't be saved this session: the key your saved history " +
				"is encrypted with is damaged. BENCchat won't replace it, since that " +
				"would discard everything already saved. Clear history in Privacy & " +
				"Security to start fresh.")
		return
	}

	// Nothing stored: this account has no history key yet, which is the genuine
	// first-run case. Any file on disk is either absent or plaintext from an
	// older BENCchat, and both are readable without a key — so a new key strands
	// nothing, and the next save re-encrypts what was plaintext.
	k, err := history.NewKey()
	if err != nil {
		slog.Default().Warn("could not generate a history key", "err", err)
		a.disableHistoryPersistence(
			"Message history won't be saved this session: BENCchat couldn't generate " +
				"a key to encrypt it with.")
		return
	}
	if serr := secret.StoreHistoryKey(screenName, base64.StdEncoding.EncodeToString(k[:])); serr != nil {
		// Using a key we couldn't store would write a file nothing can ever open
		// again — worse than not writing one, so don't.
		slog.Default().Warn("could not save the history key", "err", serr)
		a.disableHistoryPersistence(
			"Message history won't be saved this session: BENCchat couldn't store the " +
				"key in your keychain, and history sealed with a key that isn't saved " +
				"could never be read back.")
		return
	}
	a.setHistoryKey(k)
}

// setHistoryKey installs the session's history key.
func (a *App) setHistoryKey(k *[32]byte) {
	a.histMu.Lock()
	a.histKey = k
	a.histMu.Unlock()
}

// historyKey returns the session's history key, or nil when persistence is off.
func (a *App) historyKey() *[32]byte {
	a.histMu.Lock()
	defer a.histMu.Unlock()
	return a.histKey
}

// historySession returns the account whose history we persist and the key that
// seals it, read together so a save can't pair one session's account with
// another's key. An empty account or a nil key means: do not write.
func (a *App) historySession() (string, *[32]byte) {
	a.histMu.Lock()
	defer a.histMu.Unlock()
	return a.histAccount, a.histKey
}

// disableHistoryPersistence stops saving for the rest of the session and says
// why — once. Saves then skip silently: the reason doesn't change, and repeating
// it on every debounce tick is how a single locked keychain becomes a wall of
// identical notices. Staying quiet is only acceptable because the user was told
// the first time.
func (a *App) disableHistoryPersistence(msg string) {
	a.histMu.Lock()
	a.histKey = nil
	first := !a.histNoticeShown
	a.histNoticeShown = true
	a.histMu.Unlock()
	if first {
		a.store.Notify(state.NoticeError, msg)
	}
}

// retentionCutoff is the oldest timestamp to keep, or the zero time when
// retention is disabled (keep forever).
func (a *App) retentionCutoff() time.Time {
	if a.cfg.HistoryRetentionDays <= 0 {
		return time.Time{}
	}
	return time.Now().AddDate(0, 0, -a.cfg.HistoryRetentionDays)
}

// scheduleHistorySave debounces a write of the current scrollback to disk, so a
// burst of messages produces one save rather than one per message.
func (a *App) scheduleHistorySave() {
	if !a.cfg.HistoryOn() {
		return
	}
	a.histMu.Lock()
	defer a.histMu.Unlock()
	if a.histAccount == "" {
		return
	}
	if a.histTimer != nil {
		a.histTimer.Stop()
	}
	a.histTimer = time.AfterFunc(2*time.Second, a.flushHistory)
}

// flushHistory writes the current conversations to the signed-on account's file,
// applying retention. It is a no-op when signed off, when history is disabled,
// when there is no key, or when there is nothing to save — the last guard is what
// stops a sign-off race (store already reset) from clobbering the file with an
// empty set.
func (a *App) flushHistory() {
	account, key := a.historySession()
	// No key means persistence was disabled for this session and the user has
	// already been told once. Skip in silence rather than logging every tick.
	if account == "" || key == nil || !a.cfg.HistoryOn() {
		return
	}
	d := history.Prune(history.Data{
		Conversations: a.store.Conversations(),
		Rooms:         a.store.Rooms(),
	}, a.retentionCutoff())
	if len(d.Conversations) == 0 && len(d.Rooms) == 0 {
		return
	}
	if err := history.Save(account, d, key); err != nil {
		slog.Default().Warn("could not save chat history", "err", err)
	}
}

// CloseConversation removes a 1:1 thread from the list without blocking the
// other party, and persists the removal so it doesn't return on next sign-on.
func (a *App) CloseConversation(screenName string) {
	a.store.CloseConversation(screenName)
	a.persistHistoryNow()
}

// persistHistoryNow writes history immediately, and — unlike flushHistory —
// persists an empty result (clearing the file). An explicit removal must stick;
// flushHistory's skip-if-empty guard exists only to survive the sign-off race
// where the store is momentarily reset.
func (a *App) persistHistoryNow() {
	account, key := a.historySession()
	// Without a key this does nothing at all — not even the Clear below. We may
	// be unable to READ the file (locked keychain, wrong key), and deleting
	// history we merely failed to open is a far worse outcome than a removal that
	// doesn't stick. ClearHistory is the deliberate route to wiping the file.
	if account == "" || key == nil || !a.cfg.HistoryOn() {
		return
	}
	d := history.Prune(history.Data{
		Conversations: a.store.Conversations(),
		Rooms:         a.store.Rooms(),
	}, a.retentionCutoff())
	if len(d.Conversations) == 0 && len(d.Rooms) == 0 {
		_ = history.Clear(account)
		return
	}
	if err := history.Save(account, d, key); err != nil {
		slog.Default().Warn("could not save chat history", "err", err)
	}
}

// SetHistoryEnabled turns local history saving on or off. Turning it off stops
// future saves but leaves any existing file until the user clears it.
func (a *App) SetHistoryEnabled(enabled bool) string {
	a.cfg.HistoryEnabled = &enabled
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	if enabled {
		// Switching history on is the moment to retry a key setup that failed at
		// sign-on: the usual cause is a locked keychain, which the user may well
		// have unlocked since. Without this, persistence would stay off — silently,
		// because the one notice was already spent — until the next sign-on.
		if account, key := a.historySession(); account != "" && key == nil {
			a.setupHistoryKey(account)
		}
		a.scheduleHistorySave()
	} else {
		a.histMu.Lock()
		if a.histTimer != nil {
			a.histTimer.Stop()
			a.histTimer = nil
		}
		a.histMu.Unlock()
	}
	return ""
}

// SetHistoryRetention sets the auto-delete age in days (0 = keep forever) and
// applies it immediately.
func (a *App) SetHistoryRetention(days int) string {
	if days < 0 {
		days = 0
	}
	a.cfg.HistoryRetentionDays = days
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	a.flushHistory() // prune-on-save applies the new window now
	return ""
}

// ClearHistory wipes all saved history — the in-memory scrollback and the file.
// Works whether signed on (uses the live account) or off (uses the last one).
func (a *App) ClearHistory() string {
	a.store.ClearConversations()

	a.histMu.Lock()
	account := a.histAccount
	a.histMu.Unlock()
	if account == "" {
		account = a.cfg.LastScreenName
	}
	if account == "" {
		return ""
	}
	if err := history.Clear(account); err != nil {
		return err.Error()
	}
	// The key only ever existed to open the file we just destroyed, so it goes
	// too — leaving it behind means the keychain keeps an entry for data that no
	// longer exists. Best-effort on purpose: a keyring that can't be reached must
	// not turn a successful wipe into a reported failure, and a stale key is
	// harmless anyway (the next sign-on simply reuses it to seal fresh history).
	if err := secret.ClearHistoryKey(account); err != nil {
		slog.Default().Warn("could not clear the history key", "err", err)
	}
	// Mint a replacement straight away when a session is live, so the rest of it
	// keeps saving. Without this, clearing history would quietly switch
	// persistence off until the next sign-on.
	if live, _ := a.historySession(); live != "" {
		a.setupHistoryKey(live)
	}
	return ""
}

// SaveTheme persists the chosen theme. name is a preset id or "custom"; tokens
// holds per-token overrides (empty for an unmodified preset). Returns an error
// string (empty on success).
func (a *App) SaveTheme(name string, tokens map[string]string) string {
	a.cfg.Theme = config.Theme{Name: name, Tokens: tokens}
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// SetSoundEnabled persists the sound on/off preference.
func (a *App) SetSoundEnabled(enabled bool) string {
	a.cfg.SoundEnabled = &enabled
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// SetSoundMuted mutes or unmutes a single sound event, independent of the
// global on/off switch. Unknown keys are rejected so the stored list can't
// accumulate entries the UI has no way to clear.
func (a *App) SetSoundMuted(key string, muted bool) string {
	if !soundEventKeys[key] {
		return "unknown sound event"
	}
	out := make([]string, 0, len(a.cfg.MutedSounds)+1)
	for _, k := range a.cfg.MutedSounds {
		if k != key {
			out = append(out, k)
		}
	}
	if muted {
		out = append(out, key)
	}
	a.cfg.MutedSounds = out
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// SetSoundPack persists the chosen notification sound pack. The name is validated
// on the frontend (it owns the pack definitions); the backend just stores it.
func (a *App) SetSoundPack(name string) string {
	a.cfg.SoundPack = name
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}
