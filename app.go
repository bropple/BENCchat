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

	// Local history orchestration. histAccount is the signed-on screen name whose
	// history we're persisting ("" when signed off); histTimer debounces saves so
	// a burst of messages writes the file once. Guarded by histMu.
	histMu      sync.Mutex
	histAccount string
	histTimer   *time.Timer

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

	// trust holds the signed-on account's manually-verified peer keys, loaded on
	// sign-on. Guarded by trustMu since UI calls read/write it off the main loop.
	trustMu sync.Mutex
	trust   trust.Store

	// Device-linking state, guarded by linkMu. linkPrompted records keys we've
	// already put in front of the user this session and linkDeclined those they
	// said no to, so a device that announces more than once — a sibling
	// reconnecting, an auto-login racing a manual one — asks once rather than
	// stacking a dialog per announcement.
	//
	// linkPending is the other side of the same conversation: true when THIS
	// device has announced itself to an account that already has devices and is
	// waiting to be approved from one of them.
	linkMu       sync.Mutex
	linkPrompted map[[32]byte]bool
	linkDeclined map[[32]byte]bool
	linkPending  bool

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
	return &App{
		cfg:    cfg,
		store:  store,
		client: client.New(store, slog.Default()),
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
// SetTLS turns TLS on or off for future connections. insecure disables
// certificate verification and is for testing against a self-signed server
// only — it defeats the point of TLS, so the UI must label it as such.
func (a *App) SetTLS(on, insecure bool) string {
	a.cfg.TLSEnabled = &on
	a.cfg.TLSInsecure = on && insecure
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// ConnectionSecure reports whether the live session is encrypted in transit.
func (a *App) ConnectionSecure() bool { return a.client.Secure() }

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

	// Restore local history BEFORE signing on, so offline messages delivered
	// during sign-on append onto the existing scrollback rather than replacing it.
	// Rooms come back as re-joinable "recents" with their past messages.
	if a.cfg.HistoryOn() {
		if d, err := history.Load(screenName); err != nil {
			slog.Default().Warn("could not load chat history", "err", err)
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

// GetGroups returns the buddy-list group names in list order.
func (a *App) GetGroups() []string { return a.store.Groups() }

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

// RequestAwayMessage asks for a buddy's away message. The result arrives as a
// state:event updating that buddy, so this returns nothing.
func (a *App) RequestAwayMessage(screenName string) { a.client.RequestAwayMessage(screenName) }

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
// or when there is nothing to save — the last guard is what stops a sign-off
// race (store already reset) from clobbering the file with an empty set.
func (a *App) flushHistory() {
	a.histMu.Lock()
	account := a.histAccount
	a.histMu.Unlock()
	if account == "" || !a.cfg.HistoryOn() {
		return
	}
	d := history.Prune(history.Data{
		Conversations: a.store.Conversations(),
		Rooms:         a.store.Rooms(),
	}, a.retentionCutoff())
	if len(d.Conversations) == 0 && len(d.Rooms) == 0 {
		return
	}
	if err := history.Save(account, d); err != nil {
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
	a.histMu.Lock()
	account := a.histAccount
	a.histMu.Unlock()
	if account == "" || !a.cfg.HistoryOn() {
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
	if err := history.Save(account, d); err != nil {
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
