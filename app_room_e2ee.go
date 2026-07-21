package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/roomkeys"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Encrypted chat rooms, app layer.
//
// The membership rule that shapes all of this: OSCAR has no access control on
// rooms and no way to remove anyone. Whoever knows a room name can walk in, and
// once someone holds the group key there is no taking it back. So the key is
// only ever given deliberately, and "removing" someone means moving the
// conversation to a fresh room.

// roomMembers tracks who we have deliberately given a room's key to.
//
// Rotation redistributes to exactly this set — never to "everyone currently in
// the room", which would hand a key to an uninvited walk-in the moment anybody
// left.
type roomMembers struct {
	mu      sync.Mutex
	invited map[string]map[string]bool // room cookie -> normalized screen name
}

func (m *roomMembers) add(cookie, screenName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invited == nil {
		m.invited = map[string]map[string]bool{}
	}
	if m.invited[cookie] == nil {
		m.invited[cookie] = map[string]bool{}
	}
	m.invited[cookie][state.NormalizeScreenName(screenName)] = true
}

func (m *roomMembers) remove(cookie, screenName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invited[cookie] != nil {
		delete(m.invited[cookie], state.NormalizeScreenName(screenName))
	}
}

func (m *roomMembers) list(cookie string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.invited[cookie]))
	for sn := range m.invited[cookie] {
		out = append(out, sn)
	}
	return out
}

func (m *roomMembers) forget(cookie string) {
	m.mu.Lock()
	delete(m.invited, cookie)
	m.mu.Unlock()
}

// addAll unions names into a room's set, skipping self.
//
// Used when a roster arrives alongside a key we ALREADY hold: somebody added a
// member, and the news is additive. Replacing on that would lose anyone we
// invited concurrently, whose invite the sender had not seen yet.
func (m *roomMembers) addAll(cookie string, names []string, self string) {
	for _, n := range names {
		if state.NormalizeScreenName(n) == self {
			continue
		}
		m.add(cookie, n)
	}
}

// setAll replaces a room's set with names, skipping self.
//
// Used when a roster arrives with a NEW key. A rotation is authoritative about
// who holds the key it carries — that is the whole point of rotating — so this
// is the path by which a removal actually propagates.
func (m *roomMembers) setAll(cookie string, names []string, self string) {
	m.mu.Lock()
	if m.invited == nil {
		m.invited = map[string]map[string]bool{}
	}
	set := map[string]bool{}
	for _, n := range names {
		if norm := state.NormalizeScreenName(n); norm != self {
			set[norm] = true
		}
	}
	m.invited[cookie] = set
	m.mu.Unlock()
}

// saveRoomKeys persists the current key set for a room, so a restart doesn't
// lock the user out of their own encrypted rooms.
func (a *App) saveRoomKeys(cookie string) {
	acct := a.currentAccount()
	if acct == "" {
		return
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return
	}
	keys, currentID := a.client.RoomKeySet(cookie)

	store, err := roomkeys.Load(acct)
	if err != nil {
		slog.Default().Warn("could not read saved room keys", "err", err)
		store = roomkeys.Store{}
	}
	encoded := make(map[string]string, len(keys))
	for id, k := range keys {
		encoded[id] = e2ee.EncodeRoomKey(k)
	}
	store[cookie] = roomkeys.Room{
		Name:      room.Name,
		Keys:      encoded,
		CurrentID: currentID,
		Members:   a.members.list(cookie),
		Updated:   time.Now(),
	}
	if err := roomkeys.Save(acct, store); err != nil {
		slog.Default().Warn("could not save room keys", "err", err)
	}
}

// restoreRoomKeys reinstalls saved keys after sign-on.
//
// Rooms are matched by cookie, which is derived from the room name, so a room
// rejoined later gets its key back. A room whose key we can't decode is still
// marked encrypted — better to refuse to send than to quietly go plaintext.
func (a *App) restoreRoomKeys() {
	acct := a.currentAccount()
	if acct == "" {
		return
	}
	store, err := roomkeys.Load(acct)
	if err != nil {
		slog.Default().Warn("could not load saved room keys", "err", err)
		return
	}
	for cookie, r := range store {
		keys := make(map[string]e2ee.RoomKey, len(r.Keys))
		for id, enc := range r.Keys {
			k, derr := e2ee.DecodeRoomKey(enc)
			if derr != nil {
				continue
			}
			keys[id] = k
		}
		if len(keys) == 0 {
			a.client.MarkRoomEncrypted(cookie)
			continue
		}
		a.client.RestoreRoomKeys(cookie, keys, r.CurrentID)
		for _, m := range r.Members {
			a.members.add(cookie, m)
		}
	}
}

// RoomSecurity is what the UI needs to describe a room's encryption state.
type RoomSecurity struct {
	Encrypted bool `json:"encrypted"`
	// Readable is whether we hold a usable key. An encrypted room we can't read
	// is a real state — after a restart, or before an invitation is accepted —
	// and the UI must show it rather than implying the room is plaintext.
	Readable bool `json:"readable"`
	// NonReaders are participants whose client advertises no encryption support,
	// i.e. people present who cannot read what is being said. Detected, not
	// guaranteed — see Client.RoomNonReaders.
	NonReaders []string `json:"nonReaders"`
	// Members are the people we deliberately gave the key to.
	Members []string `json:"members"`
}

// RoomSecurityInfo reports a room's encryption state.
func (a *App) RoomSecurityInfo(cookie string) RoomSecurity {
	return RoomSecurity{
		Encrypted:  a.client.RoomEncrypted(cookie),
		Readable:   a.client.RoomReadable(cookie),
		NonReaders: a.client.RoomNonReaders(cookie),
		Members:    a.members.list(cookie),
	}
}

// CreateEncryptedRoom joins (or creates) a room and turns on encryption for it.
//
// Nobody else can read it until they are invited — including people already
// sitting in the room, who will see ciphertext.
func (a *App) CreateEncryptedRoom(name string) string {
	if err := a.client.JoinRoom(name); err != nil {
		return err.Error()
	}
	cookie, ok := a.roomCookieByName(name)
	if !ok {
		return "Joined the room but couldn't identify it — try again."
	}
	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		return err.Error()
	}
	a.client.SetRoomKey(cookie, key)
	a.saveRoomKeys(cookie)
	a.store.Notify(state.NoticeInfo,
		"Encrypted room created. Nobody else can read it until you invite them.")
	return ""
}

// InviteToRoom shares the active room's key with someone, over the 1:1
// encrypted channel.
func (a *App) InviteToRoom(cookie, screenName string) string {
	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return "Enter a screen name."
	}
	key, ok := a.client.RoomKey(cookie)
	if !ok {
		return "This room isn't encrypted, so there's no key to share."
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return "You're not in that room."
	}
	// Record them BEFORE distributing, so the roster that goes out already names
	// the newcomer — that is how the existing members learn about them.
	a.members.add(cookie, screenName)
	a.saveRoomKeys(cookie)

	// Sent to everyone, not just the newcomer. The key is unchanged for the
	// people who already had it; what they are being told is the new roster,
	// without which their own rotations would never reach the person just added.
	if failed := a.distributeRoomKey(cookie, room.Name, key, nil); len(failed) > 0 {
		if len(failed) == 1 && state.NormalizeScreenName(failed[0]) == state.NormalizeScreenName(screenName) {
			// The invitee themselves is the one we could not reach, so nothing
			// happened at all. Undo, rather than leaving a member recorded who
			// never got a key.
			a.members.remove(cookie, screenName)
			a.saveRoomKeys(cookie)
			return "Couldn't reach " + screenName + " — they haven't been invited."
		}
		a.store.Notify(state.NoticeWarn, "Invited "+screenName+", but couldn't tell "+
			strings.Join(failed, ", ")+" about it — their next key rotation may miss people.")
		return ""
	}
	a.store.Notify(state.NoticeInfo, screenName+" can now read this room.")
	return ""
}

// roomRoster is the member list as it goes on the wire: everyone we believe
// holds this room's key, INCLUDING us.
//
// Recipients strip themselves back out, which keeps a.members meaning "other
// people who hold the key" on every machine. Leaving ourselves off instead would
// mean a person we invited never learns WE hold it, and would then refuse our
// own rotations as coming from a non-member.
func (a *App) roomRoster(cookie string) []string {
	roster := a.members.list(cookie)
	if self := state.NormalizeScreenName(a.currentAccount()); self != "" {
		roster = append(roster, self)
	}
	sort.Strings(roster)
	return roster
}

// distributeRoomKey sends a room's key and current roster to every member,
// skipping anyone in dropped, and returns those it could not reach.
//
// Shared by invite, rotation and reform so all three compute the roster
// identically — the bug this exists to prevent is three call sites drifting into
// three different ideas of who is in the room.
func (a *App) distributeRoomKey(cookie, roomName string, key e2ee.RoomKey, dropped map[string]bool) []string {
	roster := a.roomRoster(cookie)
	var failed []string
	for _, sn := range a.members.list(cookie) {
		if dropped[sn] {
			continue
		}
		if err := a.client.InviteToRoom(sn, roomName, key, roster); err != nil {
			failed = append(failed, sn)
			slog.Default().Warn("could not deliver a room key", "peer", sn, "room", roomName, "err", err)
		}
	}
	return failed
}

// learnRoomRoster folds an inbound roster into what we know.
//
// keyIsNew decides union versus replace, and the distinction matters: a
// rotation is authoritative about who holds the key it carries, so it replaces
// (this is how a removal propagates), while a roster arriving with a key we
// already hold is somebody announcing an ADD, so it unions (replacing there
// would drop anyone we invited concurrently, whose invite the sender had not
// seen yet).
func (a *App) learnRoomRoster(cookie string, roster []string, keyIsNew bool) {
	if len(roster) == 0 {
		return // a v1 invite told us nothing; that is not "the room is empty"
	}
	self := state.NormalizeScreenName(a.currentAccount())
	if keyIsNew {
		a.members.setAll(cookie, roster, self)
		return
	}
	a.members.addAll(cookie, roster, self)
}

// handleRoomInvite surfaces an inbound room key for the user to accept.
//
// Never auto-joined: accepting means entering a room and being seen there, and
// the invite arrives over a channel authenticated only as far as the sender's
// key — which the user may never have verified.
func (a *App) handleRoomInvite(from string, inv e2ee.RoomInvite) {
	// A key for a room we're already in is a ROTATION, not an invitation. Apply
	// it directly: prompting to "join" a room the user is sitting in would be
	// nonsense, and re-joining would open a second connection to it.
	//
	// Only from someone we deliberately gave this room's key to, though. Reaching
	// us over the encrypted 1:1 channel proves nothing about room membership —
	// peer keys are fetched on demand for anyone — so without this check any
	// account that learns the room name can replace the key we SEND under, and
	// our messages get sealed to them instead of to the room. The reasoning this
	// replaces (that a bogus key only makes the room unreadable to us, which is
	// immediately visible) holds for receiving and fails for sending.
	if cookie, ok := a.roomCookieByName(inv.Room); ok {
		if !a.isRoomMember(cookie, from) {
			slog.Default().Warn("ignoring a room key rotation from a non-member",
				"peer", from, "room", inv.Room)
			a.store.Notify(state.NoticeWarn, from+" tried to change the key for “"+inv.Room+
				"” but was never given it. Ignored.")
			return
		}
		// Not every one of these is a rotation. An invite sent to somebody ELSE
		// goes to the whole room so everyone learns the new roster, and it
		// carries the key we already hold. Announcing that as "the key was
		// rotated" would be a lie, and a frequent one.
		cur, hadKey := a.client.RoomKey(cookie)
		keyIsNew := !hadKey || cur.ID() != inv.Key.ID()
		a.learnRoomRoster(cookie, inv.Members, keyIsNew)

		if !keyIsNew {
			a.saveRoomKeys(cookie)
			return
		}
		a.client.SetRoomKey(cookie, inv.Key)
		a.saveRoomKeys(cookie)
		a.store.Notify(state.NoticeInfo, "The key for “"+inv.Room+"” was rotated by "+from+".")
		return
	}

	a.pendingMu.Lock()
	if a.pendingInvites == nil {
		a.pendingInvites = map[string]e2ee.RoomInvite{}
	}
	a.pendingInvites[inv.Room] = inv
	if a.pendingInviteFrom == nil {
		a.pendingInviteFrom = map[string]string{}
	}
	a.pendingInviteFrom[inv.Room] = from
	a.pendingMu.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "room:invite", map[string]string{
			"from": from,
			"room": inv.Room,
		})
	}
}

// RoomInviteInfo is a pending invitation, for the roster's invite list.
type RoomInviteInfo struct {
	Room string `json:"room"`
	From string `json:"from"`
}

// PendingRoomInvites lists invitations waiting for a decision.
//
// Invitations queue here rather than interrupting: one can arrive before you
// have verified the sender, and a modal demanding an immediate answer about a
// person you haven't checked yet is exactly the wrong prompt at the wrong time.
func (a *App) PendingRoomInvites() []RoomInviteInfo {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	out := make([]RoomInviteInfo, 0, len(a.pendingInvites))
	for room := range a.pendingInvites {
		out = append(out, RoomInviteInfo{Room: room, From: a.pendingInviteFrom[room]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Room < out[j].Room })
	return out
}

// AcceptRoomInvite joins an invited room and installs its key.
func (a *App) AcceptRoomInvite(roomName string) string {
	a.pendingMu.Lock()
	from := a.pendingInviteFrom[roomName]
	inv, ok := a.pendingInvites[roomName]
	delete(a.pendingInvites, roomName)
	a.pendingMu.Unlock()
	if !ok {
		return "That invitation is no longer available."
	}
	if err := a.client.JoinRoom(inv.Room); err != nil {
		return err.Error()
	}
	cookie, found := a.roomCookieByName(inv.Room)
	if !found {
		return "Joined but couldn't identify the room."
	}
	a.client.SetRoomKey(cookie, inv.Key)
	// The roster names everyone who holds this key, so take the lot — knowing
	// only the person who invited us is what left three-way rooms unable to
	// rotate. `from` is added regardless: a v1 invite carries no roster, and
	// even in v2 the inviter is the one member we can be certain of.
	a.members.add(cookie, from)
	a.learnRoomRoster(cookie, inv.Members, false)
	a.saveRoomKeys(cookie)
	go a.requestRoomCatchup(cookie)
	return ""
}

// DeclineRoomInvite drops a pending invitation.
func (a *App) DeclineRoomInvite(roomName string) {
	a.pendingMu.Lock()
	delete(a.pendingInvites, roomName)
	delete(a.pendingInviteFrom, roomName)
	a.pendingMu.Unlock()
}

// RotateRoomKey mints a new group key and gives it to the people we previously
// invited, except anyone named in drop.
//
// This is what makes leaving meaningful: without it, someone who left keeps
// reading everything said afterwards. Messages already sent stay readable to
// everyone who had the old key — rotation bounds the future, not the past.
func (a *App) RotateRoomKey(cookie string, drop []string) string {
	if !a.client.RoomEncrypted(cookie) {
		return "This room isn't encrypted."
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return "You're not in that room."
	}
	dropped := map[string]bool{}
	for _, d := range drop {
		dropped[state.NormalizeScreenName(d)] = true
		a.members.remove(cookie, d)
	}

	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		return err.Error()
	}
	a.client.SetRoomKey(cookie, key)
	a.saveRoomKeys(cookie)

	failed := a.distributeRoomKey(cookie, room.Name, key, dropped)
	if len(failed) > 0 {
		// Say so rather than leaving people silently unable to read: they need a
		// re-invite once they're reachable again.
		a.store.Notify(state.NoticeWarn, "New room key sent, but "+strings.Join(failed, ", ")+
			" couldn't be reached — they won't be able to read this room until you invite them again.")
		return ""
	}
	a.store.Notify(state.NoticeInfo, "Room key rotated.")
	return ""
}

// ReformRoom is the closest thing to removing someone: OSCAR has no kick, so
// the conversation moves to a fresh room with an unguessable name and a new
// key, and only the invited members are told where it went.
//
// The person left behind sees everyone leave. It's a relocation, not a silent
// ejection — worth the user knowing.
func (a *App) ReformRoom(cookie string, drop []string) string {
	room, ok := a.store.Room(cookie)
	if !ok {
		return "You're not in that room."
	}
	if !a.client.RoomEncrypted(cookie) {
		return "This room isn't encrypted."
	}

	dropped := map[string]bool{}
	for _, d := range drop {
		dropped[state.NormalizeScreenName(d)] = true
	}
	var carry []string
	for _, sn := range a.members.list(cookie) {
		if !dropped[sn] {
			carry = append(carry, sn)
		}
	}

	newName, err := reformedRoomName(room.Name)
	if err != nil {
		return err.Error()
	}
	if err := a.client.JoinRoom(newName); err != nil {
		return "Couldn't create the new room: " + err.Error()
	}
	newCookie, found := a.roomCookieByName(newName)
	if !found {
		return "Created the new room but couldn't identify it."
	}
	key, err := e2ee.GenerateRoomKey()
	if err != nil {
		return err.Error()
	}
	a.client.SetRoomKey(newCookie, key)

	// Record everyone being carried over BEFORE distributing, so the roster each
	// of them receives already names all the others. Doing it as each invite
	// succeeded meant the first person invited was told the room contained only
	// themselves. Anyone unreachable is dropped again immediately below.
	for _, sn := range carry {
		a.members.add(newCookie, sn)
	}
	for _, sn := range a.distributeRoomKey(newCookie, newName, key, nil) {
		a.members.remove(newCookie, sn)
	}
	a.saveRoomKeys(newCookie)

	// Leave the old room last, so we don't drop out before the invitations go.
	a.client.LeaveRoom(cookie)
	a.client.ForgetRoomKeys(cookie)
	a.members.forget(cookie)
	if acct := a.currentAccount(); acct != "" {
		if err := roomkeys.Forget(acct, cookie); err != nil {
			slog.Default().Warn("could not forget the old room's keys", "err", err)
		}
	}

	a.store.Notify(state.NoticeInfo,
		"Moved to a new room. Everyone still on the list was invited; anyone else is left behind.")
	return ""
}

// reformedRoomName builds an unguessable name for a reformed room. Room names
// are the only handle on a room and there is no join control, so the randomness
// is what keeps the person left behind from simply following.
func reformedRoomName(base string) (string, error) {
	if i := strings.LastIndex(base, "-x"); i > 0 && len(base)-i == 10 {
		base = base[:i] // don't accumulate suffixes across repeated reforms
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate room name: %w", err)
	}
	suffix := strings.ToLower(base64.RawURLEncoding.EncodeToString(b[:]))
	suffix = strings.NewReplacer("-", "a", "_", "b").Replace(suffix)
	return base + "-x" + suffix, nil
}

// roomCookieByName finds a joined room's cookie from its name.
func (a *App) roomCookieByName(name string) (string, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, r := range a.store.Rooms() {
		if strings.ToLower(r.Name) == want && r.Joined {
			return r.Cookie, true
		}
	}
	return "", false
}

// --- Room catch-up ----------------------------------------------------------

// lastSeenRoom remembers how far we had caught up in each room, so a returning
// member asks for the right window instead of the whole history.
func (a *App) roomLastSeen(cookie string) time.Time {
	room, ok := a.store.Room(cookie)
	if !ok || len(room.Messages) == 0 {
		// Nothing local: ask for a day's worth rather than everything, which
		// would blow past the response size limit and mostly be trimmed anyway.
		return time.Now().Add(-24 * time.Hour)
	}
	return room.Messages[len(room.Messages)-1].At
}

// requestRoomCatchup asks a member who was present what we missed.
//
// Only people we deliberately invited are asked: they are the ones who have the
// history, and asking a stranger would advertise which rooms we are in.
func (a *App) requestRoomCatchup(cookie string) {
	room, ok := a.store.Room(cookie)
	if !ok {
		return
	}
	since := a.roomLastSeen(cookie)
	self := state.NormalizeScreenName(a.store.Self().ScreenName)

	for _, sn := range a.members.list(cookie) {
		if sn == self {
			continue
		}
		if err := a.client.RequestCatchup(sn, room.Name, since); err != nil {
			slog.Default().Debug("catch-up request not sent", "peer", sn, "err", err)
			continue
		}
		// One member is enough; overlapping answers would just be de-duplicated,
		// and asking everyone multiplies traffic for no gain.
		return
	}
}

// handleCatchup answers a peer's request, or folds in their answer.
func (a *App) handleCatchup(from string, isRequest bool, req e2ee.CatchupRequest, res e2ee.CatchupResponse) {
	if isRequest {
		a.serveCatchup(from, req)
		return
	}
	cookie, ok := a.roomCookieByName(res.Room)
	if !ok {
		return // we're not in that room; nothing to merge into
	}
	n := a.client.MergeCatchup(cookie, res)
	if n == 0 {
		return
	}
	msg := fmt.Sprintf("Recovered %d message(s) you missed in “%s”.", n, res.Room)
	if res.Truncated {
		msg += " Older messages were left out — only the most recent were sent."
	}
	a.store.Notify(state.NoticeInfo, msg)
}

// serveCatchup answers a request for room history.
//
// Only members we deliberately invited are answered. Anyone else — including
// someone sitting in the room uninvited — gets silence: the room is joinable by
// name, so "is in the room" is not evidence of anything, and history is exactly
// what we withheld from them by not sharing the key.
func (a *App) serveCatchup(from string, req e2ee.CatchupRequest) {
	cookie, ok := a.roomCookieByName(req.Room)
	if !ok {
		return
	}
	if !a.isRoomMember(cookie, from) {
		slog.Default().Warn("ignoring a room history request from a non-member",
			"peer", from, "room", req.Room)
		return
	}
	msgs := a.client.RoomHistorySince(cookie, req.Since)
	if len(msgs) == 0 {
		return
	}
	if err := a.client.SendCatchup(from, e2ee.CatchupResponse{Room: req.Room, Messages: msgs}); err != nil {
		slog.Default().Warn("could not serve room history", "peer", from, "err", err)
	}
}

// isRoomMember reports whether we deliberately gave this person the room's key.
func (a *App) isRoomMember(cookie, screenName string) bool {
	want := state.NormalizeScreenName(screenName)
	for _, sn := range a.members.list(cookie) {
		if sn == want {
			return true
		}
	}
	return false
}
