package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/benco-holdings/benchat/internal/secret"
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
	// owner is the room's owner, pinned the first time we see the room and never
	// silently changed. Only the owner may SHRINK a roster.
	owner map[string]string
	// epoch is the highest roster epoch we have SEEN for a room, from anybody. It
	// exists to stamp outgoing rosters ahead of everyone else's, and it is not
	// the authority check.
	epoch map[string]uint64
	// ownerEpoch is the highest epoch from an accepted OWNER roster. Only the
	// owner's rosters are ordered, because only they can remove — and ordering
	// is exactly what a removal needs, so that replaying the roster from before
	// one cannot roll it back.
	ownerEpoch map[string]uint64
	// removed is who the owner has taken out of a room, and it is the reason
	// members' rosters need no ordering at all.
	//
	// Ordering members' rosters against the owner's looks like the obvious
	// defence and quietly breaks convergence: two people adding at the same
	// moment stamp the same epoch, neither having seen the other, and whichever
	// arrives second is discarded — one of the two newcomers silently missing
	// from everybody's list, which is the exact three-way bug this mechanism
	// exists to prevent, reintroduced by the replay defence.
	//
	// A tombstone is the honest shape instead. Removal is durable until the owner
	// says otherwise, so record it as durable state rather than inferring it from
	// message order. A member's roster then unions freely — replaying an old one
	// can only re-assert claims that member really made — and the one thing it
	// must never do, resurrect somebody the owner removed, is refused by name.
	removed map[string]map[string]bool
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
	delete(m.owner, cookie)
	delete(m.epoch, cookie)
	delete(m.ownerEpoch, cookie)
	delete(m.removed, cookie)
	m.mu.Unlock()
}

// addAll unions names into a room's set, skipping self and anyone the owner has
// removed.
//
// This is how any member's roster is applied: additive, because a member
// announcing "I invited Dave" is telling the truth about Dave and nothing at all
// about anybody else. Replacing on one would let any member drop any other by
// leaving them off, and would lose whoever somebody else invited concurrently.
func (m *roomMembers) addAll(cookie string, names []string, self string) {
	for _, n := range names {
		if state.NormalizeScreenName(n) == self || m.wasRemoved(cookie, n) {
			continue
		}
		m.add(cookie, n)
	}
}

// setAll replaces a room's set with names, skipping self.
//
// Only ever from the room's owner, who is the sole authority on who is NOT in a
// room. Anybody else's roster goes through addAll.
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

// pinOwner records a room's owner if we have not already, and reports who the
// owner is afterwards.
//
// Trust on first use, deliberately. There is nothing better available: the first
// thing we ever learn about a room comes from whoever invited us, and if they
// lied about the owner they could equally have invited us to a room of their own
// making. What TOFU does buy is that the answer cannot change afterwards without
// the pinned owner signing off, so a member cannot promote themselves later.
func (m *roomMembers) pinOwner(cookie, owner string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	if cur := m.owner[cookie]; cur != "" {
		return cur
	}
	norm := state.NormalizeScreenName(owner)
	if norm != "" {
		m.owner[cookie] = norm
	}
	return norm
}

func (m *roomMembers) ownerOf(cookie string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.owner[cookie]
}

// aheadOfOwner reports whether an epoch is ahead of the last one the room's
// owner set. Applies to the owner's own rosters; members' are not ordered.
func (m *roomMembers) aheadOfOwner(cookie string, e uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return e > m.ownerEpoch[cookie]
}

// tombstone records the owner's removals and lifts them for anyone the owner
// names as present — so re-inviting somebody works, and only the owner can do it.
func (m *roomMembers) tombstone(cookie string, gone, present []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	if m.removed[cookie] == nil {
		m.removed[cookie] = map[string]bool{}
	}
	for _, n := range gone {
		m.removed[cookie][state.NormalizeScreenName(n)] = true
	}
	for _, n := range present {
		delete(m.removed[cookie], state.NormalizeScreenName(n))
	}
}

// wasRemoved reports whether the owner has taken somebody out of a room.
func (m *roomMembers) wasRemoved(cookie, screenName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[cookie][state.NormalizeScreenName(screenName)]
}

// removedList is the tombstone set, for persistence.
func (m *roomMembers) removedList(cookie string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.removed[cookie]))
	for sn := range m.removed[cookie] {
		out = append(out, sn)
	}
	sort.Strings(out)
	return out
}

// acceptOwnerEpoch records an owner's roster as applied. Moves both counters:
// the owner's, which is the baseline, and the high-water mark used for stamping.
func (m *roomMembers) acceptOwnerEpoch(cookie string, e uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	if e > m.ownerEpoch[cookie] {
		m.ownerEpoch[cookie] = e
	}
	if e > m.epoch[cookie] {
		m.epoch[cookie] = e
	}
}

// noteEpoch records having seen an epoch without treating it as a baseline. A
// member's roster gets this: it must not become the floor other members' adds
// have to clear, or concurrent adds would knock each other out.
func (m *roomMembers) noteEpoch(cookie string, e uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	if e > m.epoch[cookie] {
		m.epoch[cookie] = e
	}
}

// nextEpoch is the epoch to stamp on a roster we are about to send. Ahead of
// everything we have seen, so ours is never mistaken for a replay of somebody
// else's, and claimed immediately so two of ours cannot collide.
func (m *roomMembers) nextEpoch(cookie string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	next := m.epoch[cookie] + 1
	if o := m.ownerEpoch[cookie]; o >= next {
		next = o + 1
	}
	m.epoch[cookie] = next
	return next
}

func (m *roomMembers) epochOf(cookie string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epoch[cookie]
}

func (m *roomMembers) ownerEpochOf(cookie string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ownerEpoch[cookie]
}

// ensure initializes the maps. Callers hold mu.
func (m *roomMembers) ensure() {
	if m.owner == nil {
		m.owner = map[string]string{}
	}
	if m.epoch == nil {
		m.epoch = map[string]uint64{}
	}
	if m.ownerEpoch == nil {
		m.ownerEpoch = map[string]uint64{}
	}
	if m.removed == nil {
		m.removed = map[string]map[string]bool{}
	}
}

func (m *roomMembers) restore(cookie, owner string, epoch, ownerEpoch uint64, removed []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	if len(removed) > 0 {
		if m.removed[cookie] == nil {
			m.removed[cookie] = map[string]bool{}
		}
		for _, n := range removed {
			m.removed[cookie][state.NormalizeScreenName(n)] = true
		}
	}
	if owner != "" {
		m.owner[cookie] = owner
	}
	if epoch > m.epoch[cookie] {
		m.epoch[cookie] = epoch
	}
	if ownerEpoch > m.ownerEpoch[cookie] {
		m.ownerEpoch[cookie] = ownerEpoch
	}
}

// roomsKey returns this account's room-file encryption key, minting and storing
// one on first use.
//
// Unlike the history key there is no "off" setting to respect: a room file that
// cannot be written means losing the ability to read or send in every encrypted
// room after a restart, so this is not optional. It still fails CLOSED — a
// keyring we cannot reach disables saving rather than writing key material in
// the clear, and it never replaces a stored key it merely failed to parse, since
// that would strand the file that key wrote.
func (a *App) roomsKey() *[32]byte {
	acct := a.currentAccount()
	if acct == "" {
		return nil
	}
	a.roomsKeyMu.Lock()
	defer a.roomsKeyMu.Unlock()
	if a.roomsKeyCache != nil {
		return a.roomsKeyCache
	}

	stored, err := secret.RetrieveRoomsKey(acct)
	if err != nil {
		slog.Default().Warn("could not read the room key file's key", "err", err)
		return nil
	}
	if stored != "" {
		raw, derr := base64.StdEncoding.DecodeString(stored)
		if derr == nil && len(raw) == 32 {
			var k [32]byte
			copy(k[:], raw)
			a.roomsKeyCache = &k
			return a.roomsKeyCache
		}
		slog.Default().Warn("the stored room-file key is unusable", "err", derr, "len", len(raw))
		return nil
	}

	k, err := roomkeys.NewKey()
	if err != nil {
		slog.Default().Warn("could not mint a room-file key", "err", err)
		return nil
	}
	if err := secret.StoreRoomsKey(acct, base64.StdEncoding.EncodeToString(k[:])); err != nil {
		slog.Default().Warn("could not store the room-file key", "err", err)
		return nil
	}
	a.roomsKeyCache = k
	return k
}

// saveRoomKeys persists a room's chain state, so a restart resumes sealing where
// it left off and can still read what it could before.
func (a *App) saveRoomKeys(cookie string) {
	acct := a.currentAccount()
	if acct == "" {
		return
	}
	key := a.roomsKey()
	if key == nil {
		slog.Default().Warn("not saving room keys: no usable encryption key")
		return
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return
	}

	store, err := roomkeys.Load(acct, key)
	if err != nil {
		// Do NOT fall back to an empty store: saving over a file we merely
		// failed to read would discard every room key it holds.
		slog.Default().Warn("could not read saved room keys; not saving", "err", err)
		return
	}

	// Wind old views forward before they reach disk. A view kept at the position
	// it was first given opens the room's whole life, which is what makes a
	// stolen room file valuable; nothing is lost, because scrollback comes from
	// the history file rather than from re-opening ciphertext.
	if moved := a.client.PruneChainViews(cookie); moved > 0 {
		slog.Default().Debug("wound room chain views forward", "room", cookie, "chains", moved)
	}
	out, views, seen, reserved, shared := a.client.RoomChainState(cookie)
	store[cookie] = roomkeys.Room{
		Name:            room.Name,
		Out:             out,
		ReservedThrough: reserved,
		Shared:          shared,
		Views:           views,
		Seen:            seen,
		Members:         a.members.list(cookie),
		Owner:           a.members.ownerOf(cookie),
		RosterEpoch:     a.members.epochOf(cookie),
		OwnerEpoch:      a.members.ownerEpochOf(cookie),
		Removed:         a.members.removedList(cookie),
		Updated:         time.Now(),
	}
	if joined, ok := a.roomJoinedAtTime(cookie); ok {
		entry := store[cookie]
		entry.JoinedAt = joined
		store[cookie] = entry
	}
	if err := roomkeys.Save(acct, store, key); err != nil {
		slog.Default().Warn("could not save room keys", "err", err)
	}
}

// persistRoomChain durably records a room's chain state, and reports whether it
// actually reached disk.
//
// saveRoomKeys is best-effort and logs its failures; a reservation cannot be,
// because a promise nobody made must not be acted on. Same work, an answer
// instead of a log line.
func (a *App) persistRoomChain(cookie string) error {
	acct := a.currentAccount()
	if acct == "" {
		return errors.New("no signed-on account")
	}
	key := a.roomsKey()
	if key == nil {
		return errors.New("no usable room-file encryption key")
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return errors.New("not in that room")
	}
	store, err := roomkeys.Load(acct, key)
	if err != nil {
		return err
	}
	out, views, seen, reserved, shared := a.client.RoomChainState(cookie)
	entry := roomkeys.Room{
		Name:            room.Name,
		Out:             out,
		ReservedThrough: reserved,
		Shared:          shared,
		Views:           views,
		Seen:            seen,
		Members:         a.members.list(cookie),
		Owner:           a.members.ownerOf(cookie),
		RosterEpoch:     a.members.epochOf(cookie),
		OwnerEpoch:      a.members.ownerEpochOf(cookie),
		Removed:         a.members.removedList(cookie),
		Updated:         time.Now(),
	}
	if joined, ok := a.roomJoinedAtTime(cookie); ok {
		entry.JoinedAt = joined
	}
	store[cookie] = entry
	return roomkeys.Save(acct, store, key)
}

// flushRoomKeys persists every joined encrypted room. Called on shutdown, which
// used to flush history and leave chain state entirely — so a CLEAN QUIT lost
// every position advanced since the last invite, and the next start resumed at
// an index already used.
func (a *App) flushRoomKeys() {
	for _, r := range a.store.Rooms() {
		if !r.Joined || !a.client.RoomEncrypted(r.Cookie) {
			continue
		}
		if err := a.persistRoomChain(r.Cookie); err != nil {
			slog.Default().Warn("could not flush room chain state", "room", r.Name, "err", err)
		}
	}
}

// restoreRoomKeys reinstalls saved chain state after sign-on.
//
// A room whose state we cannot decode is still marked encrypted — better to
// refuse to send than to quietly go plaintext into a room the user believes is
// private.
func (a *App) restoreRoomKeys() {
	acct := a.currentAccount()
	if acct == "" {
		return
	}
	key := a.roomsKey()
	if key == nil {
		slog.Default().Warn("could not restore room keys: no usable encryption key")
		return
	}
	store, err := roomkeys.Load(acct, key)
	if err != nil {
		slog.Default().Warn("could not load saved room keys", "err", err)
		return
	}
	for cookie, r := range store {
		a.client.RestoreChainState(cookie, r.Out, r.Views, r.Seen, r.ReservedThrough, r.Shared)
		for _, m := range r.Members {
			a.members.add(cookie, m)
		}
		a.members.restore(cookie, r.Owner, r.RosterEpoch, r.OwnerEpoch, r.Removed)
		if !r.JoinedAt.IsZero() {
			a.roomJoinMu.Lock()
			if a.roomJoinedAt == nil {
				a.roomJoinedAt = map[string]time.Time{}
			}
			a.roomJoinedAt[cookie] = r.JoinedAt
			a.roomJoinMu.Unlock()
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
	// Owner is who may remove people. Reported so the UI can withhold the
	// control rather than offer one the backend will refuse — and so the room
	// can say who to ask.
	Owner string `json:"owner"`
}

// RoomSecurityInfo reports a room's encryption state.
func (a *App) RoomSecurityInfo(cookie string) RoomSecurity {
	return RoomSecurity{
		Encrypted:  a.client.RoomEncrypted(cookie),
		Readable:   a.client.RoomReadable(cookie),
		NonReaders: a.client.RoomNonReaders(cookie),
		Members:    a.members.list(cookie),
		Owner:      a.members.ownerOf(cookie),
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
	// Marked encrypted and nothing more. The chain is minted and broadcast on
	// the first send, by the same path every other room uses — a shared key
	// here would be a second key model to keep alive for one code path.
	a.client.MarkRoomEncrypted(cookie)
	// Ours, and pinned now rather than at the first invite: the creator is the
	// owner, and the pin is what lets us sign removals later.
	a.members.pinOwner(cookie, a.currentAccount())
	a.noteRoomJoined(cookie)
	a.saveRoomKeys(cookie)
	a.store.Notify(state.NoticeInfo,
		"Encrypted room created. Nobody else can read it until you invite them.")
	return ""
}

// InviteToRoom gives somebody the chains they need to read a room, over the 1:1
// encrypted channel.
func (a *App) InviteToRoom(cookie, screenName string) string {
	screenName = strings.TrimSpace(screenName)
	if screenName == "" {
		return "Enter a screen name."
	}
	if !a.client.RoomEncrypted(cookie) {
		return "This room isn't encrypted, so there's nothing to share."
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return "You're not in that room."
	}
	// Recorded BEFORE distributing, so the roster that goes out already names
	// the newcomer — that is how the existing members learn about them.
	a.members.add(cookie, screenName)
	a.saveRoomKeys(cookie)

	// A bundle, not one chain. One chain would let them read only its owner;
	// what they need is every chain we can read, each wound forward to where the
	// conversation has got to — readable from here on, and not one message
	// before. ChainBundleFor does the winding.
	bundle := a.client.ChainBundleFor(cookie)
	if err := a.client.InviteToRoom(screenName, room.Name, bundle, a.encodedRoster(cookie, room.Name)); err != nil {
		// Nothing happened, so do not leave a member recorded who got nothing.
		a.members.remove(cookie, screenName)
		a.saveRoomKeys(cookie)
		return "Couldn't reach " + screenName + " — they haven't been invited."
	}

	// The people already here need only the new roster; they hold the chains
	// already. Without it their own broadcasts would leave the newcomer out.
	dropped := map[string]bool{state.NormalizeScreenName(screenName): true}
	if failed := a.distributeRoster(cookie, room.Name, dropped); len(failed) > 0 {
		a.store.Notify(state.NoticeWarn, "Invited "+screenName+", but couldn't tell "+
			strings.Join(failed, ", ")+" about it — their next re-key may miss people.")
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

// signedRoster builds and signs the current membership statement for a room.
//
// It claims the next epoch as it goes, so two of ours can never collide — the
// second would be read as a replay of the first and dropped.
func (a *App) signedRoster(cookie, roomName string) (e2ee.Roster, error) {
	self := state.NormalizeScreenName(a.currentAccount())
	if self == "" {
		return e2ee.Roster{}, errors.New("not signed on")
	}
	return e2ee.Roster{
		Room:    roomName,
		Epoch:   a.members.nextEpoch(cookie),
		Members: a.roomRoster(cookie),
		Owner:   a.members.pinOwner(cookie, self),
		Author:  self,
	}, nil
}

// encodedRoster is signedRoster rendered for the wire, ready to ride inside an
// invite. Empty on failure, which a recipient reads as "told us nothing".
func (a *App) encodedRoster(cookie, roomName string) string {
	r, err := a.signedRoster(cookie, roomName)
	if err != nil {
		return ""
	}
	body, err := a.client.SignRosterBody(r)
	if err != nil {
		slog.Default().Warn("could not sign a room roster", "room", roomName, "err", err)
		return ""
	}
	return body
}

// distributeRoster tells every member who else is in the room.
//
// One signed statement, sent twice over: an in-room broadcast so everybody
// present gets it in a single message, and 1:1 copies to anybody the broadcast
// cannot reach — a member who is offline, and who would otherwise never learn
// that somebody was removed. Applying one is idempotent, so arriving by both
// routes costs nothing.
//
// Only the ROSTER travels this way. Key material goes out as a single in-room
// broadcast on the send path (see Client.ensureRoomChainDistributed), so the
// expensive part of what used to happen here — one sealed message per member —
// is gone. What remains is small and still has to reach everybody, because a
// member with a stale roster leaves people out of their own broadcasts.
//
// Shared by invite, removal and reform so all three compute the roster
// identically; three call sites drifting into three ideas of who is in the room
// is the bug this exists to prevent.
func (a *App) distributeRoster(cookie, roomName string, dropped map[string]bool) []string {
	r, err := a.signedRoster(cookie, roomName)
	if err != nil {
		return nil
	}
	// The removed are not told. They would learn nothing they cannot see anyway,
	// but there is no reason to spend a message on it either — what actually
	// stops them reading is the chain they never receive.
	var tell []string
	for _, sn := range a.members.list(cookie) {
		if !dropped[sn] {
			tell = append(tell, sn)
		}
	}
	if err := a.client.SendRoster(r, tell); err != nil {
		slog.Default().Warn("could not distribute a room roster", "room", roomName, "err", err)
		return tell
	}
	return nil
}

// applyRoster decides whether an inbound roster has the authority to change what
// we believe about a room, and applies as much of it as it is entitled to.
//
// Four conditions, and each one closes something specific:
//
//  1. The signature verifies, and the author is who sent it. Checked upstream in
//     the client, because a roster we cannot authenticate should never get here.
//  2. The author is already a member. Reaching us over the encrypted 1:1 channel
//     proves nothing about room membership — peer keys are fetched on demand for
//     anybody — so without this a stranger who knows the room name signs a roster
//     naming the real owner, adds themselves, and every member's next chain
//     broadcast seals them a slot.
//  3. The roster names the owner we pinned. Otherwise a member promotes
//     themselves and starts removing people.
//  4. If the author IS the owner, the epoch is ahead of the last one they set.
//     Rolling a removal back is what an attacker would replay a roster to
//     achieve, and only the owner's rosters can remove.
//
// Then authority splits, and the split IS the design:
//
//   - **The owner's roster is authoritative.** It replaces the list outright,
//     which is the only way a removal can be expressed at all.
//   - **Anybody else's roster may only ADD.** Names it omits are left alone. Not
//     a refusal so much as a ceiling: a member announcing "I invited Dave" is
//     telling the truth about Dave and nothing at all about anyone else.
//
// Adding stays flat because gating it would buy nothing — you can only add
// somebody you can already reach, and they would learn the room name regardless.
// Removal is the asymmetric one. A flat model where any member may evict any
// other is not an access control, it is a griefing surface.
//
// **On concurrency.** Members' rosters are deliberately NOT ordered. Two people
// adding at the same moment stamp the same epoch, neither having seen the other,
// so any ordering rule discards one of them — a newcomer silently missing from
// everybody's list, which is the three-way bug this whole mechanism exists to
// prevent, reintroduced by the replay defence. What a member's roster must never
// do is resurrect somebody the owner removed, and that is refused by name rather
// than by ordering: see the tombstone set on roomMembers.
//
// And the part that makes removal bite: on an owner roster that SHRINKS, every
// recipient marks its OWN chain stale. That is what was missing when chains
// replaced the shared room key. Under a shared key the rotation message CARRIED
// the new key, so "I hold new key material" doubled as proof of authority and a
// removal propagated by accident; when the key went, the accident went with it,
// and everybody except the person who clicked Remove carried on sending on
// chains the removed member still held.
func (a *App) applyRoster(cookie string, r e2ee.Roster) {
	self := state.NormalizeScreenName(a.currentAccount())
	author := state.NormalizeScreenName(r.Author)

	owner := a.members.pinOwner(cookie, r.Owner)
	if state.NormalizeScreenName(r.Owner) != owner {
		slog.Default().Warn("ignoring a roster that names a different room owner",
			"room", r.Room, "pinned", owner, "claimed", r.Owner, "author", r.Author)
		return
	}
	if author != owner && author != self && !a.isRoomMember(cookie, author) {
		slog.Default().Warn("ignoring a roster from someone who is not in the room",
			"room", r.Room, "author", r.Author)
		return
	}
	staying := map[string]bool{}
	for _, n := range r.Members {
		staying[state.NormalizeScreenName(n)] = true
	}
	var shrinks bool
	for _, m := range a.members.list(cookie) {
		if !staying[m] {
			shrinks = true
			break
		}
	}

	if author != owner {
		// No epoch gate. A member's roster can only add, and it cannot resurrect
		// anyone the owner removed — the tombstone refuses that by name — so
		// there is nothing a replay of one can achieve, and ordering them would
		// cost convergence for nothing. See the note on roomMembers.removed.
		if shrinks {
			// Applied as an add anyway — its omissions simply carry no weight —
			// but said out loud, because somebody attempting it is worth knowing
			// about whether it was malice or a stale client.
			slog.Default().Warn("a non-owner's roster tried to remove people; adding only",
				"room", r.Room, "author", r.Author, "owner", owner)
			a.store.Notify(state.NoticeWarn, r.Author+" tried to remove people from “"+r.Room+
				"” but doesn't own it. Ignored.")
		}
		a.members.addAll(cookie, r.Members, self)
		a.members.noteEpoch(cookie, r.Epoch)
		a.saveRoomKeys(cookie)
		return
	}

	// The owner's, and the only kind that is ordered: rolling a removal back is
	// what an attacker would replay a roster to achieve.
	if !a.members.aheadOfOwner(cookie, r.Epoch) {
		slog.Default().Debug("ignoring a stale roster from the room's owner",
			"room", r.Room, "epoch", r.Epoch)
		return
	}
	var gone []string
	for _, m := range a.members.list(cookie) {
		if !staying[m] {
			gone = append(gone, m)
		}
	}
	a.members.tombstone(cookie, gone, r.Members)
	a.members.setAll(cookie, r.Members, self)
	a.members.acceptOwnerEpoch(cookie, r.Epoch)
	if shrinks {
		// Replaced lazily, before our next send: a chain nobody advances gives
		// the removed member nothing, so the earliest moment it matters is the
		// next thing we say.
		a.client.MarkChainStale(cookie)
	}
	a.saveRoomKeys(cookie)
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
		// Most of these carry no chains at all: an invite sent to somebody ELSE
		// goes round the room so everybody learns the new roster, and there is
		// nothing to announce about that. Chains arriving for a room we are
		// already in are somebody re-keying, which the room does not need told —
		// their broadcast is what actually delivers it.
		for _, v := range inv.Chains {
			a.client.LearnChainView(cookie, v)
		}
		// Chains and nothing else. An invite's roster is a BOOTSTRAP, for
		// somebody who is not in the room yet and has no other way to learn who
		// is; membership changes for a room we are already in arrive as signed
		// rosters in their own right.
		//
		// What used to be here was a guess — "chains present means the sender
		// re-keyed, so their roster replaces ours; otherwise it adds" — and the
		// guess was load-bearing for removal. It was also wrong in both
		// directions: any member's rotation could rewrite anyone's roster, and
		// an add could not remove even when it should.
		a.saveRoomKeys(cookie)
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
	// Every chain the inviter could read, each already wound forward to where
	// the conversation stands. We can read from here on and nothing before it,
	// which is the whole point of joining a room mid-conversation.
	a.client.MarkRoomEncrypted(cookie)
	for _, v := range inv.Chains {
		a.client.LearnChainView(cookie, v)
	}
	// `from` regardless: they are the one member we can be certain of, having
	// just heard from them over a channel authenticated to their key.
	a.members.add(cookie, from)
	// Then the signed roster, which names everyone else — knowing only the
	// person who invited us is what left three-way rooms unable to re-key. This
	// is where the room's owner and epoch get pinned, and it is trust on first
	// use: the first thing we ever learn about a room comes from whoever invited
	// us, and if they lied about the owner they could equally have invited us to
	// a room of their own making. What the pin buys is that it cannot change
	// afterwards without the pinned owner signing off.
	if r, ok := a.client.VerifiedRoster(from, inv.Roster); ok && r.Room == inv.Room {
		a.members.pinOwner(cookie, r.Owner)
		if state.NormalizeScreenName(r.Author) == state.NormalizeScreenName(r.Owner) {
			a.members.acceptOwnerEpoch(cookie, r.Epoch)
		} else {
			a.members.noteEpoch(cookie, r.Epoch)
		}
		a.members.addAll(cookie, r.Members, state.NormalizeScreenName(a.currentAccount()))
	} else if inv.Roster != "" {
		slog.Default().Warn("joined a room whose invite carried an unverifiable roster",
			"room", inv.Room, "from", from)
	}
	// From here, and not one message before it. The bundle grants exactly that,
	// and asking for history would fetch messages sealed at positions we cannot
	// derive — a screenful of "sent before you joined", which is the ratchet
	// working correctly presented as though something had broken.
	a.noteRoomJoined(cookie)
	a.saveRoomKeys(cookie)
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
	failed, errMsg := a.rekeyRoom(cookie, drop)
	if errMsg != "" {
		return errMsg
	}
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

// rekeyRoom drops the named members and marks our chain for replacement.
//
// Nothing is minted or sent here, and that is the design rather than an
// omission. Our chain is replaced LAZILY, before the next message we send: a
// chain nobody advances gives the removed member nothing, so the earliest point
// it matters is the next send, and a room where nobody speaks costs nothing.
// The replacement then goes out as one in-room broadcast, which the removed
// member receives like everybody else and can open nothing in.
//
// Says nothing to the user either. A removal somebody asked for and one
// triggered by a device disappearing elsewhere want very different words, and
// the second kind can affect several rooms at once where a notice each would be
// noise.
func (a *App) rekeyRoom(cookie string, drop []string) (failed []string, errMsg string) {
	if !a.client.RoomEncrypted(cookie) {
		return nil, "This room isn't encrypted."
	}
	room, ok := a.store.Room(cookie)
	if !ok {
		return nil, "You're not in that room."
	}
	// Refuse a removal we cannot make stick. Only the owner's shrink is honoured,
	// so a member clicking Remove would otherwise get "Room key rotated" while
	// every other client ignored the roster and carried on including the person
	// they thought they had removed — our chain replaced, and nobody else's.
	if len(drop) > 0 {
		self := state.NormalizeScreenName(a.currentAccount())
		if owner := a.members.pinOwner(cookie, self); owner != self {
			return nil, "Only " + owner + " can remove people from this room."
		}
	}

	dropped := map[string]bool{}
	for _, d := range drop {
		dropped[state.NormalizeScreenName(d)] = true
		a.members.remove(cookie, d)
	}
	// Tombstoned, not merely dropped. Without this the next roster any member
	// sends — built from a list that still names them — would put them straight
	// back, and the removal would last until the next message arrived.
	a.members.tombstone(cookie, drop, nil)

	a.client.MarkChainStale(cookie)
	a.saveRoomKeys(cookie)

	if len(dropped) == 0 {
		// Nobody left, so nobody's list is stale. This is the device-removal
		// path, where the chain needed replacing but membership did not change —
		// sending an identical roster to every member of every affected room
		// would be noise, and it would burn an epoch each time.
		return nil, ""
	}
	// The roster still has to reach everybody who remains: a member working from
	// a stale list leaves people out of their own broadcasts.
	return a.distributeRoster(cookie, room.Name, dropped), ""
}

// rotateRoomsAfterDeviceRemoval re-keys the encrypted rooms a removed device
// could still read.
//
// Room membership is by SCREEN NAME, and the key is sealed to every device an
// account publishes — so removing a device from an account takes nothing back
// from it. It keeps every room key it ever held, and OSCAR has no way to stop it
// rejoining a room whose name it knows. Rotation is the only thing that bounds
// what it reads next, which is the same reason removing a member triggers one.
//
// peer is the account that lost a device, or "" when it was ours — in which case
// every encrypted room we are in is affected, since our own removed device holds
// all of their keys. Bounds the future, not the past.
func (a *App) rotateRoomsAfterDeviceRemoval(peer string) {
	var done, failed []string
	for _, r := range a.store.Rooms() {
		if !r.Joined || !a.client.RoomEncrypted(r.Cookie) {
			continue
		}
		if peer != "" && !a.isRoomMember(r.Cookie, peer) {
			continue
		}
		unreachable, errMsg := a.rekeyRoom(r.Cookie, nil)
		if errMsg != "" {
			slog.Default().Warn("could not re-key a room after a device removal",
				"room", r.Name, "peer", peer, "err", errMsg)
			failed = append(failed, r.Name)
			continue
		}
		if len(unreachable) > 0 {
			slog.Default().Warn("re-keyed a room but could not reach everyone",
				"room", r.Name, "unreachable", unreachable)
		}
		done = append(done, r.Name)
	}
	if len(done) == 0 && len(failed) == 0 {
		return
	}

	who := "You removed a device"
	if peer != "" {
		who = peer + " removed a device"
	}
	if len(done) > 0 {
		a.store.Notify(state.NoticeInfo, who+", so "+strings.Join(done, ", ")+
			" got a new key — the removed device can't read what's said from now on. "+
			"What it already received stays readable to it.")
	}
	if len(failed) > 0 {
		a.store.Notify(state.NoticeWarn, who+", but "+strings.Join(failed, ", ")+
			" could not be re-keyed. Rotate those rooms by hand.")
	}
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
	// A brand new room gets a brand new chain, and nobody is carried into it
	// from the old one: reform exists precisely so the person left behind reads
	// nothing further, and reusing a chain they hold would defeat the point.
	view, _, err := a.client.EnsureOutboundChain(newCookie)
	if err != nil {
		return err.Error()
	}

	// Record everyone being carried over BEFORE distributing, so the roster each
	// of them receives already names all the others. Doing it as each invite
	// succeeded meant the first person invited was told the room contained only
	// themselves. Anyone unreachable is dropped again immediately below.
	for _, sn := range carry {
		a.members.add(newCookie, sn)
	}
	// It has genuinely been distributed below, 1:1, because the carried members
	// are not in the new room yet and a broadcast would not reach them. Saying
	// so is what lets the room be sent to: without it the next send found an
	// unshared chain, declined, and told the user to get re-invited to a room
	// they had just created.
	a.client.MarkChainShared(newCookie)
	a.noteRoomJoined(newCookie)

	roster := a.encodedRoster(newCookie, newName)
	for _, sn := range carry {
		// The full bundle 1:1, because they are not in the new room yet and an
		// in-room broadcast would not reach them.
		if err := a.client.InviteToRoom(sn, newName, []e2ee.ChainView{view}, roster); err != nil {
			slog.Default().Warn("could not invite to the reformed room", "peer", sn, "err", err)
			a.members.remove(newCookie, sn)
		}
	}
	a.saveRoomKeys(newCookie)

	// Leave the old room last, so we don't drop out before the invitations go.
	a.client.LeaveRoom(cookie)
	a.client.ForgetRoomKeys(cookie)
	a.members.forget(cookie)
	if acct := a.currentAccount(); acct != "" {
		if err := roomkeys.Forget(acct, cookie, a.roomsKey()); err != nil {
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

// noteRoomJoined records when we first entered a room, if we have not already.
//
// Only the FIRST time: this is the floor on what we may ask for, and moving it
// on every rejoin would mean a member who reconnects can never catch up on
// anything.
func (a *App) noteRoomJoined(cookie string) {
	a.roomJoinMu.Lock()
	if a.roomJoinedAt == nil {
		a.roomJoinedAt = map[string]time.Time{}
	}
	if _, seen := a.roomJoinedAt[cookie]; !seen {
		a.roomJoinedAt[cookie] = time.Now()
	}
	a.roomJoinMu.Unlock()
}

// roomJoinedAtTime returns when we joined a room, and whether we know.
func (a *App) roomJoinedAtTime(cookie string) (time.Time, bool) {
	a.roomJoinMu.Lock()
	defer a.roomJoinMu.Unlock()
	t, ok := a.roomJoinedAt[cookie]
	return t, ok
}

// roomLastSeen is how far back a catch-up request may reach.
//
// Bounded below by when we joined, which is the change chains force. Anything
// earlier was sealed at positions we cannot derive, so asking for it returns
// messages that render as "sent before you joined" — correct behaviour presented
// as a fault, and a request nobody benefits from.
//
// The old floor was a flat 24 hours, which for a fresh joiner meant being handed
// a day of conversation from before they arrived. That was the disclosure the
// ratchet exists to prevent, delivered by the layer above it.
func (a *App) roomLastSeen(cookie string) time.Time {
	floor, haveFloor := a.roomJoinedAtTime(cookie)

	room, ok := a.store.Room(cookie)
	if ok && len(room.Messages) > 0 {
		last := room.Messages[len(room.Messages)-1].At
		if !haveFloor || last.After(floor) {
			return last
		}
		return floor
	}
	if haveFloor {
		return floor
	}
	// A room we have no record of joining and no local messages for. Ask for a
	// day rather than everything, which would blow past the response size limit
	// and mostly be trimmed anyway.
	return time.Now().Add(-24 * time.Hour)
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
