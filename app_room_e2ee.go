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
	// epoch is the highest roster epoch WE have claimed for a room. It exists to
	// stamp our own outgoing rosters, and it is not the authority check.
	//
	// Deliberately not "the highest seen from anybody". Only the owner's rosters
	// are ordered, so a member's epoch means nothing to any recipient — but
	// feeding it into this counter handed every member a denial: one roster
	// stamped near 2^64 dragged our own stamps to the ceiling, the increment
	// wrapped to zero, and every roster we sent from then on read as a replay.
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

// nextEpoch is the epoch to stamp on a roster we are about to send. Ahead of
// everything we have stamped before and everything the owner has established,
// so ours is never mistaken for a replay, and claimed immediately so two of
// ours cannot collide.
//
// Saturating, never wrapping. A wrap to zero would be read everywhere as the
// oldest roster ever, and it would reset this counter so every later stamp
// repeats an epoch already spent. The only way to reach the ceiling is an owner
// SIGNING it — increments cannot get there — so saturation strands exactly the
// room whose owner jammed it, and nothing else.
func (m *roomMembers) nextEpoch(cookie string, now time.Time) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensure()
	cur := m.epoch[cookie]
	if o := m.ownerEpoch[cookie]; o > cur {
		cur = o
	}
	next := cur + 1
	if next == 0 {
		next = ^uint64(0)
	}
	// Floored at the wall clock, which is what lets an owner run two devices.
	//
	// Epochs only have to increase; nothing reads their value. Two devices of
	// the same account never see each other's rosters — SendRoster skips self,
	// and the server refuses a self-addressed message anyway — so each keeps its
	// own counter, and the second one to remove somebody stamps an epoch the
	// first already used. Every recipient discards it as stale, and the owner is
	// told the room was re-keyed. Seconds since the epoch are a counter both
	// devices already share without having to exchange anything.
	//
	// Still a strict increment on top: the clock is a FLOOR, never the value, so
	// two removals in the same second, or a clock that has gone backwards, still
	// produce increasing epochs rather than a collision or a rollback.
	if sec := now.Unix(); sec > 0 && uint64(sec) > next {
		next = uint64(sec)
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
	store[cookie] = a.mergedRoomEntry(cookie, room.Name, store[cookie])
	if err := roomkeys.Save(acct, store, key); err != nil {
		slog.Default().Warn("could not save room keys", "err", err)
	}
}

// mergedRoomEntry builds the entry to persist for a room, folding what is
// already on disk into what this session knows.
//
// A merge, never a plain replacement. restoreRoomKeys returns silently when the
// keyring is unreachable at sign-on, and if the keyring comes back mid-session
// the next save runs against in-memory state that never saw the file — a
// replacement would then write zero over the owner pin, both epoch high-water
// marks and every tombstone, re-arming each replay they exist to refuse. So the
// anti-rollback marks only ever ratchet, and a live value wins only where a
// live value exists.
func (a *App) mergedRoomEntry(cookie, name string, prev roomkeys.Room) roomkeys.Room {
	out, views, seen, reserved, shared := a.client.RoomChainState(cookie)
	entry := roomkeys.Room{
		Name:            name,
		Out:             out,
		ReservedThrough: reserved,
		Shared:          shared,
		Stale:           a.client.RoomChainStale(cookie),
		Views:           views,
		Seen:            seen,
		Members:         a.members.list(cookie),
		Owner:           a.members.ownerOf(cookie),
		RosterEpoch:     a.members.epochOf(cookie),
		OwnerEpoch:      a.members.ownerEpochOf(cookie),
		Removed:         a.members.removedList(cookie),
		JoinedAt:        prev.JoinedAt,
		Updated:         time.Now(),
	}
	if joined, ok := a.roomJoinedAtTime(cookie); ok {
		entry.JoinedAt = joined
	}

	// The owner pin: never erased, and never silently changed. A disagreement
	// means one of the two pins was established without the other's history,
	// and the earlier one is the one trust-on-first-use stands behind.
	if entry.Owner == "" {
		entry.Owner = prev.Owner
	} else if prev.Owner != "" && prev.Owner != entry.Owner {
		slog.Default().Warn("keeping the room owner already on disk over a conflicting live pin",
			"room", name, "disk", prev.Owner, "live", entry.Owner)
		entry.Owner = prev.Owner
	}
	if prev.RosterEpoch > entry.RosterEpoch {
		entry.RosterEpoch = prev.RosterEpoch
	}
	if prev.OwnerEpoch > entry.OwnerEpoch {
		entry.OwnerEpoch = prev.OwnerEpoch
	}
	entry.Removed = unionSorted(entry.Removed, prev.Removed)

	// Members are live state, not a ratchet — the list may genuinely shrink —
	// but an EMPTY live list on top of a non-empty saved one is the restore
	// having never run, not everyone having left. Either way nobody the merged
	// tombstones name may be written back as a member.
	if len(entry.Members) == 0 {
		entry.Members = prev.Members
	}
	entry.Members = withoutNames(entry.Members, entry.Removed)

	// Chain state likewise: live wins where live exists. No live chain plus a
	// chain on disk is, again, a restore that never ran — dropping it would
	// discard a reservation, and the next start could reuse positions.
	if entry.Out == "" && prev.Out != "" {
		entry.Out = prev.Out
		entry.ReservedThrough = prev.ReservedThrough
		entry.Shared = prev.Shared
		entry.Stale = prev.Stale
	}
	for id, v := range prev.Views {
		if _, held := entry.Views[id]; !held {
			if entry.Views == nil {
				entry.Views = map[string]string{}
			}
			entry.Views[id] = v
		}
	}
	for id, n := range prev.Seen {
		if n > entry.Seen[id] {
			if entry.Seen == nil {
				entry.Seen = map[string]uint32{}
			}
			entry.Seen[id] = n
		}
	}
	return entry
}

// unionSorted merges two name lists, normalized and deduplicated.
func unionSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, n := range a {
		set[state.NormalizeScreenName(n)] = true
	}
	for _, n := range b {
		set[state.NormalizeScreenName(n)] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// withoutNames filters drop out of names, comparing normalized.
func withoutNames(names, drop []string) []string {
	gone := map[string]bool{}
	for _, n := range drop {
		gone[state.NormalizeScreenName(n)] = true
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !gone[state.NormalizeScreenName(n)] {
			out = append(out, n)
		}
	}
	return out
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
	store[cookie] = a.mergedRoomEntry(cookie, room.Name, store[cookie])
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
		a.applyRoomEntry(cookie, r)
	}
}

// applyRoomEntry reinstalls one room's persisted state. Split from
// restoreRoomKeys so the reinstallation rules are testable without an OS
// keyring in the loop.
func (a *App) applyRoomEntry(cookie string, r roomkeys.Room) {
	a.client.RestoreChainState(cookie, r.Out, r.Views, r.Seen, r.ReservedThrough, r.Shared)
	if r.Stale {
		// The removal happened; the replacement chain had not been minted yet.
		// Without re-marking, the restored chain came back looking usable and
		// the next send sealed on the chain the removed member still holds.
		a.client.MarkChainStale(cookie)
	}
	// Tombstones first, members second: addAll refuses removed names, and a
	// file whose lists disagree must resolve in the removal's favour.
	a.members.restore(cookie, r.Owner, r.RosterEpoch, r.OwnerEpoch, r.Removed)
	a.members.addAll(cookie, r.Members, state.NormalizeScreenName(a.currentAccount()))
	if !r.JoinedAt.IsZero() {
		a.roomJoinMu.Lock()
		if a.roomJoinedAt == nil {
			a.roomJoinedAt = map[string]time.Time{}
		}
		a.roomJoinedAt[cookie] = r.JoinedAt
		a.roomJoinMu.Unlock()
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
	owner := a.members.ownerOf(cookie)
	if owner == "" {
		// No pin means no roster can be signed or judged, so an invite from here
		// would hand out chains with a membership claim nobody can verify —
		// exactly the bootstrap that lets a stranger's roster stick.
		return "This room has no confirmed owner yet, so nobody can be invited from here. " +
			"Ask whoever invited you to re-send the invitation."
	}
	self := state.NormalizeScreenName(a.currentAccount())
	liftedTombstone := false
	if a.members.wasRemoved(cookie, screenName) {
		// The tombstone is the owner's statement, and only the owner unsays it.
		// Anybody's invite silently restoring a removed member — with a chain
		// bundle wound to the present — was precisely how a removal came undone
		// without any other member ever hearing about it.
		if owner != self {
			return "Only " + owner + " can re-invite " + screenName + " — they were removed from this room."
		}
		// Lifted BEFORE the roster is built, so the statement that goes out no
		// longer names them removed; re-laid below if the invite never lands.
		a.members.tombstone(cookie, nil, []string{screenName})
		liftedTombstone = true
	}
	// Recorded BEFORE distributing, so the roster that goes out already names
	// the newcomer — that is how the existing members learn about them.
	a.members.add(cookie, screenName)
	a.saveRoomKeys(cookie)

	// A bundle, not one chain. One chain would let them read only its owner;
	// what they need is every chain we can read, each wound forward to where the
	// conversation has got to — readable from here on, and not one message
	// before. ChainBundleFor does the winding.
	bundle := a.client.ChainBundleFor(cookie, screenName)
	if err := a.client.InviteToRoom(screenName, room.Name, bundle, a.encodedRoster(cookie, room.Name)); err != nil {
		// Nothing happened, so do not leave a member recorded who got nothing —
		// or a removal lifted for somebody who was never readmitted.
		a.members.remove(cookie, screenName)
		if liftedTombstone {
			a.members.tombstone(cookie, []string{screenName}, nil)
		}
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
//
// It refuses a room with no pinned owner rather than pinning ourselves. The pin
// used to be a side effect here, which meant a member of a room whose invite
// arrived rosterless quietly installed THEMSELVES as owner on their first
// invite — and the real owner's every roster was rejected from then on.
func (a *App) signedRoster(cookie, roomName string) (e2ee.Roster, error) {
	self := state.NormalizeScreenName(a.currentAccount())
	if self == "" {
		return e2ee.Roster{}, errors.New("not signed on")
	}
	owner := a.members.ownerOf(cookie)
	if owner == "" {
		return e2ee.Roster{}, errors.New("no owner is pinned for this room")
	}
	r := e2ee.Roster{
		Room:    roomName,
		Epoch:   a.members.nextEpoch(cookie, time.Now()),
		Members: a.roomRoster(cookie),
		Owner:   owner,
		Author:  self,
	}
	if self == owner {
		// The full tombstone set rides on every roster of ours, so a member who
		// missed the removal itself still learns of it from the next one.
		r.Removed = a.members.removedList(cookie)
		// Our own stamp is an owner epoch. We never receive our own rosters —
		// SendRoster skips self — so without recording it here the persisted
		// owner high-water mark stayed at zero for the one account whose
		// rollback matters most, and a replay of our own old roster walked in.
		a.members.acceptOwnerEpoch(cookie, r.Epoch)
	}
	return r, nil
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
//
// Returns the members the roster genuinely did not reach — them and only them.
// Reporting the whole list on any failure told the user to re-invite people who
// had received the roster perfectly well, while saying nothing useful about the
// ones who hadn't.
func (a *App) distributeRoster(cookie, roomName string, skip map[string]bool) []string {
	// skip is who not to SEND to — someone told by other means (the invite
	// itself) or someone just removed. The removed learn nothing they cannot
	// see anyway; what actually stops them reading is the chain they never
	// receive.
	var tell []string
	for _, sn := range a.members.list(cookie) {
		if !skip[sn] {
			tell = append(tell, sn)
		}
	}
	r, err := a.signedRoster(cookie, roomName)
	if err != nil {
		// Nothing can be sent at all, so everybody who needed telling is
		// un-told — that IS the failure set.
		slog.Default().Warn("could not build a room roster", "room", roomName, "err", err)
		return tell
	}
	failed, err := a.client.SendRoster(r, tell)
	if err != nil {
		slog.Default().Warn("could not distribute a room roster", "room", roomName, "err", err)
		return tell
	}
	return failed
}

// applyRoster decides whether an inbound roster has the authority to change what
// we believe about a room, and applies as much of it as it is entitled to.
//
// Five conditions, and each one closes something specific:
//
//  1. The signature verifies, and the author is who sent it. Checked upstream in
//     the client, because a roster we cannot authenticate should never get here.
//  2. An owner IS pinned. A roster can only be judged against a pin that some
//     path with real authority established — creating the room, or the verified
//     roster inside the invitation that got us in. Pinning from the roster under
//     judgment, which is what used to happen, let the first stranger to name
//     themselves owner of an unpinned room become its owner for good.
//  3. The author is already a member. Reaching us over the encrypted 1:1 channel
//     proves nothing about room membership — peer keys are fetched on demand for
//     anybody — so without this a stranger who knows the room name signs a roster
//     naming the real owner, adds themselves, and every member's next chain
//     broadcast seals them a slot.
//  4. The roster names the owner we pinned. Otherwise a member promotes
//     themselves and starts removing people.
//  5. If the author IS the owner, the epoch is ahead of the last one they set.
//     Rolling a removal back is what an attacker would replay a roster to
//     achieve, and only the owner's rosters can remove.
//
// Then authority splits, and the split IS the design:
//
//   - **The owner's roster is authoritative.** It replaces the list outright,
//     and its signed Removed set is what lays tombstones. An omission alone does
//     NOT tombstone: the owner may simply never have learned of a concurrent
//     invite, and the next member roster puts that person back — whereas a name
//     the owner REMOVED must stay gone, which is exactly the difference between
//     the two.
//   - **Anybody else's roster may only ADD.** Names it omits are left alone, and
//     its Removed set carries no weight. Not a refusal so much as a ceiling: a
//     member announcing "I invited Dave" is telling the truth about Dave and
//     nothing at all about anyone else.
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
// And the part that makes removal bite: on an owner roster whose REMOVED SET
// names somebody new, every recipient marks its OWN chain stale. That is what
// was missing when chains replaced the shared room key. Under a shared key the
// rotation message CARRIED the new key, so "I hold new key material" doubled as
// proof of authority and a removal propagated by accident; when the key went,
// the accident went with it, and everybody except the person who clicked Remove
// carried on sending on chains the removed member still held.
//
// The trigger is the SIGNED removed set, not a diff against our own list. The
// diff cannot say "D was removed" to a recipient who never learned D existed —
// and that recipient may hold exactly the chains D can read, because an invite
// hands a newcomer every chain the inviter holds while the roster announcing
// them travels separately and can fail. The removed set reaches everyone the
// roster reaches, whatever they knew before.
func (a *App) applyRoster(cookie string, r e2ee.Roster) {
	self := state.NormalizeScreenName(a.currentAccount())
	author := state.NormalizeScreenName(r.Author)

	owner := a.members.ownerOf(cookie)
	if owner == "" {
		// Refused, never pinned. Establishing the pin from the roster being
		// judged let a stranger name themselves owner of any room that had none
		// — every room joined by name, and every invite whose roster could not
		// be verified — then tombstone the real members and collect the next
		// chain by attrition.
		slog.Default().Warn("refusing a roster for a room with no pinned owner",
			"room", r.Room, "claimed_owner", r.Owner, "author", r.Author)
		return
	}
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

	if author != owner {
		// No epoch gate. A member's roster can only add, and it cannot resurrect
		// anyone the owner removed — the tombstone refuses that by name — so
		// there is nothing a replay of one can achieve, and ordering them would
		// cost convergence for nothing. See the note on roomMembers.removed.
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
		if shrinks || len(r.Removed) > 0 {
			// Applied as an add anyway — its omissions and removals simply carry
			// no weight — but said out loud, because somebody attempting it is
			// worth knowing about whether it was malice or a stale client.
			slog.Default().Warn("a non-owner's roster tried to remove people; adding only",
				"room", r.Room, "author", r.Author, "owner", owner)
			a.store.Notify(state.NoticeWarn, r.Author+" tried to remove people from “"+r.Room+
				"” but doesn't own it. Ignored.")
		}
		a.members.addAll(cookie, r.Members, self)
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
	// The removed set is the full tombstone list at this epoch, so most of it is
	// usually old news. Only a name we have not already tombstoned means a
	// removal happened since our chain was last replaced — retiring it for
	// names already processed would re-key the room on every owner roster.
	var newlyRemoved []string
	for _, n := range r.Removed {
		if !a.members.wasRemoved(cookie, n) {
			newlyRemoved = append(newlyRemoved, n)
		}
	}
	a.members.tombstone(cookie, r.Removed, r.Members)
	a.members.setAll(cookie, r.Members, self)
	a.members.acceptOwnerEpoch(cookie, r.Epoch)
	if len(newlyRemoved) > 0 {
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

	// The roster is verified BEFORE joining, because it is the only thing that
	// can ever pin the room's owner. Joining anyway when it did not verify —
	// which the old code did, with a warning in the log — left the room pinless
	// for good, and a pinless room used to hand ownership to the first roster
	// that named one. The common cause is benign timing: the inviter's signing
	// keys have not landed yet. Fetch them and try once more before refusing.
	r, verified := a.client.VerifiedRoster(from, inv.Roster)
	if !verified && inv.Roster != "" {
		a.client.EnsurePeerKeys(from)
		r, verified = a.client.VerifiedRoster(from, inv.Roster)
	}
	if verified && !sameRoomName(r.Room, inv.Room) {
		// Signed for a different room than the invite claims. Somebody is
		// splicing invitations; treat the roster as worthless.
		slog.Default().Warn("an invite's roster is signed for a different room",
			"invite", inv.Room, "roster", r.Room, "from", from)
		verified = false
	}
	if !verified && inv.Roster != "" {
		// Deferred, not abandoned: the invitation goes back in the queue so the
		// user can try again once the inviter's keys are fetchable.
		a.pendingMu.Lock()
		a.pendingInvites[inv.Room] = inv
		a.pendingInviteFrom[inv.Room] = from
		a.pendingMu.Unlock()
		return "Couldn't verify who runs “" + inv.Room + "”, so the invitation wasn't accepted. " +
			"Try again in a moment — " + from + "'s keys may still be on their way."
	}

	if err := a.client.JoinRoom(inv.Room); err != nil {
		return err.Error()
	}
	cookie, found := a.roomCookieByName(inv.Room)
	if !found {
		return "Joined but couldn't identify the room."
	}
	a.adoptInviteState(cookie, from, inv, r, verified)
	// From here, and not one message before it. The bundle grants exactly that,
	// and asking for history would fetch messages sealed at positions we cannot
	// derive — a screenful of "sent before you joined", which is the ratchet
	// working correctly presented as though something had broken.
	a.noteRoomJoined(cookie)
	a.saveRoomKeys(cookie)
	return ""
}

// adoptInviteState installs what an accepted invitation tells us about a room.
// Split from AcceptRoomInvite so the pinning rules are testable without a live
// join in the loop.
func (a *App) adoptInviteState(cookie, from string, inv e2ee.RoomInvite, r e2ee.Roster, verified bool) {
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
	if !verified {
		// An invite with no roster at all — an older client's, or the inviter
		// could not sign one. The room joins without an owner pin, which
		// applyRoster and rekeyRoom treat as "no membership authority exists":
		// no roster is accepted, nobody can be invited or removed from here.
		// Degraded on purpose — the alternative was accepting the first claim of
		// ownership to arrive, from anybody.
		slog.Default().Warn("joined a room whose invite carried no verifiable roster; "+
			"no owner is pinned and rosters will be refused", "room", inv.Room, "from", from)
		a.store.Notify(state.NoticeWarn, "“"+inv.Room+"” was joined without a verifiable member list. "+
			"You can read and send, but invitations and removals won't work — ask "+from+
			" to invite you again if that changes.")
		return
	}
	// The signed roster names everyone else — knowing only the person who
	// invited us is what left three-way rooms unable to re-key. This is where
	// the room's owner gets pinned, and it is trust on first use: the first
	// thing we ever learn about a room comes from whoever invited us, and if
	// they lied about the owner they could equally have invited us to a room of
	// their own making. What the pin buys is that it cannot change afterwards
	// without the pinned owner signing off.
	a.members.pinOwner(cookie, r.Owner)
	if state.NormalizeScreenName(r.Author) == state.NormalizeScreenName(r.Owner) {
		a.members.acceptOwnerEpoch(cookie, r.Epoch)
		// The owner's tombstones bootstrap with the membership, so a member the
		// owner removed cannot be handed back to us as a fresh face by the next
		// member roster we see.
		a.members.tombstone(cookie, r.Removed, r.Members)
	}
	a.members.addAll(cookie, r.Members, state.NormalizeScreenName(a.currentAccount()))
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
		// Name exactly who was not told, and say what that means: an un-told
		// member keeps broadcasting on chains the removed person still holds, so
		// the removal has not fully taken. "Re-invite them" — the old advice —
		// was wrong twice over: they are still members, and inviting them again
		// does not deliver the roster they missed.
		a.store.Notify(state.NoticeWarn, "Removed them, but "+strings.Join(failed, ", ")+
			" couldn't be told. Until they hear, messages THEY send may still be readable "+
			"by whoever was removed. Remove the same person again once everyone is online "+
			"to re-send the update.")
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
	// Refuse a removal we cannot make stick. Only the owner's removals are
	// honoured, so a member clicking Remove would otherwise get "Room key
	// rotated" while every other client ignored the roster and carried on
	// including the person they thought they had removed — our chain replaced,
	// and nobody else's.
	//
	// A plain lookup, never pinOwner: pinning here made this guard install the
	// CALLER as owner of any room that had none — the exact seizure it exists to
	// refuse — and mis-pinned durably, so the real owner's rosters were rejected
	// from then on.
	if len(drop) > 0 {
		self := state.NormalizeScreenName(a.currentAccount())
		switch owner := a.members.ownerOf(cookie); {
		case owner == "":
			return nil, "This room has no confirmed owner, so nobody can be removed from it. " +
				"Reform the room instead to leave someone behind."
		case owner != self:
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
	// Ours, same as CreateEncryptedRoom: reform mints a new room and the person
	// who minted it owns it. Explicit now — this pin used to happen as a side
	// effect of signing the first roster, which is the mutating pattern that
	// let unauthorized paths pin owners too.
	a.members.pinOwner(newCookie, a.currentAccount())
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
	for _, r := range a.store.Rooms() {
		if sameRoomName(r.Name, name) && r.Joined {
			return r.Cookie, true
		}
	}
	return "", false
}

// sameRoomName is the one rule for matching room names: case folded, outer
// whitespace trimmed, interior spaces KEPT. Screen-name normalization strips
// interior spaces, and using it for rooms made "Team Chat" and "teamchat" the
// same room — wider than the exact string a roster's signature covers.
func sameRoomName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
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
