package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/roomkeys"
	"github.com/benco-holdings/benchat/internal/state"
)

// Furnishing a newly linked device — K7.
//
// A device that has just been linked has an account, an identity and a place in
// the manifest, and nothing else: no history, and no room chains, so every
// encrypted room reads as ciphertext and every conversation opens blank. Nothing
// on the server can fix that, deliberately — it holds neither, which is the
// property the whole design is for. The only thing that can furnish a new device
// is an old one.
//
// This is the transport-independent half: build a bundle, apply a bundle. What
// carries it between the two machines — a file the user moves, or a direct
// connection — is a separate question, and both ends of it look identical from
// here. The file is what exists today because it works over any channel the user
// already has and adds no listening socket to a client that currently makes only
// outbound connections.
//
// The bundle's signature answers exactly one question — did another of this
// account's devices build this? — and that is a smaller grant than it reads. A
// device on the account can already speak AS the account; what it must never get
// from a transfer is the power to speak as anyone else — not as a peer whose
// words it is retelling, not as a room owner whose roster rules it never passed.
// So a transfer carries CONTENT and never VERDICTS: verification badges,
// membership authority, epochs, tombstones and the owner pin are all either
// recomputed on arrival or re-learned from the parties who can actually prove
// them. Everything below that looks like a restriction is this one rule applied.

// transferPayload is what actually travels.
//
// Note what is NOT here. The outbound chain never travels, because a chain is a
// position counter and two devices sending on one would seal two different
// messages at the same position under the same key; the receiving device mints
// its own. Nor does the identity key, which is not ours to move — it lives in a
// server-side backup under the recovery phrase and is held only transiently even
// on the device that uses it.
type transferPayload struct {
	Version int    `json:"version"`
	Account string `json:"account"`

	// Conversations and Rooms are the history file's contents. Their trust
	// markers are recomputed on arrival — see sanitizeTransferredMessage.
	Conversations []state.Conversation `json:"conversations,omitempty"`
	Rooms         []state.Room         `json:"rooms,omitempty"`

	// RoomState is per-room chain state, keyed by room cookie. Deliberately NOT
	// roomkeys.Room: that struct holds the outbound chain, the owner pin, the
	// epochs, the tombstones and the seen positions, none of which a transfer
	// is entitled to assert. A type that cannot express them is a stronger
	// guarantee than stripping them at both ends and hoping nobody adds a field.
	RoomState map[string]transferRoom `json:"roomState,omitempty"`
}

// transferPayloadVersion is 2. Version 1 put roomkeys.Room on the wire
// wholesale, which let a bundle assert everything that struct records — an
// owner, an epoch, a removal — with none of the signatures those records rest
// on. A v1 bundle is refused by the version check rather than partially honoured.
const transferPayloadVersion = 2

// transferRoom is the per-room state a transfer may carry, which is much less
// than the room file holds. What is absent is absent on purpose:
//
//   - The outbound chain, its reservation and its Shared flag. A chain is a
//     position counter; two devices advancing one seal two messages at the
//     same index under the same key. v1 carried the whole Room struct and
//     stripped these three fields at both ends — this type cannot express
//     them, so there is nothing to forget to strip.
//   - Seen. It merges by max, and everything downstream of it is one-way:
//     PruneChainViews winds views forward off it and ChainBundleFor starts
//     invites at it, so a poisoned value either destroys the ability to read a
//     peer or hands a future invitee history nobody observed. The receiver
//     rebuilds its own from traffic it actually authenticates — until then it
//     simply has nothing to put in an invite, which is the honest position.
//   - Owner, both epochs, and the tombstones. All three are CONCLUSIONS of
//     applyRoster's authority rules — a pinned owner, an accepted owner
//     signature, an ordered removal — and the bundle carries none of the
//     signatures those conclusions rest on. Importing the numbers without the
//     evidence hands a compromised device exactly what the roster rules deny
//     it: a durable removal, an owner pin planted before the real invite
//     arrives, or an epoch nothing can ever climb past — which silently
//     discards every future owner roster, removals included, forever. The
//     receiver re-learns all of it from signed rosters, which is where the
//     sender learnt it too.
//
// Members DO travel, because they carry exactly a member's weight and no more:
// the sending device could put the same names in a signed roster of its own and
// every client would union them in, so the transfer granting the same adds no
// power — and the receiver needs some idea of the room to distribute its first
// chain to. They are applied under the same ceiling applyRoster puts on any
// member: adds only, never past our own tombstones.
type transferRoom struct {
	Name     string            `json:"name"`
	Views    map[string]string `json:"views,omitempty"`
	Members  []string          `json:"members,omitempty"`
	JoinedAt time.Time         `json:"joinedAt,omitempty"`
}

// deviceBoxKey returns the box key of one of this account's devices, by signing
// key ID, from the VERIFIED manifest.
//
// The manifest and nothing else. That is the whole access control here: a device
// listed in it is one somebody deliberately put there, because publishing
// requires signing with the account's identity key.
func (a *App) deviceBoxKey(signerID string) ([32]byte, bool) {
	a.trustMu.Lock()
	memo, have := a.manifestSeen[state.NormalizeScreenName(a.currentAccount())]
	a.trustMu.Unlock()
	if !have {
		return [32]byte{}, false
	}
	for _, d := range memo.devices {
		if len(d.Sign) > 0 && e2ee.SignerID(d.Sign) == signerID {
			return d.Box, true
		}
	}
	return [32]byte{}, false
}

// otherDeviceKeys returns the signing and box keys of every device on this
// account EXCEPT the one named, from the verified manifest.
//
// Ours is left out when checking an inbound transfer — not for safety, since a
// bundle we made is one we already have, but because including it would let a
// corrupted local state verify against itself.
func (a *App) otherDeviceKeys(exceptID string) ([]ed25519.PublicKey, [][32]byte) {
	a.trustMu.Lock()
	memo, have := a.manifestSeen[state.NormalizeScreenName(a.currentAccount())]
	a.trustMu.Unlock()
	if !have {
		return nil, nil
	}
	var (
		signs []ed25519.PublicKey
		boxes [][32]byte
	)
	for _, d := range memo.devices {
		if len(d.Sign) == 0 || e2ee.SignerID(d.Sign) == exceptID {
			continue
		}
		signs = append(signs, d.Sign)
		boxes = append(boxes, d.Box)
	}
	return signs, boxes
}

// confirmDeviceSet re-reads and re-verifies the account's manifest, so that
// whatever follows runs against the device list as it stands rather than as it
// stood at sign-on.
//
// The manifest memo has no expiry — written at sign-on and on publish, then
// trusted indefinitely. That is tolerable for choosing whom to seal one chat
// message to, where a removed device costs one message and a rotation is
// already underway, and not tolerable here, where the payload is everything the
// account ever said. Failure refuses rather than proceeds: a transfer built
// against yesterday's device list is the leak itself, not a degraded mode.
func (a *App) confirmDeviceSet(account string) error {
	if a.keyDir == nil || !a.keyDir.SupportsKeyDir() {
		return errors.New("this server has no key directory, so the device list can't be confirmed")
	}
	sm, ok := a.keyDir.QueryManifest(account)
	if !ok {
		return errors.New("the key directory didn't answer, so the device list can't be confirmed — try again in a moment")
	}
	if _, ok := a.verifyManifest(sm); !ok {
		return errors.New("the account's device list doesn't verify right now, so a transfer can't be checked against it")
	}
	return nil
}

// BuildDeviceTransfer produces a bundle for another of this account's devices,
// named by its signing key ID.
//
// The recipient's keys come from the account's VERIFIED manifest and nowhere
// else. That is the entire access control: a device in the manifest is one
// somebody deliberately put there, because publishing requires signing with the
// identity key, which is unwrapped with the recovery phrase. Taking the key from
// anywhere a user could paste it — a code, a hostname, a handshake — would turn
// this into a way to hand an account's history to whoever asked.
func (a *App) BuildDeviceTransfer(recipientID string) (string, error) {
	account := a.currentAccount()
	if account == "" {
		return "", errors.New("sign in first")
	}
	signer, hasSigner := a.client.SigningKeyPair()
	if !hasSigner {
		return "", errors.New("this device has no signing key, so it can't vouch for a transfer")
	}
	ourPriv, hasBox := a.client.EncryptionPrivateKey()
	if !hasBox {
		return "", errors.New("this device has no encryption key")
	}
	// The directory is asked NOW, not at sign-on. "Seal the account's entire
	// history to this device" is the single worst call to make on a stale list:
	// a device removed an hour ago stayed in the memo, and TransferTargets kept
	// offering it.
	if err := a.confirmDeviceSet(account); err != nil {
		return "", err
	}

	recipientBox, ok := a.deviceBoxKey(recipientID)
	if !ok {
		return "", errors.New("that device isn't in this account's device list — link it first")
	}

	payload, err := json.Marshal(a.transferPayload(account))
	if err != nil {
		return "", fmt.Errorf("could not assemble the transfer: %w", err)
	}
	sealed, err := e2ee.SealTransfer(state.NormalizeScreenName(account), recipientID,
		recipientBox, payload, ourPriv, signer, time.Now().Unix())
	if err != nil {
		return "", err
	}
	return e2ee.EncodeTransfer(sealed)
}

// transferPayload assembles what travels.
func (a *App) transferPayload(account string) transferPayload {
	p := transferPayload{
		Version:       transferPayloadVersion,
		Account:       state.NormalizeScreenName(account),
		Conversations: a.store.Conversations(),
	}

	// Room state comes off DISK rather than out of the live client, so a room
	// the user is not currently joined to still travels. The saved copy is also
	// the one whose chain positions are already reserved, which is the only
	// version safe to hand anybody.
	encrypted := map[string]bool{}
	if key := a.roomsKey(); key != nil {
		store, err := roomkeys.Load(account, key)
		if err != nil {
			slog.Default().Warn("could not read room state for a transfer", "err", err)
		} else {
			p.RoomState = make(map[string]transferRoom, len(store))
			for cookie, r := range store {
				p.RoomState[cookie] = transferRoomState(r)
				encrypted[cookie] = true
			}
		}
	}

	// Room history travels only for the rooms whose encrypted state travels
	// with it. The receiver marks every transferred room message as encrypted-
	// without-envelope so catch-up will never relay it (see
	// sanitizeTransferredRoomMessage), and shipping a plaintext room's
	// scrollback under that rule would only mislabel it for no read-back gain.
	rooms := a.store.Rooms()
	p.Rooms = make([]state.Room, 0, len(rooms))
	for _, r := range rooms {
		if !encrypted[r.Cookie] {
			r.Messages = nil
		}
		r.Participants = nil // occupancy is live server state, not history
		p.Rooms = append(p.Rooms, r)
	}
	return p
}

// transferRoomState reduces one room's saved state to what a transfer may carry.
//
// The views are wound forward to seen+1 — the same entitlement ChainBundleFor
// hands a newcomer, and for the same reason. A stored view sits at the EARLIEST
// position we may read so that our own scrollback opens; handing that over
// while the receiver's Seen starts empty was the leak: the receiver typically
// never joins the room (room state travels off disk precisely so unjoined
// rooms travel), so its Seen never advances, and anyone it later invited was
// granted read-back from our earliest position — conversation from before that
// invitee existed. Nothing is lost by winding: the plaintext travels in the
// history half of this same bundle, and a view's only remaining job on the new
// device is opening ciphertext that arrives AFTER it.
//
// A chain with no seen entry is dropped rather than shipped unwound — the same
// fail-closed rule ChainBundleFor applies, because "we do not know where this
// chain has got to" cannot be wound to now.
//
// Our own chain's view goes through the same winding as everyone else's, which
// means what ships for it is the chain's CURRENT state — the exact bytes
// EncodeChain would store for the live chain, since the two encodings are
// byte-identical today. Nothing may ever migrate a shipped view into a room's
// Out: that would put two devices on one position counter.
func transferRoomState(r roomkeys.Room) transferRoom {
	out := transferRoom{Name: r.Name, Members: r.Members, JoinedAt: r.JoinedAt}
	if len(r.Views) == 0 {
		return out
	}
	out.Views = make(map[string]string, len(r.Views))
	for id, enc := range r.Views {
		v, err := e2ee.DecodeChainView(enc)
		if err != nil || v.ID != id {
			continue
		}
		n, known := r.Seen[id]
		if !known {
			continue
		}
		// uint64 so a wrapped position cannot turn the +1 back into an unwound
		// view — the same guard ChainBundleFor grew for the same reason.
		target := uint64(n) + 1
		if target > uint64(^uint32(0)) {
			continue
		}
		if uint32(target) > v.Index {
			wound, ok := v.Advance(uint32(target))
			if !ok {
				continue // too far to hash; fail closed rather than ship read-back
			}
			v = wound
		}
		out.Views[id] = e2ee.EncodeChainView(v)
	}
	return out
}

// ApplyDeviceTransfer opens a bundle another of our devices made and installs it.
func (a *App) ApplyDeviceTransfer(body string) error {
	account := a.currentAccount()
	if account == "" {
		return errors.New("sign in first")
	}
	ourSigner, hasSigner := a.client.SigningKeyPair()
	if !hasSigner {
		return errors.New("this device has no signing key, so it can't check a transfer")
	}
	ourPriv, hasBox := a.client.EncryptionPrivateKey()
	if !hasBox {
		return errors.New("this device has no encryption key, so it can't open a transfer")
	}
	// The same freshness rule as building one. The signature below is checked
	// against the account's device list, and a list with a since-removed device
	// still on it would accept that device's bundle — the exact keys a takeover
	// is most likely to be holding.
	if err := a.confirmDeviceSet(account); err != nil {
		return err
	}

	bundle, err := e2ee.DecodeTransfer(strings.TrimSpace(body))
	if err != nil {
		return fmt.Errorf("that doesn't look like a device transfer: %w", err)
	}

	// Our OTHER devices' keys, from the verified manifest. Ours is excluded —
	// not for safety, since a bundle we made is one we already have, but because
	// including it would let a corrupted local state verify against itself.
	signKeys, boxKeys := a.otherDeviceKeys(e2ee.SignerID(ourSigner.Public))
	if len(signKeys) == 0 {
		return errors.New("this account's device list hasn't been read yet, so a transfer can't be checked — try again in a moment")
	}

	payload, err := e2ee.OpenTransfer(bundle, state.NormalizeScreenName(account),
		e2ee.SignerID(ourSigner.Public), signKeys, boxKeys, ourPriv)
	if err != nil {
		switch {
		case errors.Is(err, e2ee.ErrTransferNotForUs):
			return errors.New("that transfer was made for a different device")
		case errors.Is(err, e2ee.ErrTransferSignature):
			return errors.New("that transfer isn't signed by any device on this account — don't use it")
		}
		return err
	}

	var p transferPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("the transfer is damaged: %w", err)
	}
	if p.Version != transferPayloadVersion {
		return fmt.Errorf("that transfer was made by a different version of BENCchat (format %d, this one reads %d)",
			p.Version, transferPayloadVersion)
	}
	if p.Account != state.NormalizeScreenName(account) {
		// Belt and braces: the signature already binds the account, so reaching
		// here means the two disagree with each other rather than with us.
		return errors.New("that transfer belongs to a different account")
	}

	a.installTransfer(account, p)
	return nil
}

// installTransfer writes a verified bundle into this device's state.
//
// MERGED, never replaced. A device being furnished is usually empty, but it does
// not have to be — somebody may link a machine, use it, and import later — and
// overwriting would silently destroy whatever it had already received. And
// nothing trust-shaped is taken at the bundle's word: the signature proves
// another of our devices SAID all this, which makes it history worth keeping
// and authority worth nothing. sanitizeTransferredMessage and
// mergeTransferredRoom are the two halves of that line.
func (a *App) installTransfer(account string, p transferPayload) {
	now := time.Now()
	a.mergeTransferredConversations(p.Conversations, now)
	for _, r := range p.Rooms {
		if r.Cookie == "" {
			continue
		}
		a.store.UpsertRoom(r.Cookie, r.Name)
		if len(r.Messages) == 0 {
			continue
		}
		msgs := make([]state.Message, 0, len(r.Messages))
		for _, m := range r.Messages {
			msgs = append(msgs, sanitizeTransferredRoomMessage(m, now))
		}
		// MergeRoomMessages, not AddRoomMessage: it de-duplicates, orders by
		// time and keeps the newest when over the cap, which is what makes
		// importing the same bundle twice a no-op instead of a doubling.
		a.store.MergeRoomMessages(r.Cookie, msgs)
	}

	key := a.roomsKey()
	if key == nil {
		slog.Default().Warn("transferred room state could not be saved: no usable key")
		a.store.Notify(state.NoticeWarn,
			"Transfer applied to your message history, but no usable key store is available, so its room keys were not installed.")
		return
	}
	store, err := roomkeys.Load(account, key)
	if err != nil {
		// Not a fall back to empty: saving over a file we merely failed to read
		// would discard every room key it holds.
		slog.Default().Warn("could not read saved room keys; transferred rooms not installed", "err", err)
		a.store.Notify(state.NoticeWarn,
			"Transfer applied to your message history, but the saved room keys could not be read, so its room keys were not installed.")
		return
	}
	self := state.NormalizeScreenName(account)
	for cookie, in := range p.RoomState {
		if cookie == "" {
			continue
		}
		cur, have := store[cookie]
		store[cookie] = mergeTransferredRoom(cur, have, in, self, now)
	}
	if err := roomkeys.Save(account, store, key); err != nil {
		slog.Default().Warn("could not save transferred room state", "err", err)
		return
	}
	// Live state, so the rooms are readable now rather than after a restart.
	a.restoreRoomKeys()
	a.store.Notify(state.NoticeInfo, "Transfer applied. This device can now read what the other one could.")
}

// mergeTransferredRoom folds one room's transferred state into what this device
// already holds, granting the bundle exactly what a member's signed roster
// could and nothing more.
//
// Views are added only where none is held. A view we already hold arrived
// through LearnChainView's continuity check or an earlier restore, and
// replacing it on a bundle's word would let a crafted "further-back" view
// permanently blind us to a peer we could read. A view for a chain we have
// never seen is trust-on-first-use, which is the same position every other key
// in this client starts from.
//
// Members union in, minus ourselves and minus anybody OUR tombstones name —
// the ceiling applyRoster puts on any member's roster, and no rule here may be
// looser than that one, because the sending device could have mailed us
// exactly that roster instead. Owner, epochs, tombstones and Seen are not
// merged because they do not travel; see transferRoom for why each is absent.
func mergeTransferredRoom(cur roomkeys.Room, have bool, in transferRoom, self string, now time.Time) roomkeys.Room {
	if !have {
		cur = roomkeys.Room{Name: in.Name}
	}
	for id, enc := range in.Views {
		// Decoded before it is believed: an entry whose name disagrees with its
		// own contents is damaged or dishonest, and either way not a key.
		if v, err := e2ee.DecodeChainView(enc); err != nil || v.ID != id {
			continue
		}
		if _, held := cur.Views[id]; held {
			continue
		}
		if cur.Views == nil {
			cur.Views = map[string]string{}
		}
		cur.Views[id] = enc
	}
	removed := make(map[string]bool, len(cur.Removed))
	for _, n := range cur.Removed {
		removed[state.NormalizeScreenName(n)] = true
	}
	adds := make([]string, 0, len(in.Members))
	for _, n := range in.Members {
		if norm := state.NormalizeScreenName(n); norm != "" && norm != self && !removed[norm] {
			adds = append(adds, norm)
		}
	}
	cur.Members = mergeNames(cur.Members, adds)
	// JoinedAt only widens what catch-up may ASK for, never what anyone grants,
	// but a future stamp would freeze the floor ahead of real traffic — bounded
	// like every other timestamp in the bundle.
	if !in.JoinedAt.IsZero() && !in.JoinedAt.After(now) &&
		(cur.JoinedAt.IsZero() || in.JoinedAt.Before(cur.JoinedAt)) {
		cur.JoinedAt = in.JoinedAt
	}
	cur.Updated = now
	return cur
}

// sanitizeTransferredMessage strips a 1:1 message down to what a transfer can
// prove, which is provenance — "another of my devices told me this" — and
// nothing else.
//
// The envelope and cipher never travel (both are json:"-"), so a transferred
// message is unverifiable by construction: there is nothing left to check a
// badge against, now or ever. Taking Encrypted, SenderVerified or Signed at
// the bundle's word would therefore let one compromised device of OURS put the
// lock icon on words a PEER never said — an escalation, because a device can
// already speak as the account but could not previously make other people
// speak. All of them are forced off, and the text stands as relayed history.
//
// At is clamped because Conversations() sorts threads by their last message,
// so a single stamp from the far future pins a thread to the top of the list
// for good.
func sanitizeTransferredMessage(m state.Message, now time.Time) state.Message {
	m.Encrypted = false
	m.SenderVerified = false
	m.Signed = false
	m.Forged = false
	m.Transferred = true
	m.ID = "" // resend handles belong to messages THIS device sent
	if m.At.After(now) {
		m.At = now
	}
	return m
}

// sanitizeTransferredRoomMessage does the same for room history, with one flag
// deliberately forced the OTHER way.
//
// Encrypted is set, not cleared, and here it is doing access control rather
// than badge work: serveCatchup relays a plaintext message's text verbatim but
// skips an encrypted one whose envelope is gone, and a transferred message
// never has its envelope. Left "plaintext", forged room history planted by a
// compromised device would be served to other members as catch-up — laundered
// through a device they trust. Marked encrypted-without-envelope, it is
// exactly the shape catch-up already refuses to relay: readable here, vouched
// for nowhere. The badges that assert trust — SenderVerified, Signed — stay
// off, and Forged is KEPT: it only ever lowers trust, and dropping a warning
// the old device recorded is the one direction that cannot be walked back.
func sanitizeTransferredRoomMessage(m state.Message, now time.Time) state.Message {
	m.Encrypted = true
	m.SenderVerified = false
	m.Signed = false
	m.Forged = false
	m.Transferred = true
	m.ID = ""
	if m.At.After(now) {
		m.At = now
	}
	return m
}

// mergeTransferredConversations folds transferred threads into the store.
//
// The de-duplication lives here because the store cannot provide it: AddMessage
// appends unconditionally, and its cap keeps the LAST thousand — so pushing old
// history through it did not merge, it EVICTED the newest messages to make room
// for the oldest, and a re-import doubled everything. The merge is computed
// outside the store and installed through RestoreConversations, the one entry
// point that replaces threads wholesale.
//
// Two known costs, both taken knowingly. RestoreConversations zeroes unread
// counts, so an import marks everything read — tolerable for a rare, explicit
// action whose content is mostly history read long ago on the other machine.
// And a message arriving live in the gap between the snapshot and the restore
// would be lost — the same window the room-state load/modify/save below already
// has, microseconds wide, on a path the user invokes by hand.
func (a *App) mergeTransferredConversations(incoming []state.Conversation, now time.Time) {
	if len(incoming) == 0 {
		return
	}
	merged := a.store.Conversations()
	index := make(map[string]int, len(merged))
	for i, c := range merged {
		index[c.Key] = i
	}
	changed := false
	for _, in := range incoming {
		// Keyed off the screen name, not the bundle's Key field — the two must
		// agree, and only one of them is recomputable.
		key := state.NormalizeScreenName(in.ScreenName)
		if key == "" {
			continue
		}
		i, have := index[key]
		cur := state.Conversation{Key: key, ScreenName: in.ScreenName, Hidden: in.Hidden}
		if have {
			cur = merged[i]
		}
		seen := make(map[string]bool, len(cur.Messages))
		for _, m := range cur.Messages {
			seen[convMsgKey(m)] = true
		}
		added := false
		for _, m := range in.Messages {
			m = sanitizeTransferredMessage(m, now)
			k := convMsgKey(m)
			if seen[k] {
				continue
			}
			seen[k] = true
			cur.Messages = append(cur.Messages, m)
			added = true
		}
		if !added {
			continue
		}
		sort.SliceStable(cur.Messages, func(x, y int) bool {
			return cur.Messages[x].At.Before(cur.Messages[y].At)
		})
		if have {
			merged[i] = cur
		} else {
			index[key] = len(merged)
			merged = append(merged, cur)
		}
		changed = true
	}
	if !changed {
		return
	}
	a.store.RestoreConversations(merged)
}

// convMsgKey identifies a 1:1 message for de-duplication: the trio roomMsgKey
// uses, plus direction — an echo of our own words and the peer saying the same
// thing back are different messages.
func convMsgKey(m state.Message) string {
	dir := "<"
	if m.Outgoing {
		dir = ">"
	}
	return dir + "\x00" + m.From + "\x00" + m.To + "\x00" + m.At.UTC().Format(time.RFC3339) + "\x00" + m.Text
}

// mergeNames unions two normalized name lists.
func mergeNames(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, n := range list {
			norm := state.NormalizeScreenName(n)
			if norm == "" || seen[norm] {
				continue
			}
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out
}

// ExportDeviceTransfer writes a bundle to a file for another of this account's
// devices.
//
// A file rather than a network connection, and the reasoning is worth keeping:
// this client makes only outbound connections today, so a listening socket would
// be the first thing on it that anybody on the same network could reach. A file
// works over every channel the user already has — a USB stick, a synced folder,
// their own mail — needs no discovery, and adds no surface at all. The bundle is
// sealed to one device and signed by this one, so it is no more sensitive in
// transit than any other ciphertext.
func (a *App) ExportDeviceTransfer(recipientID, path string) string {
	if strings.TrimSpace(path) == "" {
		// Before any work is done: building the bundle assembles the account's
		// whole history in memory, a silly price for "no destination chosen".
		return "Choose where to save the transfer."
	}
	body, err := a.BuildDeviceTransfer(recipientID)
	if err != nil {
		return err.Error()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "Couldn't create that folder: " + err.Error()
	}
	// 0600: the bundle is encrypted, but it is still this account's whole
	// history sitting in the filesystem, and a world-readable copy of it is not
	// something to leave behind on the strength of the encryption alone.
	//
	// Not os.WriteFile, which follows a symlink and keeps a pre-existing file's
	// mode — making the 0600 aspirational on any path that already exists.
	// Removing first and creating exclusively makes it real: whatever sat at
	// the path, file or symlink, is gone, and the new file is ours from birth.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "Couldn't replace that file: " + err.Error()
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "Couldn't write that file: " + err.Error()
	}
	_, werr := f.WriteString(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "Couldn't write that file: " + werr.Error()
	}
	a.store.Notify(state.NoticeInfo,
		"Transfer written. Move it to the other device and import it there — it can only be opened by that device.")
	return ""
}

// ImportDeviceTransfer reads a bundle from a file and applies it.
func (a *App) ImportDeviceTransfer(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "Couldn't read that file: " + err.Error()
	}
	defer f.Close()
	// Capped BEFORE it is read, not merely re-checked in the decoder: by the
	// time a decoder sees the string, an unbounded ReadFile has already paid
	// for the attacker's file in memory.
	raw, err := io.ReadAll(io.LimitReader(f, int64(e2ee.MaxEncodedTransfer)+1))
	if err != nil {
		return "Couldn't read that file: " + err.Error()
	}
	if len(raw) > e2ee.MaxEncodedTransfer {
		return "That file is too large to be a device transfer."
	}
	if err := a.ApplyDeviceTransfer(string(raw)); err != nil {
		return err.Error()
	}
	return ""
}

// TransferTarget is a device a transfer can be built for.
type TransferTarget struct {
	// ID is the device's signing key ID, which is what names it in a bundle.
	ID string `json:"id"`
	// Label is how it appears in the device list.
	Label string `json:"label"`
}

// deviceLabel is a short human-readable name for a device.
//
// A manifest carries no nickname, so this is derived from the signing key ID.
// Short, stable, and enough to tell two devices apart in a list of two or three
// — which is what a list of an account's devices actually is.
func deviceLabel(signerID string) string {
	short := base64.RawURLEncoding.EncodeToString([]byte(signerID))
	if len(short) > 8 {
		short = short[:8]
	}
	return "device " + short
}

// TransferTargets lists this account's OTHER devices.
//
// Ours is excluded because a transfer to ourselves is a transfer of what we
// already have, and offering it would only invite the user to try it.
func (a *App) TransferTargets() []TransferTarget {
	signer, ok := a.client.SigningKeyPair()
	if !ok {
		return nil
	}
	ours := e2ee.SignerID(signer.Public)

	a.trustMu.Lock()
	memo, have := a.manifestSeen[state.NormalizeScreenName(a.currentAccount())]
	a.trustMu.Unlock()
	if !have {
		return nil
	}

	out := make([]TransferTarget, 0, len(memo.devices))
	for _, d := range memo.devices {
		if len(d.Sign) == 0 {
			// A device with no signing key hashes to the "name" every such
			// device shares, and a transfer built for it is refused two calls
			// later as not being on the account. Not offering it is the honest
			// list.
			continue
		}
		id := e2ee.SignerID(d.Sign)
		if id == ours {
			continue
		}
		out = append(out, TransferTarget{ID: id, Label: deviceLabel(id)})
	}
	return out
}
