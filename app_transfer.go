package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

	// Conversations and Rooms are the history file's contents.
	Conversations []state.Conversation `json:"conversations,omitempty"`
	Rooms         []state.Room         `json:"rooms,omitempty"`

	// RoomState is per-room chain and membership state, keyed by room cookie —
	// the same shape the room file holds, minus what must not be copied.
	RoomState map[string]roomkeys.Room `json:"roomState,omitempty"`
}

const transferPayloadVersion = 1

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
		Rooms:         a.store.Rooms(),
	}

	// Room state comes off DISK rather than out of the live client, so a room
	// the user is not currently joined to still travels. The saved copy is also
	// the one whose chain positions are already reserved, which is the only
	// version safe to hand anybody.
	if key := a.roomsKey(); key != nil {
		store, err := roomkeys.Load(account, key)
		if err != nil {
			slog.Default().Warn("could not read room state for a transfer", "err", err)
		} else {
			p.RoomState = make(map[string]roomkeys.Room, len(store))
			for cookie, r := range store {
				p.RoomState[cookie] = withoutOutboundChain(r)
			}
		}
	}
	return p
}

// withoutOutboundChain returns a room's state with our own sending chain
// removed.
//
// This is the single most important line in the feature, so it is one function
// called from both ends rather than the same three assignments written twice.
//
// A chain is a position counter. Two devices advancing the same one would seal
// two different messages at the same position under the same key — keystream
// reuse, in a room, silently, for everyone in it. Nothing about a transfer needs
// the sending chain: the receiving device mints its own on its first send and
// broadcasts it by the ordinary path, so what travels is the ability to READ
// what others send and never the ability to speak as the device that sent it.
func withoutOutboundChain(r roomkeys.Room) roomkeys.Room {
	r.Out = ""
	r.ReservedThrough = 0
	// Shared says "our chain reached the room", which cannot be true of a chain
	// that does not exist yet. Carrying it over would tell the new device its
	// unminted chain had already been distributed, and the first thing it said
	// in that room would be unreadable to everyone.
	r.Shared = false
	return r
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
// overwriting would silently destroy whatever it had already received. Merging
// costs a duplicate or two; replacing costs messages.
func (a *App) installTransfer(account string, p transferPayload) {
	for _, c := range p.Conversations {
		for _, m := range c.Messages {
			a.store.AddMessage(m)
		}
	}
	for _, r := range p.Rooms {
		a.store.UpsertRoom(r.Cookie, r.Name)
	}

	key := a.roomsKey()
	if key == nil {
		slog.Default().Warn("transferred room state could not be saved: no usable key")
		return
	}
	store, err := roomkeys.Load(account, key)
	if err != nil {
		// Not a fall back to empty: saving over a file we merely failed to read
		// would discard every room key it holds.
		slog.Default().Warn("could not read saved room keys; transferred rooms not installed", "err", err)
		return
	}
	for cookie, raw := range p.RoomState {
		// Stripped again on arrival rather than trusted to have been stripped on
		// departure. The sender is authenticated, not infallible: a bug or a
		// damaged payload that carried a chain would otherwise hand this device
		// a position counter another machine is still using.
		in := withoutOutboundChain(raw)

		cur, have := store[cookie]
		if !have {
			store[cookie] = in
			continue
		}
		// A room we already have: take the views we lack and keep our own chain
		// exactly as it is.
		if cur.Views == nil {
			cur.Views = map[string]string{}
		}
		for id, v := range in.Views {
			if _, held := cur.Views[id]; !held {
				cur.Views[id] = v
			}
		}
		if cur.Seen == nil {
			cur.Seen = map[string]uint32{}
		}
		for id, n := range in.Seen {
			if n > cur.Seen[id] {
				cur.Seen[id] = n
			}
		}
		cur.Members = mergeNames(cur.Members, in.Members)
		cur.Removed = mergeNames(cur.Removed, in.Removed)
		if cur.Owner == "" {
			cur.Owner = in.Owner
		}
		// Epochs take the higher of the two: they are anti-rollback marks, and
		// the whole point of one is that it never goes backwards.
		if in.RosterEpoch > cur.RosterEpoch {
			cur.RosterEpoch = in.RosterEpoch
		}
		if in.OwnerEpoch > cur.OwnerEpoch {
			cur.OwnerEpoch = in.OwnerEpoch
		}
		if cur.JoinedAt.IsZero() || (!in.JoinedAt.IsZero() && in.JoinedAt.Before(cur.JoinedAt)) {
			cur.JoinedAt = in.JoinedAt
		}
		store[cookie] = cur
	}
	if err := roomkeys.Save(account, store, key); err != nil {
		slog.Default().Warn("could not save transferred room state", "err", err)
		return
	}
	// Live state, so the rooms are readable now rather than after a restart.
	a.restoreRoomKeys()
	a.store.Notify(state.NoticeInfo, "Transfer applied. This device can now read what the other one could.")
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
	body, err := a.BuildDeviceTransfer(recipientID)
	if err != nil {
		return err.Error()
	}
	if strings.TrimSpace(path) == "" {
		return "Choose where to save the transfer."
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "Couldn't create that folder: " + err.Error()
	}
	// 0600: the bundle is encrypted, but it is still this account's whole
	// history sitting in the filesystem, and a world-readable copy of it is not
	// something to leave behind on the strength of the encryption alone.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "Couldn't write that file: " + err.Error()
	}
	a.store.Notify(state.NoticeInfo,
		"Transfer written. Move it to the other device and import it there — it can only be opened by that device.")
	return ""
}

// ImportDeviceTransfer reads a bundle from a file and applies it.
func (a *App) ImportDeviceTransfer(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "Couldn't read that file: " + err.Error()
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
		id := e2ee.SignerID(d.Sign)
		if id == "" || id == ours {
			continue
		}
		out = append(out, TransferTarget{ID: id, Label: deviceLabel(id)})
	}
	return out
}
