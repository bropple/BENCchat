package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/roomkeys"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// K7: furnishing a newly linked device. See app_transfer.go.

// transferDevice is one machine on an account — a box keypair and a signing
// keypair, which is what a manifest entry amounts to — plus the directory it
// asks and the identity that signed the manifest that directory serves.
type transferDevice struct {
	app      *App
	box      e2ee.KeyPair
	sign     e2ee.SigningKeyPair
	id       string
	dir      *xferKeyDir
	identity e2ee.IdentityKey
}

// xferKeyDir is a key directory holding one signed manifest — enough for the
// freshness check both ends of a transfer make before trusting a device list.
type xferKeyDir struct {
	manifest    client.SignedManifest
	unreachable bool
}

func (d *xferKeyDir) SupportsKeyDir() bool { return true }
func (d *xferKeyDir) QueryManifest(string) (client.SignedManifest, bool) {
	return d.manifest, !d.unreachable
}
func (d *xferKeyDir) PublishManifest([]byte, uint8, []byte) (client.PublishOutcome, uint64, bool) {
	return client.PublishRefused, 0, false
}
func (d *xferKeyDir) PutIdentityBackup(uint8, []byte, []byte, []byte) (bool, bool) {
	return false, false
}
func (d *xferKeyDir) GetIdentityBackup() (client.IdentityBackup, bool) {
	return client.IdentityBackup{}, false
}

// signedManifestFor builds and signs a manifest naming the given devices — the
// full entries, signing keys included, which is what the transfer paths check
// against. (signedFor in app_keydir_test.go ships box keys only, which is all
// the verifier tests need.)
func signedManifestFor(t *testing.T, kp e2ee.IdentityKey, screenName string, counter uint64, devices ...e2ee.Device) client.SignedManifest {
	t.Helper()
	manifest, _, err := buildManifest(screenName, kp.Public, counter, devices)
	if err != nil {
		t.Fatalf("buildManifest: %v", err)
	}
	sig, err := e2ee.SignManifest(kp, manifest)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	return client.SignedManifest{
		ScreenName: screenName,
		Present:    true,
		Manifest:   manifest,
		SigAlg:     wire.BENCOAlgEd25519,
		Signature:  sig,
	}
}

// transferPair builds two devices on the same account, each able to fetch a
// REAL signed manifest listing them both from its own fake directory.
//
// A real manifest and the real verifier, not a pre-filled memo: the transfer
// paths re-query and re-verify the device list on every build and apply, so a
// map the test stuffed by hand would bypass the access control being tested.
// Each device gets its own directory so a test can cut one off or serve it a
// shrunken device list without touching the other.
func transferPair(t *testing.T, account string) (old, fresh transferDevice) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	mk := func() transferDevice {
		store := state.NewStore()
		a := &App{store: store, client: client.New(store, nil)}
		a.histAccount = account
		store.SetSelf(account)

		box, err := e2ee.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		sign, err := e2ee.GenerateSigningKey()
		if err != nil {
			t.Fatalf("GenerateSigningKey: %v", err)
		}
		a.client.SetE2EEKeyPair(box, true)
		a.client.SetSigningKey(sign, true)
		return transferDevice{app: a, box: box, sign: sign, id: e2ee.SignerID(sign.Public)}
	}
	old, fresh = mk(), mk()

	identity, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	manifest := signedManifestFor(t, identity, account, 1,
		e2ee.Device{Box: old.box.Public, Sign: old.sign.Public},
		e2ee.Device{Box: fresh.box.Public, Sign: fresh.sign.Public},
	)
	old.dir, fresh.dir = &xferKeyDir{manifest: manifest}, &xferKeyDir{manifest: manifest}
	old.identity, fresh.identity = identity, identity
	old.app.keyDir, fresh.app.keyDir = old.dir, fresh.dir
	return old, fresh
}

// sealPayload signs and seals an arbitrary payload exactly as BuildDeviceTransfer
// would, for the tests that need to hand ApplyDeviceTransfer a payload no honest
// build would produce — which is precisely the compromised-device model.
func sealPayload(t *testing.T, from, to transferDevice, p transferPayload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := e2ee.SealTransfer(p.Account, to.id, to.box.Public, raw,
		from.box.Private, from.sign, time.Now().Unix())
	if err != nil {
		t.Fatalf("SealTransfer: %v", err)
	}
	body, err := e2ee.EncodeTransfer(sealed)
	if err != nil {
		t.Fatalf("EncodeTransfer: %v", err)
	}
	return body
}

// TestATransferFurnishesTheOtherDevice: the whole point. What one device could
// read, the other can read afterwards.
func TestATransferFurnishesTheOtherDevice(t *testing.T) {
	old, fresh := transferPair(t, "me")

	old.app.store.AddMessage(state.Message{
		From: "bob", To: "me", Text: "said before the laptop existed", At: time.Now(),
	})

	body, err := old.app.BuildDeviceTransfer(fresh.id)
	if err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}
	if err := fresh.app.ApplyDeviceTransfer(body); err != nil {
		t.Fatalf("ApplyDeviceTransfer: %v", err)
	}

	conv, ok := fresh.app.store.Conversation("bob")
	if !ok || len(conv.Messages) != 1 {
		t.Fatalf("the new device did not receive the conversation: %+v", conv)
	}
	if conv.Messages[0].Text != "said before the laptop existed" {
		t.Errorf("message = %q", conv.Messages[0].Text)
	}
}

// TestATransferNeverCarriesAnOutboundChain is the one that would be worst to get
// wrong.
//
// A chain is a position counter. Two devices advancing the same one would seal
// two different messages at the same position under the same key — keystream
// reuse, in a room, silently, for everyone in it. The payload type can no longer
// express the chain, its reservation or its Shared flag at all, so what is left
// to test is the view-shaped copy of the same secret: our own chain's VIEW at a
// low position IS the chain state (EncodeChain and EncodeChainView emit the same
// bytes), so every view must leave wound to seen+1 and a view with no recorded
// position must not leave at all.
func TestATransferNeverCarriesAnOutboundChain(t *testing.T) {
	ours, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	peer, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	// A chain we hold a view of but have never seen a message on.
	silent, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	full := roomkeys.Room{
		Name:            "secret room",
		Out:             e2ee.EncodeChain(ours),
		ReservedThrough: 17,
		Shared:          true,
		Views: map[string]string{
			ours.ID:   e2ee.EncodeChainView(ours.View()),
			peer.ID:   e2ee.EncodeChainView(peer.View()),
			silent.ID: e2ee.EncodeChainView(silent.View()),
		},
		Seen:     map[string]uint32{ours.ID: 16, peer.ID: 9},
		Members:  []string{"alice"},
		Owner:    "alice",
		JoinedAt: time.Now().Add(-time.Hour),
	}

	got := transferRoomState(full)

	ourView, err := e2ee.DecodeChainView(got.Views[ours.ID])
	if err != nil {
		t.Fatalf("our chain's view did not travel decodably: %v", err)
	}
	if ourView.Index != 17 {
		t.Errorf("our chain left at position %d, want 17 (seen+1)", ourView.Index)
	}
	// Not one already-used position derives from what shipped — that is the
	// property, not the index number.
	if _, err := ourView.MessageKey(16); !errors.Is(err, e2ee.ErrChainRewind) {
		t.Errorf("the shipped view still derives a used position's key: %v", err)
	}

	peerView, err := e2ee.DecodeChainView(got.Views[peer.ID])
	if err != nil {
		t.Fatalf("the peer view did not travel decodably: %v", err)
	}
	if peerView.Index != 10 {
		t.Errorf("the peer view left at position %d, want 10 (seen+1)", peerView.Index)
	}
	if _, err := peerView.MessageKey(9); !errors.Is(err, e2ee.ErrChainRewind) {
		t.Errorf("the receiver could read history it never observed: %v", err)
	}
	if _, err := peerView.MessageKey(10); err != nil {
		t.Errorf("the receiver cannot read from the conversation's position onward: %v", err)
	}

	if _, ok := got.Views[silent.ID]; ok {
		t.Error("a chain with no known position shipped unwound — that is its whole history")
	}

	// And what SHOULD travel still does, or the transfer is pointless.
	if got.Name != "secret room" {
		t.Errorf("the room name did not travel: %q", got.Name)
	}
	if len(got.Members) != 1 || got.Members[0] != "alice" {
		t.Errorf("membership did not travel: %v", got.Members)
	}
	if got.JoinedAt.IsZero() {
		t.Error("the join time did not travel, so catch-up on the new device has no floor")
	}
}

// TestTheSenderReducesRoomStateOnTheWayOut: the reduction is tested directly
// above; this is the disk-to-payload path, which must apply it to what it reads
// back rather than shipping the file's contents.
func TestTheSenderReducesRoomStateOnTheWayOut(t *testing.T) {
	old, _ := transferPair(t, "me")
	key := old.app.roomsKey()
	if key == nil {
		t.Skip("no keyring available in this environment; transferRoomState is covered directly above")
	}

	chain, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if err := roomkeys.Save("me", roomkeys.Store{"room-1": {
		Name: "secret room", Out: e2ee.EncodeChain(chain), ReservedThrough: 17, Shared: true,
		Views: map[string]string{chain.ID: e2ee.EncodeChainView(chain.View())},
		Owner: "alice", RosterEpoch: 4, OwnerEpoch: 3, Removed: []string{"dave"},
	}}, key); err != nil {
		t.Fatalf("roomkeys.Save: %v", err)
	}

	p := old.app.transferPayload("me")
	got, ok := p.RoomState["room-1"]
	if !ok {
		t.Fatal("the room did not travel at all")
	}
	// The chain has no recorded position, so not even its view may travel — an
	// unwound view of our own chain IS the chain.
	if len(got.Views) != 0 {
		t.Errorf("a view travelled with no position to wind it to: %v", got.Views)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), e2ee.EncodeChain(chain)) {
		t.Error("an outbound chain went on the wire")
	}
}

// TestATransferMustBeSignedByOneOfOurDevices: a bundle is somebody's whole
// history walking into our store. Anything not signed by a device this account
// published is a stranger writing our past for us.
func TestATransferMustBeSignedByOneOfOurDevices(t *testing.T) {
	_, fresh := transferPair(t, "me")

	// Keys that belong to no device on this account.
	box, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sign, err := e2ee.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	stranger := transferDevice{box: box, sign: sign}

	body := sealPayload(t, stranger, fresh, transferPayload{
		Version: transferPayloadVersion,
		Account: "me",
		Conversations: []state.Conversation{{ScreenName: "bob", Messages: []state.Message{{
			From: "bob", To: "me", Text: "you never said this", At: time.Now(),
		}}}},
	})

	if err := fresh.app.ApplyDeviceTransfer(body); err == nil {
		t.Fatal("a bundle from a device outside the account was applied")
	}
	if _, ok := fresh.app.store.Conversation("bob"); ok {
		t.Error("a refused transfer still wrote into our history")
	}
}

// TestATransferForAnotherDeviceIsRefusedClearly: it cannot be opened anyway, but
// "made for a different device" is a fixable problem and a decryption failure
// reads as a broken file.
func TestATransferForAnotherDeviceIsRefusedClearly(t *testing.T) {
	old, fresh := transferPair(t, "me")

	body, err := old.app.BuildDeviceTransfer(fresh.id)
	if err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}
	// The device that MADE it tries to apply it.
	err = old.app.ApplyDeviceTransfer(body)
	if err == nil {
		t.Fatal("a bundle was applied by the device that built it")
	}
	if !strings.Contains(err.Error(), "different device") {
		t.Errorf("unhelpful refusal: %v", err)
	}
}

// TestATransferCannotBeBuiltForAStranger: the recipient's key comes from the
// verified manifest and nowhere else, so a name the user typed cannot become a
// key we seal an account's history to.
func TestATransferCannotBeBuiltForAStranger(t *testing.T) {
	old, _ := transferPair(t, "me")

	if _, err := old.app.BuildDeviceTransfer("not-a-device-on-this-account"); err == nil {
		t.Error("a transfer was built for a device the manifest does not list")
	}
}

// TestATransferIsBuiltAgainstTheDirectoryNotTheMemo: the manifest memo has no
// expiry, so without a fresh query a device removed an hour ago would still be
// offered — and sealed the account's entire history.
func TestATransferIsBuiltAgainstTheDirectoryNotTheMemo(t *testing.T) {
	old, fresh := transferPair(t, "me")

	// Warm the memo with the full two-device list.
	if _, err := old.app.BuildDeviceTransfer(fresh.id); err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}

	// The directory now says the other device was removed; the memo remembers it.
	old.dir.manifest = signedManifestFor(t, old.identity, "me", 2,
		e2ee.Device{Box: old.box.Public, Sign: old.sign.Public})
	if _, err := old.app.BuildDeviceTransfer(fresh.id); err == nil {
		t.Fatal("the account's history was sealed to a device the directory no longer lists")
	}
}

// TestNoTransferAgainstAnUnconfirmedDeviceList: when the directory cannot
// answer, both ends refuse rather than fall back to the sign-on memo — stale
// is exactly the state a removal races against.
func TestNoTransferAgainstAnUnconfirmedDeviceList(t *testing.T) {
	old, fresh := transferPair(t, "me")
	body, err := old.app.BuildDeviceTransfer(fresh.id)
	if err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}

	old.dir.unreachable = true
	if _, err := old.app.BuildDeviceTransfer(fresh.id); err == nil {
		t.Error("a transfer was built against a device list nobody could confirm")
	}
	fresh.dir.unreachable = true
	if err := fresh.app.ApplyDeviceTransfer(body); err == nil {
		t.Error("a transfer was accepted against a device list nobody could confirm")
	}
}

// TestATransferCannotAssertTrustItCannotProve: the envelope and cipher never
// travel, so a transferred message is unverifiable by construction — and the
// flags the UI renders trust from must say so, whatever the bundle claims.
// Otherwise one compromised device of OURS puts the lock icon on words a PEER
// never said, which no device could do before transfers existed.
func TestATransferCannotAssertTrustItCannotProve(t *testing.T) {
	old, fresh := transferPair(t, "me")
	future := time.Now().Add(1000 * time.Hour)

	body := sealPayload(t, old, fresh, transferPayload{
		Version: transferPayloadVersion,
		Account: "me",
		Conversations: []state.Conversation{{ScreenName: "bob", Messages: []state.Message{{
			From: "bob", To: "me", Text: "never said this", At: future,
			Encrypted: true, SenderVerified: true, Signed: true,
		}}}},
		Rooms: []state.Room{{Cookie: "4-1-den", Name: "den", Messages: []state.Message{{
			From: "carol", Text: "planted", At: future,
			Encrypted: false, SenderVerified: true, Signed: true,
		}}}},
	})
	if err := fresh.app.ApplyDeviceTransfer(body); err != nil {
		t.Fatalf("ApplyDeviceTransfer: %v", err)
	}

	conv, ok := fresh.app.store.Conversation("bob")
	if !ok || len(conv.Messages) != 1 {
		t.Fatalf("the conversation did not install: %+v", conv)
	}
	m := conv.Messages[0]
	if m.Encrypted || m.SenderVerified || m.Signed {
		t.Errorf("a transferred 1:1 message kept trust it cannot prove: %+v", m)
	}
	if m.At.After(time.Now()) {
		t.Error("a future timestamp survived, so this thread is pinned to the top of the list for good")
	}

	room, ok := fresh.app.store.Room("4-1-den")
	if !ok || len(room.Messages) != 1 {
		t.Fatalf("the room history did not install: %+v", room)
	}
	rm := room.Messages[0]
	if rm.Text != "planted" || rm.From != "carol" {
		t.Errorf("room message arrived mangled: %+v", rm)
	}
	if rm.SenderVerified || rm.Signed {
		t.Errorf("a transferred room message kept a verification badge: %+v", rm)
	}
	// The OTHER way for room history: encrypted-without-envelope is the one
	// shape serveCatchup refuses to relay. Left "plaintext", this planted line
	// would be served to other members as genuine history.
	if !rm.Encrypted {
		t.Error("a transferred room message installed as relayable plaintext")
	}
	if rm.At.After(time.Now()) {
		t.Error("a future timestamp survived on a room message")
	}
}

// TestATransferGrantsNoRoomAuthority: for a room this device already has, a
// bundle carries a member's weight — adds, and nothing else. Everything
// applyRoster gates behind a signature or an epoch must come through applyRoster.
func TestATransferGrantsNoRoomAuthority(t *testing.T) {
	peer, _ := e2ee.NewChain()
	imposter, _ := e2ee.NewChain()
	newcomer, _ := e2ee.NewChain()
	ours, _ := e2ee.NewChain()

	now := time.Now()
	joined := now.Add(-24 * time.Hour)
	heldView := e2ee.EncodeChainView(peer.View())
	cur := roomkeys.Room{
		Name:            "den",
		Out:             e2ee.EncodeChain(ours),
		ReservedThrough: 5,
		Shared:          true,
		Views:           map[string]string{peer.ID: heldView},
		Seen:            map[string]uint32{peer.ID: 40},
		Members:         []string{"alice"},
		Owner:           "alice",
		RosterEpoch:     4,
		OwnerEpoch:      3,
		Removed:         []string{"dave"},
		JoinedAt:        joined,
	}
	in := transferRoom{
		Name: "renamed",
		Views: map[string]string{
			// A "replacement" for a view already held, a view whose name
			// disagrees with its own contents, and one honestly new chain.
			peer.ID:     e2ee.EncodeChainView(imposter.View()),
			imposter.ID: e2ee.EncodeChainView(newcomer.View()),
			newcomer.ID: e2ee.EncodeChainView(newcomer.View()),
		},
		Members:  []string{"dave", "me", "eve"},
		JoinedAt: now.Add(time.Hour),
	}

	got := mergeTransferredRoom(cur, true, in, "me", now)

	if got.Views[peer.ID] != heldView {
		t.Error("a bundle replaced a chain view we already held")
	}
	if _, ok := got.Views[imposter.ID]; ok {
		t.Error("a view whose name disagrees with its contents was believed")
	}
	if _, ok := got.Views[newcomer.ID]; !ok {
		t.Error("a genuinely new chain view did not install")
	}
	members := strings.Join(got.Members, ",")
	if members != "alice,eve" {
		t.Errorf("members = %q, want alice,eve — no tombstoned dave, no self", members)
	}
	if got.Owner != "alice" || got.RosterEpoch != 4 || got.OwnerEpoch != 3 {
		t.Errorf("a transfer moved room authority state: %+v", got)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "dave" {
		t.Errorf("a transfer touched the tombstones: %v", got.Removed)
	}
	if len(got.Seen) != 1 || got.Seen[peer.ID] != 40 {
		t.Errorf("a transfer touched seen positions: %v", got.Seen)
	}
	if got.Out != cur.Out || got.ReservedThrough != 5 || !got.Shared {
		t.Errorf("a transfer touched the outbound chain: %+v", got)
	}
	if !got.JoinedAt.Equal(joined) {
		t.Error("a future JoinedAt was accepted")
	}
	if got.Name != "den" {
		t.Errorf("a bundle renamed a room we already have: %q", got.Name)
	}
}

// TestARoomFirstLearnedFromATransferStartsWithoutAuthority: no pinned owner, no
// epochs, no tombstones, no seen positions. The pin belongs to the real invite,
// where the roster rules actually run — a bundle that could plant it would make
// the genuine owner's rosters read as an impostor's forever after.
func TestARoomFirstLearnedFromATransferStartsWithoutAuthority(t *testing.T) {
	peer, _ := e2ee.NewChain()
	now := time.Now()
	in := transferRoom{
		Name:     "den",
		Views:    map[string]string{peer.ID: e2ee.EncodeChainView(peer.View())},
		Members:  []string{"alice", "me"},
		JoinedAt: now.Add(-time.Hour),
	}

	got := mergeTransferredRoom(roomkeys.Room{}, false, in, "me", now)

	if got.Owner != "" {
		t.Errorf("a transfer pinned a room owner: %q", got.Owner)
	}
	if got.RosterEpoch != 0 || got.OwnerEpoch != 0 {
		t.Errorf("a transfer set epochs: %d/%d", got.RosterEpoch, got.OwnerEpoch)
	}
	if len(got.Removed) != 0 {
		t.Errorf("a transfer created tombstones: %v", got.Removed)
	}
	if len(got.Seen) != 0 {
		t.Errorf("a transfer created seen positions: %v", got.Seen)
	}
	if got.Out != "" || got.Shared || got.ReservedThrough != 0 {
		t.Errorf("an outbound chain materialized from a transfer: %+v", got)
	}
	if len(got.Members) != 1 || got.Members[0] != "alice" {
		t.Errorf("members = %v, want alice only (never self)", got.Members)
	}
	if _, ok := got.Views[peer.ID]; !ok {
		t.Error("the chain view did not install")
	}
	if got.Name != "den" || !got.JoinedAt.Equal(in.JoinedAt) {
		t.Errorf("name or join time did not travel: %+v", got)
	}
}

// TestApplyingATransferMergesRatherThanReplaces: a device being furnished is
// usually empty, but it does not have to be. Overwriting would silently destroy
// whatever it had already received — and merging has to mean merging, so the
// counts are checked exactly rather than "both threads exist".
func TestApplyingATransferMergesRatherThanReplaces(t *testing.T) {
	old, fresh := transferPair(t, "me")

	fresh.app.store.AddMessage(state.Message{
		From: "carol", To: "me", Text: "arrived here first", At: time.Now(),
	})
	old.app.store.AddMessage(state.Message{
		From: "bob", To: "me", Text: "from the other machine", At: time.Now(),
	})

	body, err := old.app.BuildDeviceTransfer(fresh.id)
	if err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}
	if err := fresh.app.ApplyDeviceTransfer(body); err != nil {
		t.Fatalf("ApplyDeviceTransfer: %v", err)
	}

	carol, ok := fresh.app.store.Conversation("carol")
	if !ok || len(carol.Messages) != 1 {
		t.Errorf("applying a transfer disturbed what this device already had: %+v", carol)
	}
	bob, ok := fresh.app.store.Conversation("bob")
	if !ok || len(bob.Messages) != 1 {
		t.Errorf("the transferred conversation is missing or duplicated: %+v", bob)
	}
}

// TestReapplyingATransferChangesNothing: users retry things that already
// worked, and the bundle file sits around inviting a second import. The first
// version of this feature appended unconditionally, so every retry doubled the
// account's history — and because the store keeps the LAST thousand messages,
// importing enough old history evicted the newest.
func TestReapplyingATransferChangesNothing(t *testing.T) {
	old, fresh := transferPair(t, "me")
	base := time.Now().Add(-time.Hour)
	for i, text := range []string{"one", "two", "three"} {
		old.app.store.AddMessage(state.Message{
			From: "bob", To: "me", Text: text, At: base.Add(time.Duration(i) * time.Minute),
		})
	}
	body := sealPayload(t, old, fresh, old.app.transferPayload("me"))

	if err := fresh.app.ApplyDeviceTransfer(body); err != nil {
		t.Fatalf("ApplyDeviceTransfer: %v", err)
	}
	first, _ := fresh.app.store.Conversation("bob")
	if len(first.Messages) != 3 {
		t.Fatalf("got %d messages after the first apply, want 3", len(first.Messages))
	}
	if err := fresh.app.ApplyDeviceTransfer(body); err != nil {
		t.Fatalf("ApplyDeviceTransfer (again): %v", err)
	}
	second, _ := fresh.app.store.Conversation("bob")
	if len(second.Messages) != 3 {
		t.Errorf("re-applying the same bundle changed the message count: %d, want 3",
			len(second.Messages))
	}
}

// TestATransferFromAFutureVersionIsRefused: a payload we cannot fully understand
// must not be half-applied, because half a history is worse than none and there
// is no way to tell afterwards which half.
func TestATransferFromAFutureVersionIsRefused(t *testing.T) {
	old, fresh := transferPair(t, "me")

	p := old.app.transferPayload("me")
	p.Version = transferPayloadVersion + 1
	body := sealPayload(t, old, fresh, p)

	err := fresh.app.ApplyDeviceTransfer(body)
	if err == nil {
		t.Fatal("a transfer in an unknown format was applied")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestTransferredHistoryIsMarkedAsSuch.
//
// The other trust flags cannot be honest about a transferred message: the sealed
// envelope does not travel, so nothing about the original can be re-checked
// here. A 1:1 message that genuinely was encrypted arrives with the flag
// cleared, and a room message arrives with it SET for an unrelated reason — it
// keeps catch-up from relaying unverifiable history onward. Either one shown as
// a padlock claims something this device cannot know, so the marker the UI
// actually reads has to be carried separately.
func TestTransferredHistoryIsMarkedAsSuch(t *testing.T) {
	now := time.Now()

	direct := sanitizeTransferredMessage(state.Message{
		From: "bob", Text: "hello", At: now, Encrypted: true, SenderVerified: true, Signed: true,
	}, now)
	if !direct.Transferred {
		t.Error("a transferred 1:1 message is not marked as transferred")
	}
	if direct.Encrypted || direct.SenderVerified || direct.Signed || direct.Forged {
		t.Errorf("a transferred 1:1 message kept a trust flag it cannot prove: %+v", direct)
	}

	room := sanitizeTransferredRoomMessage(state.Message{
		From: "bob", Text: "hello", At: now, SenderVerified: true, Signed: true, Forged: true,
	}, now)
	if !room.Transferred {
		t.Error("transferred room history is not marked as transferred")
	}
	if room.SenderVerified || room.Signed || room.Forged {
		t.Errorf("transferred room history kept a trust flag it cannot prove: %+v", room)
	}
	// Encrypted stays SET here, and deliberately: RoomHistorySince relays a
	// plaintext room message's text verbatim but refuses an encrypted one whose
	// envelope is missing. Cleared, forged history planted on one device would
	// be served onward to other members as catch-up.
	if !room.Encrypted {
		t.Error("transferred room history would be relayable as catch-up")
	}
}
