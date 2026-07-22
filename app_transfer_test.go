package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/roomkeys"
	"github.com/benco-holdings/benchat/internal/state"
)

// K7: furnishing a newly linked device. See app_transfer.go.

// transferDevice is one machine on an account — a box keypair and a signing
// keypair, which is what a manifest entry amounts to.
type transferDevice struct {
	app  *App
	box  e2ee.KeyPair
	sign e2ee.SigningKeyPair
	id   string
}

// transferPair builds two devices on the same account, each believing the
// account's manifest lists them both. That belief is the access control being
// tested, so it is set up explicitly rather than inferred.
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

	manifest := []e2ee.Device{
		{Box: old.box.Public, Sign: old.sign.Public},
		{Box: fresh.box.Public, Sign: fresh.sign.Public},
	}
	for _, d := range []transferDevice{old, fresh} {
		d.app.trustMu.Lock()
		d.app.manifestSeen = map[string]manifestMemo{
			state.NormalizeScreenName(account): {devices: manifest},
		}
		d.app.trustMu.Unlock()
	}
	return old, fresh
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
// reuse, in a room, silently, for everyone in it. Both ends strip it, and this
// tests the stripping directly rather than through the disk, because a test of
// this invariant must not be skippable on a machine without a keyring.
func TestATransferNeverCarriesAnOutboundChain(t *testing.T) {
	chain, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	view, err := e2ee.NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	full := roomkeys.Room{
		Name:            "secret room",
		Out:             e2ee.EncodeChain(chain),
		ReservedThrough: 17,
		Shared:          true,
		Views:           map[string]string{view.ID: e2ee.EncodeChainView(view.View())},
		Seen:            map[string]uint32{view.ID: 9},
		Members:         []string{"alice"},
		Owner:           "alice",
		RosterEpoch:     4,
		OwnerEpoch:      3,
		Removed:         []string{"dave"},
	}

	got := withoutOutboundChain(full)
	if got.Out != "" {
		t.Errorf("the sending chain travelled: %q", got.Out)
	}
	if got.ReservedThrough != 0 {
		t.Errorf("a reserved position travelled: %d", got.ReservedThrough)
	}
	if got.Shared {
		t.Error("Shared travelled, so the new device would believe a chain it has not minted was already distributed")
	}

	// And everything that SHOULD travel still does, or the transfer is pointless.
	if got.Views[view.ID] == "" {
		t.Error("the chain views we can read did not travel")
	}
	if got.Seen[view.ID] != 9 {
		t.Error("chain positions did not travel, so a bundle for a newcomer would rewind")
	}
	if got.Owner != "alice" || got.RosterEpoch != 4 || got.OwnerEpoch != 3 {
		t.Errorf("room authority state did not travel: %+v", got)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "dave" {
		t.Errorf("removals did not travel, so the new device would re-add somebody: %v", got.Removed)
	}
	if len(got.Members) != 1 || got.Members[0] != "alice" {
		t.Errorf("membership did not travel: %v", got.Members)
	}
	if got.Name != "secret room" {
		t.Errorf("the room name did not travel: %q", got.Name)
	}
}

// TestTheSenderStripsTheChainToo: the receiver strips on arrival, but a bundle
// that carried a chain across the wire would have put it in a file the user
// moves around. Both ends, and this is the sending one.
func TestTheSenderStripsTheChainToo(t *testing.T) {
	old, _ := transferPair(t, "me")
	key := old.app.roomsKey()
	if key == nil {
		t.Skip("no keyring available in this environment; withoutOutboundChain is covered directly above")
	}

	chain, _ := e2ee.NewChain()
	if err := roomkeys.Save("me", roomkeys.Store{"room-1": {
		Name: "secret room", Out: e2ee.EncodeChain(chain), ReservedThrough: 17, Shared: true,
	}}, key); err != nil {
		t.Fatalf("roomkeys.Save: %v", err)
	}

	got, ok := old.app.transferPayload("me").RoomState["room-1"]
	if !ok {
		t.Fatal("the room did not travel at all")
	}
	if got.Out != "" || got.ReservedThrough != 0 || got.Shared {
		t.Errorf("an outbound chain went on the wire: %+v", got)
	}
}

// TestATransferMustBeSignedByOneOfOurDevices: a bundle is somebody's whole
// history walking into our store. Anything not signed by a device this account
// published is a stranger writing our past for us.
func TestATransferMustBeSignedByOneOfOurDevices(t *testing.T) {
	_, fresh := transferPair(t, "me")
	stranger, _ := transferPair(t, "me") // a different account's devices entirely

	stranger.app.store.AddMessage(state.Message{
		From: "bob", To: "me", Text: "you never said this", At: time.Now(),
	})
	body, err := stranger.app.BuildDeviceTransfer(stranger.id)
	if err != nil {
		t.Fatalf("BuildDeviceTransfer: %v", err)
	}

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

// TestApplyingATransferMergesRatherThanReplaces: a device being furnished is
// usually empty, but it does not have to be. Overwriting would silently destroy
// whatever it had already received.
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

	if _, ok := fresh.app.store.Conversation("carol"); !ok {
		t.Error("applying a transfer destroyed what this device already had")
	}
	if _, ok := fresh.app.store.Conversation("bob"); !ok {
		t.Error("the transferred conversation is missing")
	}
}

// TestATransferFromAFutureVersionIsRefused: a payload we cannot fully understand
// must not be half-applied, because half a history is worse than none and there
// is no way to tell afterwards which half.
func TestATransferFromAFutureVersionIsRefused(t *testing.T) {
	old, fresh := transferPair(t, "me")

	p := old.app.transferPayload("me")
	p.Version = transferPayloadVersion + 1
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := e2ee.SealTransfer("me", fresh.id, fresh.box.Public, raw,
		old.box.Private, old.sign, time.Now().Unix())
	if err != nil {
		t.Fatalf("SealTransfer: %v", err)
	}
	body, err := e2ee.EncodeTransfer(sealed)
	if err != nil {
		t.Fatalf("EncodeTransfer: %v", err)
	}

	err = fresh.app.ApplyDeviceTransfer(body)
	if err == nil {
		t.Fatal("a transfer in an unknown format was applied")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}
