package client

import (
	"crypto/ed25519"
	"testing"

	"github.com/benco-holdings/benchat/internal/e2ee"
)

// The invite bundle must carry our live outbound chain even before we have sent
// anything into the room. A create-then-invite issues the invite while the
// owner has said nothing, and before this ChainBundleFor skipped a chain with no
// `seen` entry — so the invite went out empty and the joiner had no key. The
// newcomer must be able to read the owner's FIRST message off the bundle.
func TestChainBundleCarriesUnsentOutboundChain(t *testing.T) {
	alice, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")
	alice.MarkRoomEncrypted("4-0-r")

	// Minted at creation, as CreateEncryptedRoom now does — but NOT sent on, so
	// there is no `seen` entry for it.
	alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")

	alice.SetRoomMembersFunc(func(string) []string { return []string{"bob"} })
	bundle := alice.ChainBundleFor("4-0-r", "bob")
	if len(bundle) == 0 {
		t.Fatal("invite bundle was empty; a newcomer would join with no key")
	}

	bob, _ := newTestClient(t)
	bob.store.UpsertRoom("4-0-r", "project")
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})
	for _, v := range bundle {
		bob.LearnChainView("4-0-r", v)
	}

	first, ok, err := alice.sealRoomMessage("4-0-r", "hello, room")
	if err != nil || !ok {
		t.Fatalf("alice couldn't seal her first message: ok=%v err=%v", ok, err)
	}
	if d := bob.decodeRoomMessageFrom("4-0-r", "alice", first); d.Text != "hello, room" {
		t.Fatalf("newcomer couldn't read the owner's first message off the bundle: %+v", d)
	}
}

// The newcomer must still NOT be able to read anything the owner said BEFORE the
// bundle was cut — forward secrecy is the whole point of the chain model, and a
// bundle at the live position is what preserves it.
func TestChainBundleWithheldPriorMessages(t *testing.T) {
	alice, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")
	alice.MarkRoomEncrypted("4-0-r")
	alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")

	before, ok, err := alice.sealRoomMessage("4-0-r", "said before bob joined")
	if err != nil || !ok {
		t.Fatalf("setup send failed: ok=%v err=%v", ok, err)
	}

	alice.SetRoomMembersFunc(func(string) []string { return []string{"bob"} })
	bundle := alice.ChainBundleFor("4-0-r", "bob")

	bob, _ := newTestClient(t)
	bob.store.UpsertRoom("4-0-r", "project")
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})
	for _, v := range bundle {
		bob.LearnChainView("4-0-r", v)
	}

	if d := bob.decodeRoomMessageFrom("4-0-r", "alice", before); d.Text == "said before bob joined" {
		t.Fatalf("newcomer read a pre-join message: %+v", d)
	}
}

// RoomReadable must reflect chain material, not only the old shared-key flag —
// that mismatch is what reported "no key" for every chain room.
func TestRoomReadableReflectsChainState(t *testing.T) {
	c, _ := newTestClient(t)
	c.store.UpsertRoom("4-0-r", "project")
	c.MarkRoomEncrypted("4-0-r")
	if c.RoomReadable("4-0-r") {
		t.Fatal("an encrypted room with no chain yet should not be readable")
	}
	c.EnsureOutboundChain("4-0-r")
	if !c.RoomReadable("4-0-r") {
		t.Fatal("holding our own outbound chain should read as readable")
	}
}

// A burst of chain requests for the same room+peer must collapse to one, so an
// unreadable backlog does not become a flood — in either direction.
func TestChainRequestThrottled(t *testing.T) {
	c, _ := newTestClient(t)
	if !c.allowChainRequest(&c.roomCrypto.chainReqOut, "4-0-r", "bob") {
		t.Fatal("the first request should be allowed")
	}
	if c.allowChainRequest(&c.roomCrypto.chainReqOut, "4-0-r", "bob") {
		t.Fatal("an immediate repeat should be throttled")
	}
	if !c.allowChainRequest(&c.roomCrypto.chainReqOut, "4-0-r", "carol") {
		t.Fatal("a different peer should not be throttled")
	}
	if !c.allowChainRequest(&c.roomCrypto.chainReqIn, "4-0-r", "bob") {
		t.Fatal("the inbound throttle is a separate bucket and should allow the first")
	}
}
