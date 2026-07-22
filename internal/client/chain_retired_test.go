package client

import (
	"crypto/ed25519"
	"testing"

	"github.com/benco-holdings/benchat/internal/e2ee"
)

// After OUR OWN chain is rotated away, is the retired chain still bundled to a
// newcomer at the position we first minted it?
func TestProbe_RetiredOwnChainBundledUnwound(t *testing.T) {
	alice, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")

	alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")
	oldID := alice.OutboundChainID("4-0-r")

	secret, _, _ := alice.sealRoomMessage("4-0-r", "said before the rotation")

	// Somebody is removed: chain marked stale, a new one is minted.
	alice.MarkChainStale("4-0-r")
	alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")
	if alice.OutboundChainID("4-0-r") == oldID {
		t.Fatal("setup: chain did not rotate")
	}

	bundle := alice.ChainBundleFor("4-0-r")
	t.Logf("bundle has %d views", len(bundle))
	for _, v := range bundle {
		t.Logf("  chain %s at index %d (retired=%v)", v.ID, v.Index, v.ID == oldID)
	}

	carol, _ := newTestClient(t)
	carol.store.UpsertRoom("4-0-r", "project")
	carol.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})
	for _, v := range bundle {
		carol.LearnChainView("4-0-r", v)
	}
	if d := carol.decodeRoomMessageFrom("4-0-r", "alice", secret); d.Text == "said before the rotation" {
		t.Errorf("newcomer read pre-rotation history off a retired chain: %q", d.Text)
	} else {
		t.Logf("newcomer got: %+v", d)
	}
}
