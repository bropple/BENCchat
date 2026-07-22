package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/benco-holdings/benchat/internal/e2ee"
)

// Adversarial room tests.
//
// These began as an auditor's proof-of-concept and are kept because of what they
// proved about the suite that preceded them: every actor in every other test in
// this package is a well-behaved Client. Nothing anywhere put an UNCONSTRAINED
// BYTE EMITTER in a room, and four critical defects lived in that gap. Mutation
// testing could not reach them either — the worst was not a wrong line but a
// missing ordering constraint between two correct ones.
//
// So: keep a hostile participant in the fixtures. The assertions below are the
// defences, not the attacks.

// A poisoned wire index must not reach `seen`, and a bundle must never be handed
// out unwound. One undecryptable message from a walk-in used to set a position of
// 0xFFFFFFFF, which wrapped the bundle's +1 back to zero and gave the next
// newcomer the room's entire history.
func TestAudit_SeenOverflowDefeatsBundleWinding(t *testing.T) {
	alice, _ := newTestClient(t)
	bob, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")
	bob.store.UpsertRoom("4-0-r", "project")
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	view, _, _ := alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")
	bob.LearnChainView("4-0-r", view) // Bob holds Alice's chain at 0

	secret1, _, _ := alice.sealRoomMessage("4-0-r", "secret one")
	secret2, _, _ := alice.sealRoomMessage("4-0-r", "secret two")
	if d := bob.decodeRoomMessageFrom("4-0-r", "alice", secret1); !d.Encrypted {
		t.Fatalf("setup: bob should read secret1: %+v", d)
	}
	if d := bob.decodeRoomMessageFrom("4-0-r", "alice", secret2); !d.Encrypted {
		t.Fatalf("setup: bob should read secret2: %+v", d)
	}

	// Mallory walks into the room (no join control) and sends a v3 envelope
	// naming Alice's chain at the maximum index. It never decrypts; it does not
	// have to.
	chainID := view.ID
	poison := "\x1bBENCO-ROOM:v3:" + chainID + ":" +
		strconv.FormatUint(0xFFFFFFFF, 16) + ":" +
		base64.StdEncoding.EncodeToString(make([]byte, 64))
	bob.decodeRoomMessageFrom("4-0-r", "mallory", poison)

	bundle := bob.ChainBundleFor("4-0-r")
	if len(bundle) != 1 {
		t.Fatalf("bundle = %d views", len(bundle))
	}
	if bundle[0].Index == 0 {
		t.Fatal("the bundle was handed out unwound — a poisoned position took effect")
	}

	// A newcomer handed this bundle must NOT read Alice's pre-join history.
	carol, _ := newTestClient(t)
	carol.store.UpsertRoom("4-0-r", "project")
	carol.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})
	carol.LearnChainView("4-0-r", bundle[0])
	if d := carol.decodeRoomMessageFrom("4-0-r", "alice", secret1); d.Text == "secret one" {
		t.Errorf("newcomer read pre-join history: %q", d.Text)
	} else {
		t.Logf("newcomer got: %+v", d)
	}
}

// A2: a moderately inflated `seen` makes PruneChainViews wind a view past the
// chain's real position, permanently destroying readability.
func TestAudit_SeenInflationDestroysReadability(t *testing.T) {
	alice, _ := newTestClient(t)
	bob, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")
	bob.store.UpsertRoom("4-0-r", "project")
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	view, _, _ := alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")
	bob.LearnChainView("4-0-r", view)

	chainID := view.ID
	poison := "\x1bBENCO-ROOM:v3:" + chainID + ":" +
		strconv.FormatUint(3000, 16) + ":" +
		base64.StdEncoding.EncodeToString(make([]byte, 64))
	bob.decodeRoomMessageFrom("4-0-r", "mallory", poison)

	// The poison must not have inflated `seen`, so retention has nothing to act
	// on. Winding is irreversible, so acting on an attacker's number blinds the
	// member permanently.
	if moved := bob.PruneChainViews("4-0-r"); moved != 0 {
		t.Errorf("prune wound %d views on an attacker-supplied position", moved)
	}
	msg, _, _ := alice.sealRoomMessage("4-0-r", "can you still read me")
	d := bob.decodeRoomMessageFrom("4-0-r", "alice", msg)
	if d.Text != "can you still read me" {
		t.Errorf("bob was blinded to alice's chain: %+v", d)
	}
}

// A3: any room participant can permanently replace another member's chain view
// by broadcasting a bogus one under the same chain ID at a lower index.
func TestAudit_ChainIDHijack(t *testing.T) {
	alice, _ := newTestClient(t)
	bob, _ := newTestClient(t)
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)
	alice.store.UpsertRoom("4-0-r", "project")
	bob.store.UpsertRoom("4-0-r", "project")
	bob.learnPeerSigningKeys("alice", []ed25519.PublicKey{signer.Public})

	view, _, _ := alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")
	for i := 0; i < 5; i++ {
		alice.sealRoomMessage("4-0-r", "filler")
	}
	view, _, _ = alice.EnsureOutboundChain("4-0-r") // now at index 5
	bob.LearnChainView("4-0-r", view)

	// Mallory's own chain state, published under ALICE's chain ID at index 0.
	mallory, _ := e2ee.NewChain()
	hijack := mallory.View()
	hijack.ID = view.ID
	bob.LearnChainView("4-0-r", hijack)

	msg, _, _ := alice.sealRoomMessage("4-0-r", "real message")
	d := bob.decodeRoomMessageFrom("4-0-r", "alice", msg)
	if d.Text != "real message" {
		t.Errorf("alice's chain was hijacked, bob sees: %+v", d)
	}
}

// A4: the send path never persists, so a restart resumes at a stale index —
// reusing message-key positions AND handing a newcomer pre-join history.
func TestAudit_RestoreAtStaleIndexReusesPositions(t *testing.T) {
	alice, _ := newTestClient(t)
	alice.store.UpsertRoom("4-0-r", "project")
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)

	// A stand-in for the room file. The reservation is only worth anything if it
	// reaches durable storage BEFORE the position it covers is used, so the test
	// has to model a disk rather than a snapshot taken by hand.
	var disk struct {
		out      string
		views    map[string]string
		seen     map[string]uint32
		reserved uint32
		shared   bool
		writes   int
	}
	alice.SetPersistChainFunc(func(cookie string) error {
		disk.out, disk.views, disk.seen, disk.reserved, disk.shared = alice.RoomChainState(cookie)
		disk.writes++
		return nil
	})

	alice.EnsureOutboundChain("4-0-r")
	alice.MarkChainShared("4-0-r")

	var sentIdx []uint32
	for i := 0; i < 3; i++ {
		env, _, err := alice.sealRoomMessage("4-0-r", "message "+strconv.Itoa(i))
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		_, idx, _ := e2ee.RoomEnvelopeChain(env)
		sentIdx = append(sentIdx, idx)
	}
	if disk.writes == 0 {
		t.Fatal("nothing was persisted during sending, so no position was ever reserved")
	}

	// Crash: everything after the last durable write is gone. Restore from the
	// file bytes, which is the only state that survives.
	restarted, _ := newTestClient(t)
	restarted.store.UpsertRoom("4-0-r", "project")
	restarted.SetSigningKey(signer, true)
	restarted.RestoreChainState("4-0-r", disk.out, disk.views, disk.seen, disk.reserved, disk.shared)

	env, encrypted, err := restarted.sealRoomMessage("4-0-r", "after restart")
	if err != nil || !encrypted {
		t.Fatalf("restored client refused to send: %v", err)
	}
	_, idx, _ := e2ee.RoomEnvelopeChain(env)

	for _, used := range sentIdx {
		if idx == used {
			t.Errorf("position %d sealed a second message after restart", idx)
		}
	}
	if t.Failed() {
		t.Logf("pre-restart indices %v, post-restart index %d", sentIdx, idx)
	}
}

// A5: RestoreChainState marks a restored chain shared without evidence it ever
// went out; conversely a chain minted by ReformRoom is never marked shared, so
// the reformed room cannot be sent to until the app restarts.
func TestAudit_ReformedRoomCannotSend(t *testing.T) {
	a, _ := newTestClient(t)
	a.store.UpsertRoom("4-0-new", "project-x")
	signer, _ := e2ee.GenerateSigningKey()
	a.SetSigningKey(signer, true)

	// Exactly what ReformRoom does: mark encrypted, mint a chain, hand it out
	// 1:1 to the carried members — and then say it was handed out. That last
	// step was missing, so the next send found an unshared chain and told the
	// user to get re-invited to a room they had just created themselves.
	a.MarkRoomEncrypted("4-0-new")
	if _, fresh, err := a.EnsureOutboundChain("4-0-new"); err != nil || !fresh {
		t.Fatalf("EnsureOutboundChain: fresh=%v err=%v", fresh, err)
	}
	a.MarkChainShared("4-0-new")

	// The send path's guard sees a non-fresh chain and broadcasts nothing, which
	// is right — it already went out 1:1.
	if _, fresh, _ := a.EnsureOutboundChain("4-0-new"); fresh {
		t.Fatal("second call reported fresh")
	}
	_, encrypted, err := a.sealRoomMessage("4-0-new", "hello new room")
	if err != nil || !encrypted {
		t.Errorf("reformed room refuses to send: encrypted=%v err=%v", encrypted, err)
	}
}

// A6: sending into an ordinary, never-encrypted room silently turns it into an
// encrypted one and broadcasts key material into it.
func TestAudit_PlainRoomBecomesEncryptedOnFirstSend(t *testing.T) {
	a, _ := newTestClient(t)
	a.store.UpsertRoom("4-0-lobby", "lobby")
	signer, _ := e2ee.GenerateSigningKey()
	a.SetSigningKey(signer, true)

	if a.RoomEncrypted("4-0-lobby") {
		t.Fatal("setup: room already encrypted")
	}
	a.EnsureOutboundChain("4-0-lobby") // what SendRoomMessage calls unconditionally
	if a.RoomEncrypted("4-0-lobby") {
		t.Error("BUG: an ordinary room became encrypted just by being sent to")
	}
}

// A7: DecodeChainBroadcast returns on the FIRST slot bearing our label, so a
// decoy slot placed earlier denies us the real one.
func TestAudit_DecoySlotShadowsTheRealOne(t *testing.T) {
	ours, _ := e2ee.GenerateKeyPair()
	sender, _ := e2ee.GenerateKeyPair()
	chain, _ := e2ee.NewChain()

	good, err := e2ee.EncodeChainBroadcast(chain.View(), [][32]byte{ours.Public}, sender.Private)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(good, e2ee.ChainBroadcastPrefix))
	const header = 1 + 8 + 4 + 2
	slot := raw[header:]
	// Two slots: a corrupted copy first, the genuine one second.
	decoy := append([]byte(nil), slot...)
	decoy[len(decoy)-1] ^= 0xFF
	body := append([]byte(nil), raw[:header]...)
	body[header-1] = 2 // count = 2
	body = append(body, decoy...)
	body = append(body, slot...)
	crafted := e2ee.ChainBroadcastPrefix + base64.StdEncoding.EncodeToString(body)

	if _, err := e2ee.DecodeChainBroadcast(crafted, []e2ee.KeyPair{ours}, [][32]byte{sender.Public}); err != nil {
		t.Errorf("a decoy slot shadowed the genuine one: %v", err)
	}
}

// TestChainSurvivesACrashAtEveryStep is the invariant as a loop rather than a
// scenario.
//
// The rule: before any ciphertext sealed at index i leaves the process, a
// durable record with reservedThrough > i must exist. A single hand-written
// crash point proves that for one moment; the failure this exists for is a crash
// at the moment nobody thought about. So crash at every step and assert the
// property globally.
func TestChainSurvivesACrashAtEveryStep(t *testing.T) {
	signer, _ := e2ee.GenerateSigningKey()

	for crashAfter := 0; crashAfter < 12; crashAfter++ {
		alice, _ := newTestClient(t)
		alice.store.UpsertRoom("4-0-r", "project")
		alice.SetSigningKey(signer, true)

		var disk struct {
			out      string
			views    map[string]string
			seen     map[string]uint32
			reserved uint32
			shared   bool
		}
		alice.SetPersistChainFunc(func(cookie string) error {
			disk.out, disk.views, disk.seen, disk.reserved, disk.shared = alice.RoomChainState(cookie)
			return nil
		})
		alice.EnsureOutboundChain("4-0-r")
		alice.MarkChainShared("4-0-r")
		// The create/invite path saves as soon as a chain is minted and shared,
		// so there is always a file before the first send.
		if err := alice.persistChain("4-0-r"); err != nil {
			t.Fatalf("initial persist: %v", err)
		}

		used := map[uint32]bool{}
		for i := 0; i < crashAfter; i++ {
			env, _, err := alice.sealRoomMessage("4-0-r", "before")
			if err != nil {
				t.Fatalf("crashAfter=%d send %d: %v", crashAfter, i, err)
			}
			_, idx, _ := e2ee.RoomEnvelopeChain(env)
			used[idx] = true
		}

		// Everything not on disk is lost.
		restarted, _ := newTestClient(t)
		restarted.store.UpsertRoom("4-0-r", "project")
		restarted.SetSigningKey(signer, true)
		restarted.RestoreChainState("4-0-r", disk.out, disk.views, disk.seen, disk.reserved, disk.shared)

		for i := 0; i < 4; i++ {
			env, _, err := restarted.sealRoomMessage("4-0-r", "after")
			if err != nil {
				t.Fatalf("crashAfter=%d post-restart send %d: %v", crashAfter, i, err)
			}
			_, idx, _ := e2ee.RoomEnvelopeChain(env)
			if used[idx] {
				t.Fatalf("crashAfter=%d: position %d sealed twice across a crash", crashAfter, idx)
			}
			used[idx] = true
		}
	}
}

// TestRestoredChainIsNotAssumedShared: a chain that never reached the room must
// not come back from disk believing it did.
//
// Restore used to infer sharedness from the file existing — "persisted implies
// sent implies shared" — and both steps were false. A reformed room persisted an
// unshared chain and then refused to send forever, with a message telling the
// user to get themselves re-invited to their own room.
func TestRestoredChainIsNotAssumedShared(t *testing.T) {
	alice, _ := newTestClient(t)
	alice.store.UpsertRoom("4-0-r", "project")
	signer, _ := e2ee.GenerateSigningKey()
	alice.SetSigningKey(signer, true)

	// A chain minted and persisted but never broadcast.
	alice.EnsureOutboundChain("4-0-r")
	out, views, seen, reserved, shared := alice.RoomChainState("4-0-r")
	if shared {
		t.Fatal("a chain that was never broadcast reported itself shared")
	}

	restarted, _ := newTestClient(t)
	restarted.store.UpsertRoom("4-0-r", "project")
	restarted.SetSigningKey(signer, true)
	restarted.RestoreChainState("4-0-r", out, views, seen, reserved, shared)

	if _, _, err := restarted.sealRoomMessage("4-0-r", "hello"); err == nil {
		t.Error("sealed under a restored chain the room was never given")
	}

	// And once it is genuinely shared, it round-trips as such.
	restarted.MarkChainShared("4-0-r")
	_, _, _, _, nowShared := restarted.RoomChainState("4-0-r")
	if !nowShared {
		t.Error("a shared chain did not persist as shared")
	}
}
