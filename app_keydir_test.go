package main

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/benco-holdings/benchat/internal/wire"
)

// signedFor builds a manifest exactly as a peer's client would, and signs it.
func signedFor(t *testing.T, kp e2ee.IdentityKey, screenName string, counter uint64, boxes ...[32]byte) client.SignedManifest {
	t.Helper()
	devices := make([]e2ee.Device, 0, len(boxes))
	for _, b := range boxes {
		devices = append(devices, e2ee.Device{Box: b})
	}
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

// appForVerify returns an App wired up enough to run the verifier, with its
// trust file redirected into a temp dir.
func appForVerify(t *testing.T) *App {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store := state.NewStore()
	// A real client, because the self-manifest path hands it the account's
	// device set — the keys sent-message sync mirrors to.
	a := &App{store: store, client: client.New(store, nil)}
	a.histAccount = "us" // what currentAccount() names the trust file after
	return a
}

func box(n byte) [32]byte {
	var b [32]byte
	b[0] = n
	return b
}

// The counter is the whole rollback defence: a server that can serve an older
// signed manifest can resurrect a device its owner removed, and every signature
// on it still verifies. So a counter at or below the high-water mark must be
// refused — while the identical manifest, re-presented, must not be, or the
// ordinary path breaks the first time anything verifies the same bytes twice.
func TestManifestCounterRefusesRollback(t *testing.T) {
	a := appForVerify(t)
	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}

	current := signedFor(t, kp, "bob", 5, box(1), box(2))
	if _, ok := a.verifyManifest(current); !ok {
		t.Fatal("a well-formed manifest was refused")
	}

	// The same statement again is not a rollback.
	if _, ok := a.verifyManifest(current); !ok {
		t.Error("re-presenting the identical manifest was refused as stale")
	}

	// An older one, correctly signed, is exactly the attack.
	if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 4, box(1), box(2), box(3))); ok {
		t.Error("a manifest at a LOWER counter was accepted; the rollback defence is off")
	}
	// So is replaying the current counter with different contents.
	if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 5, box(1), box(2), box(3))); ok {
		t.Error("a manifest at the SAME counter with different devices was accepted")
	}

	// Moving forward is the normal case, including a removal.
	devices, ok := a.verifyManifest(signedFor(t, kp, "bob", 6, box(1)))
	if !ok {
		t.Fatal("a manifest at a higher counter was refused")
	}
	if len(devices) != 1 || devices[0].Box != box(1) {
		t.Errorf("devices = %v, want just the one that survived the removal", devices)
	}
}

// Counter 0 is reserved so "no manifest" and "the first manifest" stay
// distinguishable, and a manifest lifted from one account must not verify
// against another — the screen name is inside the signature for that reason.
func TestManifestVerifierRefusesTheObviousForgeries(t *testing.T) {
	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}

	t.Run("counter zero", func(t *testing.T) {
		a := appForVerify(t)
		if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 0, box(1))); ok {
			t.Error("counter 0 was accepted; it is reserved")
		}
	})

	t.Run("replayed onto another account", func(t *testing.T) {
		a := appForVerify(t)
		sm := signedFor(t, kp, "bob", 1, box(1))
		sm.ScreenName = "mallory" // as if the directory answered a query for someone else
		if _, ok := a.verifyManifest(sm); ok {
			t.Error("a manifest signed for one account was accepted for another")
		}
	})

	t.Run("tampered bytes", func(t *testing.T) {
		a := appForVerify(t)
		sm := signedFor(t, kp, "bob", 1, box(1))
		// Flipped inside the counter, so the bytes still DECODE and the only
		// thing standing between them and being believed is the signature.
		sm.Manifest[8] ^= 0xFF
		if _, ok := a.verifyManifest(sm); ok {
			t.Error("a manifest whose bytes were altered still verified")
		}
	})

	t.Run("unsupported signature algorithm", func(t *testing.T) {
		a := appForVerify(t)
		sm := signedFor(t, kp, "bob", 1, box(1))
		sm.SigAlg = wire.BENCOAlgMLDSA65 // reserved, unimplemented
		if _, ok := a.verifyManifest(sm); ok {
			t.Error("a reserved signature algorithm was accepted rather than refused")
		}
	})

	t.Run("absent", func(t *testing.T) {
		a := appForVerify(t)
		if _, ok := a.verifyManifest(client.SignedManifest{ScreenName: "bob"}); ok {
			t.Error("an account that has published nothing was treated as having keys")
		}
	})
}

// The high-water mark is scoped to an IDENTITY, not to a screen name. An account
// that lost everything and re-bootstrapped restarts its counter at 1, and
// refusing that as a rollback would lock the conversation out permanently. It
// must be accepted — and it must be loud, because it is indistinguishable from
// somebody with the password installing their own identity.
func TestNewIdentityRestartsTheCounterAndShowsAsChanged(t *testing.T) {
	a := appForVerify(t)
	first, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	second, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}

	if _, ok := a.verifyManifest(signedFor(t, first, "bob", 9, box(1))); !ok {
		t.Fatal("the first identity's manifest was refused")
	}
	// The user compares safety numbers and confirms.
	if msg := a.MarkVerified("bob"); msg != "" {
		t.Fatalf("MarkVerified: %s", msg)
	}

	// A different identity, counting from 1.
	if _, ok := a.verifyManifest(signedFor(t, second, "bob", 1, box(2))); !ok {
		t.Fatal("a new identity's first manifest was refused as a rollback")
	}

	a.trustMu.Lock()
	entry := a.trust[state.NormalizeScreenName("bob")]
	a.trustMu.Unlock()
	if entry.Identity.Key != e2ee.EncodeIdentityPublic(second.Public) {
		t.Error("the pin did not move to the new identity")
	}
	if entry.Identity.Counter != 1 {
		t.Errorf("counter = %d, want the new identity's own sequence (1)", entry.Identity.Counter)
	}
	if entry.Verified == "" || entry.Verified == entry.Identity.Key {
		t.Error("the old verification was dropped; the badge can no longer say the identity changed")
	}
}

// Proposal §12: nothing is persisted until the user has acknowledged their
// recovery key, so abandoning first run has to leave no trace — and must take
// the identity key out of memory with it, since transient custody is the
// property the whole design is paying for.
func TestCancelledSetupZeroesTheIdentityKey(t *testing.T) {
	a := appForVerify(t)
	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	a.pending = &pendingIdentity{kp: kp, recoveryKey: "not-a-real-key"}

	a.CancelIdentitySetup()

	if a.pending != nil {
		t.Error("a cancelled setup was left pending")
	}
	// Checked through this copy's backing array rather than through Zeroed():
	// Zero() nils the slice header it is called on, and what matters is that the
	// bytes themselves are gone wherever else they are still reachable from.
	for i, b := range kp.Private {
		if b != 0 {
			t.Fatalf("the identity private key survived the cancellation (byte %d = %d)", i, b)
		}
	}
}

// Confirming without having begun must not write anything, and in particular
// must not reach for a directory it has nothing to send to.
func TestConfirmWithoutBeginDoesNothing(t *testing.T) {
	a := appForVerify(t) // no client: touching one would panic, which is the check
	if msg := a.ConfirmIdentitySetup(); msg == "" {
		t.Error("confirming with nothing pending reported success")
	}
}

// A verification records the peer's IDENTITY, so it survives them adding and
// retiring machines — which is the entire reason for cross-signing. It must not
// survive the identity itself being replaced.
func TestVerificationFollowsTheIdentityNotTheDevices(t *testing.T) {
	a := appForVerify(t)
	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 1, box(1))); !ok {
		t.Fatal("manifest refused")
	}
	if msg := a.MarkVerified("bob"); msg != "" {
		t.Fatalf("MarkVerified: %s", msg)
	}

	a.trustMu.Lock()
	verified := a.trust[state.NormalizeScreenName("bob")].Verified
	a.trustMu.Unlock()
	if verified != e2ee.EncodeIdentityPublic(kp.Public) {
		t.Fatalf("verified value = %q, want the identity key", verified)
	}

	// They add a machine. The identity is unchanged, so the verification stands.
	if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 2, box(1), box(2))); !ok {
		t.Fatal("manifest refused after a device was added")
	}
	a.trustMu.Lock()
	entry := a.trust[state.NormalizeScreenName("bob")]
	a.trustMu.Unlock()
	if entry.Verified != entry.Identity.Key {
		t.Error("adding a device invalidated a verification; safety numbers are meant to be stable now")
	}
}

// The pin is only useful if it outlives the process — an in-memory high-water
// mark resets to trust-on-first-use on every launch, which is the same as not
// having one.
func TestCounterHighWaterMarkIsPersisted(t *testing.T) {
	a := appForVerify(t)
	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	if _, ok := a.verifyManifest(signedFor(t, kp, "bob", 4, box(1))); !ok {
		t.Fatal("manifest refused")
	}

	// A fresh App reading the same trust file is the next launch.
	next := &App{store: state.NewStore()}
	next.histAccount = "us"
	loaded, err := trust.Load("us")
	if err != nil {
		t.Fatalf("trust.Load: %v", err)
	}
	next.trust = loaded
	if _, ok := next.verifyManifest(signedFor(t, kp, "bob", 3, box(1), box(9))); ok {
		t.Error("a rollback was accepted after a restart; the high-water mark was not persisted")
	}
}

// restartOver returns a fresh App reading the same trust file, standing in for
// a restart: the in-memory manifest memo is gone, the high-water mark is not.
func restartOver(t *testing.T, a *App) *App {
	t.Helper()
	store := state.NewStore()
	b := &App{store: store, client: client.New(store, nil)}
	b.histAccount = a.histAccount
	tr, err := trust.Load(b.currentAccount())
	if err != nil {
		t.Fatalf("trust.Load: %v", err)
	}
	b.trust = tr
	return b
}

// Re-reading the CURRENT manifest after a restart must work.
//
// This is not an edge case, it is every sign-on: the high-water mark is the
// counter of the manifest we accepted, so the directory legitimately serves that
// same counter next time. A rule of "reject counter <= stored" refuses it — and
// refuses it SILENTLY, learning no keys and leaving every conversation
// unencrypted with nothing reported anywhere. The memo hides this in one
// process; only a restart exposes it.
func TestCurrentManifestIsAcceptedAfterARestart(t *testing.T) {
	a := appForVerify(t)
	id, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	defer id.Zero()
	sm := signedFor(t, id, "bob", 7, box(1))

	if _, ok := a.verifyManifest(sm); !ok {
		t.Fatal("the first acceptance failed")
	}
	if _, ok := restartOver(t, a).verifyManifest(sm); !ok {
		t.Fatal("the current manifest was refused after a restart; " +
			"counter == high-water is the same statement, not a rollback")
	}
}

// Equality alone must not be enough. Two DIFFERENT manifests sharing a counter
// is a fork — a well-behaved publisher never produces one, and accepting either
// would let a server pick which device set we believe.
func TestForkedManifestAtTheSameCounterIsRefused(t *testing.T) {
	a := appForVerify(t)
	id, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	defer id.Zero()

	if _, ok := a.verifyManifest(signedFor(t, id, "bob", 7, box(1))); !ok {
		t.Fatal("the first manifest was refused")
	}
	// Same identity, same counter, different devices — so different bytes.
	if _, ok := restartOver(t, a).verifyManifest(signedFor(t, id, "bob", 7, box(2))); ok {
		t.Fatal("a fork at the same counter was accepted")
	}
}

// A self pin written WITHOUT a digest -- which the publish path once did -- must
// not cause the account's own current manifest to be refused on the next launch.
// That refusal made a device re-verify against itself and republish, climbing
// its own counter every restart. An empty stored digest is adopted, not treated
// as a stale-counter mismatch.
func TestSelfManifestWithDigestlessPinIsAcceptedAfterRestart(t *testing.T) {
	id, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	defer id.Zero()

	a := appForVerify(t)
	a.store.SetSelf("us") // so isSelf("us") is true and the self branch runs
	// Pin our own identity at counter 1 with NO digest, exactly as the buggy
	// publish path persisted it.
	a.setSelfIdentityPin(trust.Identity{Key: e2ee.EncodeIdentityPublic(id.Public), Counter: 1})

	// Restart: fresh App, same trust file, empty in-memory memo.
	b := restartOver(t, a)
	b.store.SetSelf("us")

	// The account's own current manifest, at the pinned counter, must verify.
	sm := signedFor(t, id, "us", 1, box(1))
	if _, ok := b.verifyManifest(sm); !ok {
		t.Fatal("our own current manifest was refused after a restart from a digest-less pin")
	}
	// And the pin now carries a digest, so it is self-healed.
	if b.selfIdentityPin().Digest == "" {
		t.Error("the pin was not re-recorded with a digest")
	}
}