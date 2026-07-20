package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/benco-holdings/benchat/internal/wire"
)

// App-layer use of the BENCO device key directory (foodgroup 0xBE00), v2.
//
// v1 published a bare list of device keys and let the server arbitrate it. This
// file implements what replaced it: every device list travels as a MANIFEST
// signed by the account's identity key, and nothing below this layer decides
// whether one is worth believing. Two things live here:
//
//   - the verifier (installed via SetManifestVerifier), which is the only place
//     an inbound manifest is checked, and therefore the only place peer keys are
//     ever learned; and
//   - the publish path, which encodes a manifest once, signs those exact bytes,
//     and sends them.
//
// The identity PRIVATE key appears in neither. It is passed in by a caller that
// has just unwrapped it from the backup and will zero it immediately after —
// see app_identity.go. Nothing here retains it.

// keyDirectory is the slice of *client.Client that the identity flows use.
//
// It is an interface for one reason, and it is not decoupling for its own sake:
// proposal §10 and §12 are rules about WHICH call happens before which — that
// nothing is uploaded before the user holds the key, that a re-key never
// publishes a manifest — and a test with no way to observe the calls cannot
// check any of them. *client.Client is the only implementation outside tests;
// a.keyDir is set once in NewApp and never reassigned.
type keyDirectory interface {
	SupportsKeyDir() bool
	QueryManifest(screenName string) (client.SignedManifest, bool)
	PublishManifest(manifest []byte, sigAlg uint8, signature []byte) (accepted bool, counter uint64, ok bool)
	PutIdentityBackup(kdf uint8, params, salt, blob []byte) (stored bool, ok bool)
	GetIdentityBackup() (client.IdentityBackup, bool)
}

// manifestMemo is the last manifest we verified for one account.
//
// It exists because verification is not idempotent: the counter rule refuses a
// counter at or below the high-water mark, so verifying the SAME manifest twice
// would reject it the second time. That happens routinely — the client verifies
// every inbound query reply, and a caller that then wants the result would
// otherwise have to re-verify the bytes it just received.
//
// Re-presenting a byte-identical manifest is not a rollback, and treating it as
// one would break the ordinary path while defending against nothing. The digest
// is what makes that safe: anything that differs by a byte misses the memo and
// goes through the full check, signature included.
type manifestMemo struct {
	sum     [32]byte
	devices []e2ee.Device
}

// installManifestVerifier wires up the hook without which no peer key is ever
// learned.
//
// Worth stating plainly because the failure is silent: with no verifier
// installed the client drops every manifest it receives, so conversations
// simply never become encrypted and nothing reports an error.
func (a *App) installManifestVerifier() {
	a.client.SetManifestVerifier(a.verifyManifest)
}

// verifyManifest decides whether a manifest is worth believing, and returns the
// devices it names.
//
// The order of the checks is the substance of this function:
//
//  1. The signature is checked over sm.Manifest EXACTLY as received. The bytes
//     are decoded first only to reach the identity key inside them — a manifest
//     vouches for itself, and which identity that is has to be read out of the
//     statement before it can be checked. What must never happen is verifying a
//     re-ENCODING of the decoded struct, because any encoding difference would
//     fail a perfectly good signature and look like a crypto bug.
//  2. The screen name inside the signature must match the account we asked
//     about, or a manifest lifted from one account could be replayed onto
//     another and still verify.
//  3. The counter rule (proposal §6), which is the rollback defence.
//
// Returning false means the manifest teaches us nothing at all. It is never a
// reason to fall back to plaintext — a conversation with no verified keys is
// one where CanEncryptTo stays false and the UI says so.
func (a *App) verifyManifest(sm client.SignedManifest) ([]e2ee.Device, bool) {
	if !sm.Present || len(sm.Manifest) == 0 {
		return nil, false
	}
	who := state.NormalizeScreenName(sm.ScreenName)

	// Same statement as last time? Then the answer is last time's answer. See
	// manifestMemo: this is what keeps the counter rule from rejecting a repeat
	// of the manifest it just accepted.
	sum := sha256.Sum256(sm.Manifest)
	a.trustMu.Lock()
	memo, hit := a.manifestSeen[who]
	a.trustMu.Unlock()
	if hit && memo.sum == sum {
		return memo.devices, true
	}

	// A reserved algorithm is refused rather than ignored. Reporting a verified
	// signature we could not actually check would be worse than an error.
	if sm.SigAlg != wire.BENCOAlgEd25519 {
		slog.Default().Warn("manifest uses an unsupported signature algorithm",
			"screen_name", sm.ScreenName, "alg", sm.SigAlg)
		return nil, false
	}

	m, err := wire.DecodeManifest(sm.Manifest)
	if err != nil {
		slog.Default().Warn("could not decode a manifest", "screen_name", sm.ScreenName, "err", err)
		return nil, false
	}
	if m.Version != wire.BENCOKeyDirVersion {
		slog.Default().Warn("manifest has an unexpected version",
			"screen_name", sm.ScreenName, "version", m.Version)
		return nil, false
	}
	if m.Identity.Alg != wire.BENCOAlgEd25519 || len(m.Identity.Key) != wire.BENCOEd25519KeyLen {
		slog.Default().Warn("manifest carries an identity key we cannot verify against",
			"screen_name", sm.ScreenName, "alg", m.Identity.Alg)
		return nil, false
	}
	identity := ed25519.PublicKey(m.Identity.Key)

	// Over the bytes as received.
	if err := e2ee.VerifyManifest(identity, sm.Manifest, sm.Signature); err != nil {
		slog.Default().Warn("manifest signature did not verify", "screen_name", sm.ScreenName, "err", err)
		return nil, false
	}

	// Bound to an account by the signature, so it cannot be replayed onto
	// another one.
	if state.NormalizeScreenName(m.ScreenName) != who {
		slog.Default().Warn("manifest is signed for a different account",
			"asked_about", sm.ScreenName, "signed_for", m.ScreenName)
		return nil, false
	}

	// Counter 0 is reserved so that "no manifest" and "the first manifest" stay
	// distinguishable, and anything above MaxInt64 is refused because the
	// server stores counters in a signed SQLite INTEGER — a value near the top
	// of the uint64 range wraps negative there and then compares BACKWARDS,
	// inverting the rollback defence instead of breaking it visibly.
	if m.Counter == 0 || m.Counter > math.MaxInt64 {
		slog.Default().Warn("manifest counter is out of range",
			"screen_name", sm.ScreenName, "counter", m.Counter)
		return nil, false
	}

	if !a.acceptCounter(who, sm.ScreenName, identity, m.Counter, hex.EncodeToString(sum[:])) {
		return nil, false
	}

	devices := devicesFrom(m)

	a.trustMu.Lock()
	if a.manifestSeen == nil {
		a.manifestSeen = map[string]manifestMemo{}
	}
	a.manifestSeen[who] = manifestMemo{sum: sum, devices: devices}
	a.trustMu.Unlock()

	if a.isSelf(sm.ScreenName) {
		a.onSelfManifest(identity, m, devices)
	}
	return devices, true
}

// acceptCounter applies proposal §6's rule: a high-water mark scoped to an
// identity, not to a screen name.
//
// The scoping is the whole subtlety. Keyed on the counter alone, an account that
// legitimately re-bootstrapped — new identity, counter restarting at 1 — would
// look exactly like a rollback and be refused forever. Keyed on the identity,
// the sequence a given identity issues can only ever go up, and a different
// identity gets its own sequence AND a loud interruption (an identity change is
// never accepted quietly, because it is indistinguishable from a takeover).
func (a *App) acceptCounter(who, display string, identity ed25519.PublicKey, counter uint64, digest string) bool {
	encoded := e2ee.EncodeIdentityPublic(identity)

	if a.isSelf(display) {
		pinned := a.selfIdentityPin()
		switch {
		case pinned.Key == "":
			// Nothing pinned yet: this device is bootstrapping or being linked,
			// and app_identity.go decides what to do about it. Trust on first
			// use, with the counter starting where the manifest says.
		case pinned.Key != encoded:
			// Handled by onSelfManifest, which has the whole manifest and can
			// say the right thing. Accept it as a statement — it verified — but
			// the pin does not move here; the sign-out path replaces it.
			return true
		case counter == pinned.Counter && (digest == pinned.Digest || pinned.Digest == ""):
			// The manifest we already hold, re-read — routine after a restart.
			// An EMPTY pinned digest is a pin written before the digest was
			// recorded (the publish path once omitted it); adopt this manifest's
			// digest rather than refusing our own current statement, which is how
			// a device ended up re-verifying against itself and climbing its own
			// counter on every launch. The re-pin below records the digest, so
			// this self-heals on first read.
		case counter <= pinned.Counter:
			slog.Default().Warn("refusing a stale manifest for our own account",
				"counter", counter, "high_water", pinned.Counter)
			return false
		}
		a.setSelfIdentityPin(trust.Identity{Key: encoded, Counter: counter, Digest: digest})
		return true
	}

	a.trustMu.Lock()
	if a.trust == nil {
		a.trust = trust.Store{}
	}
	entry := a.trust[who]
	prev := entry.Identity
	changed := prev.Key != "" && prev.Key != encoded
	// Re-seeing the manifest we already accepted is not a rollback. That is the
	// ordinary case on every sign-on, since the high-water mark IS the counter of
	// the current manifest. A same-counter manifest whose bytes DIFFER is a fork,
	// which a well-behaved publisher never produces, and is refused below.
	// An empty stored digest (a pin from before digests were recorded) is
	// adopted rather than treated as a mismatch, same as the self branch: we
	// know the counter, we just did not record which bytes, so re-seeing that
	// counter is a re-read, not a fork.
	same := !changed && counter == prev.Counter && (digest == prev.Digest || prev.Digest == "")
	if !changed && !same && counter <= prev.Counter {
		a.trustMu.Unlock()
		slog.Default().Warn("refusing a stale manifest",
			"screen_name", display, "counter", counter, "high_water", prev.Counter,
			"forked", counter == prev.Counter)
		return false
	}
	// The pin moves; the VERIFICATION deliberately does not. Leaving the old
	// verified identity in place is what makes VerificationInfo report
	// "changed" rather than quietly dropping back to "unverified" — the user
	// verified somebody, and the badge has to keep saying that this is no
	// longer them until they decide otherwise.
	entry.Identity = trust.Identity{Key: encoded, Counter: counter, Digest: digest}
	a.trust[who] = entry
	snapshot := a.cloneTrustLocked()
	a.trustMu.Unlock()

	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		slog.Default().Warn("could not save the identity pin", "err", err)
	}
	if changed {
		// Proposal §6: never reassuring. The two explanations are genuinely
		// indistinguishable from here, and saying "this is probably fine" would
		// train people through the one alert that matters.
		a.store.Notify(state.NoticeWarn, fmt.Sprintf(
			"%s's account identity changed. Either they lost access to their old one and "+
				"started over, or somebody with their password replaced it. Nothing here can "+
				"tell those apart — ask them, some other way than this chat, before you trust "+
				"this conversation again.", display))
	}
	return true
}

// onSelfManifest is how this device finds out what has happened to it.
//
// Both cases are derived from a signed statement the device fetched itself, so
// unlike the instant-message denial v1 relied on they cannot be dropped,
// spoofed or missed while offline. The response is what that denial established
// — sign out AND clear the saved password — because leaving the credential
// behind means the next launch signs straight back into the same dead state,
// which looks like nothing happened.
func (a *App) onSelfManifest(identity ed25519.PublicKey, m wire.BENCOManifest, devices []e2ee.Device) {
	encoded := e2ee.EncodeIdentityPublic(identity)
	pinned := a.selfIdentityPin()

	a.trustMu.Lock()
	a.e2eeDevices = e2ee.BoxKeysOf(devices)
	a.manifestIssuedAt = m.IssuedAt
	wasLinked := a.linked
	a.trustMu.Unlock()

	if pinned.Key != "" && pinned.Key != encoded {
		// Proposal §6, row two.
		a.setLinked(false)
		a.store.Notify(state.NoticeError,
			"This account's identity was replaced. This device is no longer part of it, and "+
				"everything it holds is now unreadable to the account. You have been signed "+
				"out and your saved password cleared.")
		a.forgetRemembered()
		go a.SignOff()
		return
	}

	listed := false
	for _, d := range devices {
		if d.Box == a.e2eePub {
			listed = true
			break
		}
	}
	a.setLinked(listed)
	if listed || !wasLinked {
		// Not being listed is only a REMOVAL if we were listed a moment ago.
		// The same observation on a device that has never been linked is just
		// the link flow's starting condition, and calling that "you were
		// removed" would be both wrong and alarming.
		return
	}

	// Proposal §6, row one. The copy departs from the document's table, which
	// says to approve the device again from another linked machine: that was v1,
	// where an approval was a click. Under transient custody (§5) re-linking
	// costs the recovery key every time, and telling someone to click a button
	// that no longer exists would leave them stuck.
	a.store.Notify(state.NoticeError,
		"This device was removed from your account, so it can no longer read encrypted "+
			"messages. Link it again with your recovery key. You have been signed out and "+
			"your saved password cleared.")
	a.forgetRemembered()
	go a.SignOff()
}

// devicesFrom pulls the usable devices out of a verified manifest.
//
// A device whose box key is not one we can encrypt to is skipped rather than
// failing the whole manifest: the algorithm identifiers exist precisely so that
// a future post-quantum key can appear alongside today's, and an old client
// meeting one should ignore that device, not stop talking to the account.
func devicesFrom(m wire.BENCOManifest) []e2ee.Device {
	out := make([]e2ee.Device, 0, len(m.Devices))
	for _, d := range m.Devices {
		if d.Box.Alg != wire.BENCOAlgX25519 || len(d.Box.Key) != wire.BENCOX25519KeyLen {
			continue
		}
		var box [32]byte
		copy(box[:], d.Box.Key)
		dev := e2ee.Device{Box: box}
		if d.Sign.Alg == wire.BENCOAlgEd25519 && len(d.Sign.Key) == wire.BENCOEd25519KeyLen {
			dev.Sign = ed25519.PublicKey(d.Sign.Key)
		}
		out = append(out, dev)
	}
	return out
}

// --- Publishing -----------------------------------------------------------

// publishManifest signs and publishes a device list under kp.
//
// kp is borrowed, never retained: the caller unwrapped it from the backup and
// is responsible for zeroing it. Nothing in this function stores it, and nothing
// downstream of it sees the private half at all — SignManifest takes it, uses
// it, and returns a detached signature.
//
// The counter is chosen from what the server holds rather than from local
// memory, and a refusal carries the value to beat, so losing a race with
// another device costs one retry instead of a guess.
func (a *App) publishManifest(kp e2ee.IdentityKey, devices []e2ee.Device) error {
	if !a.keyDir.SupportsKeyDir() {
		return errNoKeyDir
	}
	self := a.store.Self().ScreenName
	if self == "" {
		return fmt.Errorf("not signed on")
	}
	if len(devices) > e2ee.MaxDevices {
		return fmt.Errorf("this account is at its limit of %d devices — remove one before adding another",
			e2ee.MaxDevices)
	}

	counter := a.nextCounter()
	for attempt := 0; attempt < 2; attempt++ {
		manifest, issuedAt, err := buildManifest(self, kp.Public, counter, devices)
		if err != nil {
			return err
		}
		sig, err := e2ee.SignManifest(kp, manifest)
		if err != nil {
			return err
		}
		accepted, serverCounter, ok := a.keyDir.PublishManifest(manifest, wire.BENCOAlgEd25519, sig)
		if !ok {
			return fmt.Errorf("the key directory did not answer")
		}
		if accepted {
			// Record the counter we just published BEFORE anything else can
			// query. Otherwise our own fresh manifest could be answered by a
			// replay of the previous one, which our high-water mark would then
			// happily accept.
			// The digest matters as much as the counter. Without it the pin says
			// "counter 1" but not WHICH manifest, so on the next launch — memo
			// gone — the counter rule cannot tell our own current manifest from a
			// stale one and refuses it, which republishes, which climbs the
			// counter every restart. The server returns these exact bytes, so
			// sha256(manifest) is what a self-query will hash to.
			sum := sha256.Sum256(manifest)
			a.setSelfIdentityPin(trust.Identity{
				Key:     e2ee.EncodeIdentityPublic(kp.Public),
				Counter: counter,
				Digest:  hex.EncodeToString(sum[:]),
			})
			// And remember the statement itself in the in-process memo too, so a
			// self-query WITHIN this session skips verification entirely.
			a.trustMu.Lock()
			if a.manifestSeen == nil {
				a.manifestSeen = map[string]manifestMemo{}
			}
			a.manifestSeen[state.NormalizeScreenName(self)] = manifestMemo{
				sum:     sum,
				devices: devices,
			}
			a.e2eeDevices = e2ee.BoxKeysOf(devices)
			a.manifestIssuedAt = issuedAt
			a.trustMu.Unlock()
			a.setLinked(true)
			return nil
		}
		// Refused: another device published first. Re-sign above what the
		// server now holds rather than guessing.
		if serverCounter < counter {
			return fmt.Errorf("the key directory refused the device list")
		}
		counter = serverCounter + 1
	}
	return fmt.Errorf("the key directory refused the device list twice; another device may be publishing at the same time")
}

// buildManifest encodes the statement that gets signed.
//
// Encoded exactly once, here. The bytes this returns are the message: they are
// what is signed, what is sent, and what the server stores and hands back. There
// is deliberately no path that re-encodes a manifest from a struct.
//
// The timestamp is returned alongside rather than being re-derived by the
// caller, because "now" moves between the two calls and the value inside the
// signature is the only one that means anything.
func buildManifest(screenName string, identity ed25519.PublicKey, counter uint64, devices []e2ee.Device) ([]byte, uint64, error) {
	// Advisory, and always UTC seconds. Nothing may reject a manifest on this
	// value; it is here so a UI can say how old a device list is.
	issuedAt := uint64(time.Now().UTC().Unix())
	m := wire.BENCOManifest{
		Version:    wire.BENCOKeyDirVersion,
		ScreenName: screenName,
		Counter:    counter,
		IssuedAt:   issuedAt,
		Identity:   wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: identity},
	}
	for _, d := range devices {
		dev := wire.BENCODeviceV2{
			Box: wire.BENCOKey{Alg: wire.BENCOAlgX25519, Key: d.Box[:]},
			// Label ships empty. It sits inside the signature so the server
			// cannot forge it, but nothing hides it from the server either, so
			// whether to name your hardware is the user's call to make.
			Label: "",
		}
		if len(d.Sign) == ed25519.PublicKeySize {
			dev.Sign = wire.BENCOKey{Alg: wire.BENCOAlgEd25519, Key: d.Sign}
		}
		m.Devices = append(m.Devices, dev)
	}
	b, err := wire.EncodeManifest(m)
	if err != nil {
		return nil, 0, err
	}
	if len(b) > wire.BENCOKeyDirMaxManifestLen {
		return nil, 0, fmt.Errorf("that device list is too large to publish")
	}
	return b, issuedAt, nil
}

// nextCounter is the counter to publish at: one above the highest we have seen
// for this account.
func (a *App) nextCounter() uint64 {
	pin := a.selfIdentityPin()
	if pin.Counter == 0 {
		// Counter 0 is reserved, so the first manifest an identity ever issues
		// is 1.
		return 1
	}
	return pin.Counter + 1
}

// thisDevice is this machine as it appears in a manifest.
func (a *App) thisDevice() e2ee.Device {
	d := e2ee.Device{Box: a.e2eePub}
	if a.hasSignKey {
		d.Sign = a.signPub
	}
	return d
}

// currentDevices returns the account's device set from the last verified
// manifest, with this machine merged in.
//
// The manifest is authoritative and already includes machines that are switched
// off, so there is nothing to merge from local memory — and merging would
// republish devices another machine deliberately removed.
func (a *App) currentDevices() []e2ee.Device {
	self := state.NormalizeScreenName(a.store.Self().ScreenName)
	a.trustMu.Lock()
	memo := a.manifestSeen[self]
	a.trustMu.Unlock()

	ours := a.thisDevice()
	out := make([]e2ee.Device, 0, len(memo.devices)+1)
	for _, d := range memo.devices {
		if d.Box == ours.Box {
			continue // replaced below, so our signing key is the current one
		}
		out = append(out, d)
	}
	return append(out, ours)
}

// --- Pins and session state ------------------------------------------------

func (a *App) selfIdentityPin() trust.Identity {
	a.trustMu.Lock()
	pin := a.selfIdentity
	loaded := a.selfIdentityLoaded
	a.trustMu.Unlock()
	if loaded {
		return pin
	}
	stored, err := trust.LoadSelfIdentity(a.currentAccount())
	if err != nil {
		slog.Default().Warn("could not read this account's identity pin", "err", err)
	}
	a.trustMu.Lock()
	a.selfIdentity, a.selfIdentityLoaded = stored, true
	a.trustMu.Unlock()
	return stored
}

func (a *App) setSelfIdentityPin(id trust.Identity) {
	a.trustMu.Lock()
	a.selfIdentity, a.selfIdentityLoaded = id, true
	a.trustMu.Unlock()
	if err := trust.SaveSelfIdentity(a.currentAccount(), id); err != nil {
		slog.Default().Warn("could not save this account's identity pin", "err", err)
	}
}

// setLinked records whether this device is named in the account's manifest, and
// tells the UI when that changes.
func (a *App) setLinked(linked bool) {
	a.trustMu.Lock()
	changed := a.linked != linked
	a.linked = linked
	a.trustMu.Unlock()
	if changed {
		a.emitIdentityState()
	}
}

func (a *App) isLinked() bool {
	a.trustMu.Lock()
	defer a.trustMu.Unlock()
	return a.linked
}

// isSelf reports whether a screen name is the signed-on account's.
func (a *App) isSelf(screenName string) bool {
	self := a.store.Self().ScreenName
	return self != "" && state.NormalizeScreenName(self) == state.NormalizeScreenName(screenName)
}
