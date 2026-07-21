package main

import (
	"log/slog"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
)

// currentAccount is the account whose secret-store keys we use: the signed-on
// screen name if any, else the last one (so a toggle before sign-on still
// targets the right keyring entry).
func (a *App) currentAccount() string {
	a.histMu.Lock()
	acct := a.histAccount
	a.histMu.Unlock()
	if acct != "" {
		return acct
	}
	return a.cfg.LastScreenName
}

// setupE2EE loads (or, when enabling for the first time, generates) this
// DEVICE's keypair after sign-on and wires it into the client.
//
// Note the layering, because two different keys are involved and conflating
// them is how cross-signing gets quietly undone. What this function handles is
// the per-device key: minted here, kept in the OS keyring, never leaves the
// machine. The ACCOUNT identity key that signs the device list is not touched
// here at all — it is transient, lives only in app_identity.go's flows, and is
// never written to the keyring or anywhere else.
//
// Best-effort: a keyring failure disables encryption for the session rather than
// blocking sign-on.
func (a *App) setupE2EE(screenName string) {
	a.e2eeHasKey = false
	var kp e2ee.KeyPair

	// A read that FAILED and a store that holds nothing are different answers,
	// and only one of them means "generate a key". Minting on failure gives this
	// device a new identity every time the keyring is locked or slow to start,
	// which then has to be signed into the account's manifest all over again —
	// costing the recovery key — while the dead key sits in the device list.
	//
	// So a failed read disables encryption for the session, which is what this
	// function has always claimed to do.
	keyringFailed := false
	if priv, err := secret.RetrievePrivateKey(screenName); err != nil {
		slog.Default().Warn("could not read E2EE key from the secret store", "err", err)
		keyringFailed = true
	} else if priv != "" {
		if pk, derr := e2ee.DecodeKey(priv); derr == nil {
			if loaded, lerr := e2ee.KeyPairFromPrivate(pk); lerr == nil {
				kp, a.e2eeHasKey = loaded, true
			}
		}
	}

	if keyringFailed {
		a.store.Notify(state.NoticeError,
			"Encryption is off for this session: your keychain couldn't be reached, "+
				"so BENCchat can't load this device's key. It will NOT create a new one — "+
				"that would take this device off your account's device list until you "+
				"linked it again with your recovery key. Unlock your keychain and sign in again.")
	}

	// Enabling but genuinely no key yet → generate one now.
	if a.cfg.E2EEOn() && !a.e2eeHasKey && !keyringFailed {
		if generated, err := e2ee.GenerateKeyPair(); err == nil {
			if serr := secret.StorePrivateKey(screenName, e2ee.EncodeKey(generated.Private)); serr != nil {
				slog.Default().Warn("could not save E2EE key", "err", serr)
			}
			kp, a.e2eeHasKey = generated, true
		}
	}

	if a.e2eeHasKey {
		a.e2eePub = kp.Public
	}
	a.client.SetE2EEKeyPair(kp, a.e2eeHasKey)
	a.setupSigningKey(screenName)
	a.client.SetE2EEOn(a.cfg.E2EEOn() && a.e2eeHasKey)

	// Load this account's verified peer keys so the UI can flag verified vs.
	// changed vs. unverified conversations.
	t, err := trust.Load(screenName)
	if err != nil {
		slog.Default().Warn("could not load E2EE verification state", "err", err)
		t = trust.Store{}
	}
	a.trustMu.Lock()
	a.trust = t
	a.e2eeDevices = nil
	a.manifestSeen = nil
	a.manifestIssuedAt = 0
	a.linked = false
	a.selfIdentity, a.selfIdentityLoaded = trust.Identity{}, false
	a.identityFlow = ""
	a.trustMu.Unlock()

	// Without this hook no inbound manifest is believed and no peer key is ever
	// learned — silently, since nothing errors. It goes in before anything can
	// query the directory.
	a.installManifestVerifier()
	a.client.SetPeerKeyHandler(a.notePeerKey)
	a.client.SetRoomInviteHandler(a.handleRoomInvite)
	a.client.SetCatchupHandler(a.handleCatchup)
	a.client.SetConnectionRequestHandler(a.handleConnectionRequest)
	a.client.SetConnectionResponseHandler(a.handleConnectionResponse)
	a.restoreRoomKeys()

	// Off the sign-on path: it makes directory round trips, and a slow or
	// missing reply must not hold up the session.
	go a.setupIdentity()
}

// setupSigningKey loads or mints this device's room-message signing key.
//
// Separate from the encryption key because the two do different jobs: X25519
// agrees on secrets, Ed25519 proves authorship. A room's group key is shared,
// so without this any member could produce messages attributed to anyone else.
func (a *App) setupSigningKey(screenName string) {
	var kp e2ee.SigningKeyPair
	have := false

	if seedB64, err := secret.RetrieveSigningSeed(screenName); err != nil {
		slog.Default().Warn("could not read the signing key", "err", err)
	} else if seedB64 != "" {
		if seed, derr := e2ee.DecodeSigningSeed(seedB64); derr == nil {
			if loaded, lerr := e2ee.SigningKeyFromSeed(seed); lerr == nil {
				kp, have = loaded, true
			}
		}
	}
	if a.cfg.E2EEOn() && !have {
		if generated, err := e2ee.GenerateSigningKey(); err == nil {
			if serr := secret.StoreSigningSeed(screenName, e2ee.EncodeSigningSeed(generated)); serr != nil {
				// Losing this on restart means past messages stay verifiable
				// (the public key is what verifies) but future ones are signed
				// by a new identity peers must learn.
				slog.Default().Warn("could not save the signing key", "err", serr)
			}
			kp, have = generated, true
		}
	}
	a.signPub, a.hasSignKey = nil, false
	if have {
		a.signPub, a.hasSignKey = kp.Public, true
	}
	a.client.SetSigningKey(kp, have)
}

// notePeerKey records the device set we just saw for a peer.
//
// Under key directory v2 this is no longer where a key substitution would be
// caught. Every device set arrives inside a manifest signed by the peer's
// account identity, so the server cannot insert, omit or roll back a device
// without the signature failing — and the one thing it CAN do, replace the
// identity outright, is caught in acceptCounter and announced there.
//
// What remains is informational: a peer adding a machine is worth a quiet line,
// because messages to them are now encrypted to it as well. It is deliberately
// not a warning any more. Warning about a change that is cryptographically
// accounted for is exactly the churn that teaches people to dismiss these.
func (a *App) notePeerKey(screenName string, keys, _ [][32]byte) {
	encoded := e2ee.EncodeKeys(keys)
	key := state.NormalizeScreenName(screenName)

	a.trustMu.Lock()
	if a.trust == nil {
		a.trust = trust.Store{}
	}
	entry := a.trust[key]
	prevSeen := entry.Seen
	if prevSeen == encoded {
		a.trustMu.Unlock()
		return // nothing changed; the common path does no work
	}
	entry.Seen = encoded
	a.trust[key] = entry
	snapshot := a.cloneTrustLocked()
	a.trustMu.Unlock()

	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		slog.Default().Warn("could not save E2EE key state", "err", err)
	}

	// First sighting is trust-on-first-use, not a change — nothing to say.
	if prevSeen == "" {
		return
	}
	if e2ee.KeysOnlyAdded(e2ee.DecodeKeys(prevSeen), keys) {
		a.store.Notify(state.NoticeInfo, screenName+" added another device. Messages to them "+
			"are now encrypted to all of their devices. Your safety number is unchanged — it "+
			"follows their account, not their machines.")
		return
	}

	// A device disappeared. For 1:1 that is a removal the peer signed and needs
	// no eyebrow — but their ROOM keys are a different matter. A room key is
	// sealed to every device an account publishes, so the removed one still holds
	// every room key it was ever given, and OSCAR will happily let it rejoin a
	// room whose name it knows. Re-key the rooms it could still read.
	//
	// Off this goroutine: this runs on the client's read loop, and re-keying
	// makes a send per member per room.
	go a.rotateRoomsAfterDeviceRemoval(screenName)
}

// wireProfile is the profile as sent to the server: the user's bio, and nothing
// else. Device keys used to be appended here as a hidden marker; they now live
// solely in the key directory (foodgroup 0xBE00).
func (a *App) wireProfile() string {
	return a.cfg.Profile
}

// publishProfile pushes the current wire profile to the server (a no-op when
// not signed on).
func (a *App) publishProfile() {
	if a.client.SignedOn() {
		_ = a.client.SetProfile(a.wireProfile())
	}
}

// ConversationEncrypted reports whether messages to a buddy will currently be
// end-to-end encrypted (E2EE on and their published key known).
func (a *App) ConversationEncrypted(screenName string) bool {
	return a.client.CanEncryptTo(screenName)
}

// PrepareConversation fetches a peer's keys when a conversation is opened, so
// the lock badge is right before the first message rather than after it.
//
// Every BENCchat account publishes an identity, so the expectation is that a
// peer HAS keys; this just goes and gets them. It blocks on the Go side (a
// directory round trip), but the Wails call is async to the UI. Returns whether
// the conversation is now encryptable, so the caller can refresh the badge
// without a second round trip.
func (a *App) PrepareConversation(screenName string) bool {
	a.client.EnsurePeerKeys(screenName)
	return a.client.CanEncryptTo(screenName)
}

// Verification is the safety-number state of a 1:1 conversation, for the UI's
// verify dialog and lock badge.
type Verification struct {
	// SafetyNumber is the shared code both parties compare out of band. Empty
	// when neither side has an identity yet (Status "unavailable").
	//
	// It is derived from both accounts' IDENTITY keys, not from their device
	// sets. That is the payoff of cross-signing: devices come and go beneath an
	// identity, all signed by it, and this number moves for exactly one event —
	// the identity itself being replaced. Which is the one event genuinely
	// worth interrupting someone for.
	SafetyNumber string `json:"safetyNumber"`
	// SafetyEmoji is the SAME code rendered as emoji — not a second, weaker
	// thing to check. Both are shown because matching either proves the same
	// fact, and people will actually read this one.
	SafetyEmoji []e2ee.SafetyEmoji `json:"safetyEmoji"`
	// Status is one of:
	//   "unavailable" — no identity for one side yet, nothing to verify
	//   "unverified"  — identity known but not yet confirmed (trust-on-first-use)
	//   "verified"    — user confirmed this exact identity out of band
	//   "changed"     — the peer's identity differs from the one verified
	//   "device-added"— same identity, plus machines: they added a device
	//
	// "device-added" is kept and should now essentially never be seen, which is
	// the point of the change: a device addition no longer disturbs the safety
	// number, so it has nothing to explain away.
	Status string `json:"status"`
	// Devices is how many devices the peer's manifest names.
	Devices int `json:"devices"`
}

// VerificationInfo returns the safety number and verification status for a
// conversation, so the UI can show the code to compare and reflect trust state.
func (a *App) VerificationInfo(screenName string) Verification {
	ourPin := a.selfIdentityPin()
	if ourPin.Key == "" {
		return Verification{Status: "unavailable"}
	}
	ours, err := e2ee.DecodeIdentityPublic(ourPin.Key)
	if err != nil {
		return Verification{Status: "unavailable"}
	}

	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	entry := a.trust[key]
	a.trustMu.Unlock()
	if entry.Identity.Key == "" {
		// No verified manifest from them yet. Not an error: they may simply
		// never have bootstrapped an identity.
		return Verification{Status: "unavailable"}
	}
	theirs, err := e2ee.DecodeIdentityPublic(entry.Identity.Key)
	if err != nil {
		return Verification{Status: "unavailable"}
	}

	peerKeys, _ := a.client.PeerKeys(screenName)
	v := Verification{
		SafetyNumber: e2ee.IdentitySafetyNumber(ours, theirs),
		SafetyEmoji:  e2ee.IdentitySafetyEmoji(ours, theirs),
		Status:       "unverified",
		Devices:      len(peerKeys),
	}

	current := e2ee.EncodeKeys(peerKeys)
	switch {
	case entry.Verified != "" && entry.Verified != entry.Identity.Key:
		// Either they re-bootstrapped, or somebody replaced their identity —
		// and a record written by an older BENCchat, which verified a device
		// set rather than an identity, also lands here and asks for one
		// re-verification. See trust.Entry.
		v.Status = "changed"
	case entry.Verified != "":
		v.Status = "verified"
	case entry.Seen != "" && entry.Seen != current &&
		e2ee.KeysOnlyAdded(e2ee.DecodeKeys(entry.Seen), peerKeys):
		v.Status = "device-added"
	}
	return v
}

// MarkVerified records the peer's current IDENTITY as verified: the user
// compared safety numbers and they matched.
//
// What gets recorded is the identity rather than the device set, so it survives
// the peer adding or retiring machines — and a later identity replacement, the
// one thing that does move the number, flips this to "changed".
func (a *App) MarkVerified(screenName string) string {
	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	if a.trust == nil {
		a.trust = trust.Store{}
	}
	entry := a.trust[key]
	if entry.Identity.Key == "" {
		a.trustMu.Unlock()
		return "No verified device list for this person yet, so there's nothing to compare."
	}
	entry.Verified = entry.Identity.Key
	a.trust[key] = entry
	snapshot := a.cloneTrustLocked()
	a.trustMu.Unlock()
	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		return err.Error()
	}
	return ""
}

// Unverify forgets a previously-verified identity, dropping the conversation
// back to trust-on-first-use. Returns an error string (empty on success).
func (a *App) Unverify(screenName string) string {
	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	// Drop the verification but keep the identity pin: forgetting that would
	// reset the counter high-water mark too, re-arming every replay it refuses.
	entry := a.trust[key]
	entry.Verified = ""
	if entry.Seen == "" && entry.Identity.Key == "" {
		delete(a.trust, key)
	} else {
		a.trust[key] = entry
	}
	snapshot := a.cloneTrustLocked()
	a.trustMu.Unlock()
	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		return err.Error()
	}
	return ""
}

// cloneTrustLocked returns a copy of the trust map for saving off-lock. The
// caller must hold trustMu.
func (a *App) cloneTrustLocked() trust.Store {
	out := make(trust.Store, len(a.trust))
	for k, v := range a.trust {
		out[k] = v
	}
	return out
}
