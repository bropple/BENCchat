package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/benco-holdings/benchat/internal/config"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/secret"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/wailsapp/wails/v2/pkg/runtime"
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

// setupE2EE loads (or, when enabling for the first time, generates) the account's
// keypair after sign-on, wires it into the client, and publishes the public key
// in the profile. Best-effort: a keyring failure disables encryption for the
// session rather than blocking sign-on.
func (a *App) setupE2EE(screenName string) {
	a.e2eeHasKey = false
	var kp e2ee.KeyPair

	// A read that FAILED and a store that holds nothing are different answers,
	// and only one of them means "generate a key". Minting on failure gives this
	// device a new identity every time the keyring is locked or slow to start:
	// every contact sees the safety number change, the old key is still in the
	// account's device set, and nothing prunes it — so repeated failures fill
	// the 32-device cap with dead keys until a real device gets evicted.
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
				"that would change your safety number and look like a key substitution to "+
				"your contacts. Unlock your keychain and sign in again.")
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
	a.trustMu.Unlock()

	// Fresh session, fresh linking memory: a device the user declined last time
	// gets to ask again rather than being ignored forever.
	a.resetLinkState()

	a.client.SetPeerKeyHandler(a.notePeerKey)
	a.client.SetDeviceMessageHandler(a.handleDeviceMessage)
	a.client.SetRoomInviteHandler(a.handleRoomInvite)
	a.client.SetCatchupHandler(a.handleCatchup)
	a.restoreRoomKeys()

	// Check for another device before publishing, not after: publishing
	// overwrites the very evidence we'd be looking for. Runs off the sign-on
	// path so a slow or missing reply can't hold up the session.
	go a.publishAfterDeviceCheck()
}

// publishAfterDeviceCheck merges this device's key into whatever the account
// already advertises, so a second machine ADDS itself rather than overwriting
// the first. Senders encrypt to every listed device, so all of them stay
// readable.
//
// Reading before writing is the whole point: publishing first would destroy the
// list we need to merge into. Each device re-adds itself on every sign-on, so a
// list clobbered by a race repairs itself the next time that device connects.
func (a *App) publishAfterDeviceCheck() {
	if !a.cfg.E2EEOn() || !a.e2eeHasKey {
		a.publishProfile()
		return
	}

	// Whether this device is already part of the account, judged BEFORE we add
	// ourselves to the list below. An account that already advertises devices,
	// none of which is ours, means we're the new machine and somebody has to
	// approve us — which the user otherwise has no way of knowing, since the
	// approval happens on the other device entirely.
	published, has, ok := a.ownPublishedKeys()
	notLinked := false

	// Where the device list comes from, and why it is NOT always a merge.
	//
	// The key directory is authoritative: it answers from server storage, so it
	// lists every device including machines that are currently offline. Taking
	// it as-is is what makes removal work across machines. Merging our own
	// remembered list into it would republish devices another machine removed —
	// each machine re-uploading its stale memory of the account, so a removal
	// performed on one is undone by the next one to sign on.
	//
	// Under the profile scheme a merge was unavoidable: the server kept the
	// profile on the live session and dropped it at sign-off, so it only ever
	// reported devices that were online, and without merging, any machine that
	// happened to be off was silently dropped and stopped being able to read
	// anything sent while it was away. The directory has no such gap, so the
	// workaround is retired with the thing it worked around.
	var merged [][32]byte
	authoritative := a.client.SupportsKeyDir() && ok

	if !authoritative {
		// Fallback path, or a directory query that failed. Here the server's
		// answer really is incomplete, so the local record is all that keeps an
		// offline machine in the list.
		remembered, err := trust.LoadDevices(a.currentAccount())
		if err != nil {
			slog.Default().Warn("could not read remembered device keys", "err", err)
		}
		merged = e2ee.DecodeKeys(strings.Join(remembered, ","))
		if !ok {
			slog.Default().Warn("could not read the published device set; using the remembered one")
			published = nil
		}
	}

	if ok && has {
		known := false
		for _, k := range published {
			if k == a.e2eePub {
				known = true
				break
			}
		}
		if !known && len(published) > 0 {
			// Quietly: the explanation waits until publishDevices reports
			// whether this device was refused, so the user gets one reason
			// rather than two contradictory ones.
			notLinked = a.setLinkPendingQuiet()
		}
		merged = append(merged, published...)
	}
	merged = append(merged, a.e2eePub)

	// Everything observed this sign-on counts as seen now; anything only
	// remembered keeps whatever timestamp it had. That is what lets the cap
	// evict the machine nobody has used in months rather than an arbitrary one.
	now := time.Now().Unix()
	seen, err := trust.LoadDeviceSeen(a.currentAccount(), now)
	if err != nil {
		slog.Default().Warn("could not read device timestamps", "err", err)
		seen = map[string]int64{}
	}
	for _, k := range published {
		seen[e2ee.EncodeKey(k)] = now
	}
	seen[e2ee.EncodeKey(a.e2eePub)] = now

	kept := e2ee.PickDevices(a.e2eePub, merged, seen)
	if dropped := len(e2ee.DecodeKeys(e2ee.EncodeKeys(merged))) - len(kept); dropped > 0 {
		// Never silently: a dropped key means messages sent to that machine
		// stop being readable there, which is worth saying out loud.
		a.store.Notify(state.NoticeWarn, fmt.Sprintf(
			"This account is at the %d-device limit, so %d least-recently-used device key(s) "+
				"were dropped. Remove devices you no longer use in Privacy & Security.",
			e2ee.MaxDevices, dropped))
	}

	a.setDeviceKeys(kept)
	devices := a.deviceKeys()
	if err := trust.SaveDevicesSeen(a.currentAccount(),
		strings.Split(e2ee.EncodeKeys(devices), ","), seen); err != nil {
		slog.Default().Warn("could not remember device keys", "err", err)
	}
	// publishDevices reports whether THIS device was refused, which means it was
	// removed rather than merely new — a different situation needing different
	// words, already explained by onRevokedDeviceReturned.
	accepted, wasRefused := a.publishDevices(devices)
	if notLinked && !wasRefused {
		a.notifyNotLinked()
	}
	// Say hello to any other session on this account, so a new machine can be
	// linked without typing codes.
	a.announceDevice()

	// Count what the SERVER accepted, not what we hoped to publish. Reporting
	// the local list meant announcing "3 devices" in the same breath as the
	// server refusing two of them, which is worse than saying nothing.
	// The publish reply already says how many the server stored, so this needs
	// no second round trip — and the extra query it replaces was racing the very
	// publish it was meant to report on, which is how "2 devices" appeared in
	// the same breath as one of them being refused.
	if n := accepted; n > 1 {
		a.store.Notify(state.NoticeInfo, fmt.Sprintf(
			"This account has %d devices set up for encryption. Messages sent to you are "+
				"encrypted to all of them.", n))
	}
	// Warn while there is still room to act, not once the cap is already
	// evicting things.
	if n := len(devices); n >= e2ee.MaxDevices*3/4 && n < e2ee.MaxDevices {
		a.store.Notify(state.NoticeWarn, fmt.Sprintf(
			"This account has %d device keys, close to the limit of %d. Old keys are not "+
				"removed automatically — prune ones you no longer use in Privacy & Security.",
			n, e2ee.MaxDevices))
	}
}

// ForgetOtherDevices drops every device key except this machine's, for when a
// device is decommissioned. Senders would otherwise keep encrypting to a key
// nothing can read — harmless but wasteful, and it keeps the safety number
// pinned to a machine that no longer exists.
func (a *App) ForgetOtherDevices() string {
	if !a.e2eeHasKey {
		return "Encryption is not set up on this device."
	}
	var gone [][32]byte
	for _, k := range a.deviceKeys() {
		if k != a.e2eePub {
			gone = append(gone, k)
		}
	}
	a.setDeviceKeys([][32]byte{a.e2eePub})
	if err := trust.SaveDevices(a.currentAccount(), []string{e2ee.EncodeKey(a.e2eePub)}); err != nil {
		return err.Error()
	}
	// Revoke before republishing, so the account never briefly advertises a
	// device that was just removed. See RemoveDevice.
	a.revokeDevices(gone)
	for _, k := range gone {
		a.forgetLinkPrompt(k)
		a.rememberKnownDevice(k)
	}
	a.publishDevices([][32]byte{a.e2eePub})
	a.store.Notify(state.NoticeInfo,
		"Other devices removed. Your contacts will see your safety number change.")
	return ""
}

// DeviceCount reports how many devices this account publishes keys for, so the
// settings panel can show it.
func (a *App) DeviceCount() int { return len(a.deviceKeys()) }

// deviceKeys returns this account's published device set (ours included).
func (a *App) deviceKeys() [][32]byte {
	a.trustMu.Lock()
	defer a.trustMu.Unlock()
	return a.e2eeDevices
}

func (a *App) setDeviceKeys(keys [][32]byte) {
	a.trustMu.Lock()
	a.e2eeDevices = e2ee.DecodeKeys(e2ee.EncodeKeys(keys)) // sort + dedupe
	a.trustMu.Unlock()
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

// notePeerKey records the key we just saw for a peer and warns when it differs
// from the one we recorded before.
//
// This deliberately fires for UNVERIFIED peers too. Verification is opt-in and
// most conversations never get it, so keying the warning off verification alone
// would leave the common case — a silently swapped key — completely unannounced,
// which is exactly the substitution end-to-end encryption is meant to expose.
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
	wasVerified := entry.Verified != "" && entry.Verified != encoded
	a.trustMu.Unlock()

	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		slog.Default().Warn("could not save E2EE key state", "err", err)
	}

	// First sighting is trust-on-first-use, not a change — nothing to warn about.
	if prevSeen == "" {
		return
	}

	// Someone adding a second machine is routine and must not be dressed up as
	// an attack; a key that USED to be there and now isn't is the alarming case.
	if e2ee.KeysOnlyAdded(e2ee.DecodeKeys(prevSeen), keys) {
		a.store.Notify(state.NoticeInfo, screenName+" added another device. Messages to "+
			"them are now encrypted to all of their devices; their safety number has changed.")
		return
	}
	msg := screenName + "'s encryption keys changed. That's expected if they " +
		"reinstalled BENCchat, but it can also mean someone is intercepting " +
		"your messages. Compare safety numbers before trusting it."
	if wasVerified {
		msg = screenName + "'s encryption keys changed, and they no longer match " +
			"what you verified. Compare safety numbers again before trusting it."
	}
	a.store.Notify(state.NoticeWarn, msg)
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

// SetE2EEEnabled turns opt-in end-to-end encryption on or off. Enabling
// generates a keypair if needed and republishes the profile with the key so
// peers can encrypt to us. Returns an error string on failure.
func (a *App) SetE2EEEnabled(on bool) string {
	a.cfg.E2EEEnabled = &on
	if on && !a.e2eeHasKey {
		kp, err := e2ee.GenerateKeyPair()
		if err != nil {
			return err.Error()
		}
		if serr := secret.StorePrivateKey(a.currentAccount(), e2ee.EncodeKey(kp.Private)); serr != nil {
			slog.Default().Warn("could not save E2EE key", "err", serr)
		}
		a.e2eePub, a.e2eeHasKey = kp.Public, true
		a.client.SetE2EEKeyPair(kp, true)
	}
	a.client.SetE2EEOn(on && a.e2eeHasKey)
	_ = config.Save(a.cfg)
	a.publishProfile()
	return ""
}

// ConversationEncrypted reports whether messages to a buddy will currently be
// end-to-end encrypted (E2EE on and their published key known).
func (a *App) ConversationEncrypted(screenName string) bool {
	return a.client.CanEncryptTo(screenName)
}

// Verification is the safety-number state of a 1:1 conversation, for the UI's
// verify dialog and lock badge.
type Verification struct {
	// SafetyNumber is the shared code both parties compare out of band. Empty
	// when no key exchange has happened yet (Status "unavailable").
	SafetyNumber string `json:"safetyNumber"`
	// Status is one of:
	//   "unavailable" — no peer key yet, nothing to verify
	//   "unverified"  — key known but not yet confirmed (trust-on-first-use)
	//   "verified"    — user confirmed this exact key out of band
	//   "changed"     — the peer's keys differ from what was previously seen
	//   "device-added"— same keys as before plus new ones: they added a machine
	Status string `json:"status"`
	// Devices is how many devices the peer publishes keys for.
	Devices int `json:"devices"`
}

// VerificationInfo returns the safety number and verification status for a
// conversation, so the UI can show the code to compare and reflect trust state.
func (a *App) VerificationInfo(screenName string) Verification {
	_, hasOur := a.client.OurPublicKey()
	peerKeys, hasPeer := a.client.PeerKeys(screenName)
	if !hasOur || !hasPeer {
		return Verification{Status: "unavailable"}
	}
	ourDevices := a.deviceKeys()
	if len(ourDevices) == 0 {
		ourDevices = [][32]byte{a.e2eePub}
	}
	v := Verification{
		SafetyNumber: e2ee.SafetyNumberSet(ourDevices, peerKeys),
		Status:       "unverified",
		Devices:      len(peerKeys),
	}
	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	entry := a.trust[key]
	a.trustMu.Unlock()

	current := e2ee.EncodeKeys(peerKeys)
	switch {
	case entry.Verified == current && current != "":
		v.Status = "verified"
	case entry.Verified != "":
		// Verified once, but they're presenting a different set now. A pure
		// addition is expected (a new machine) rather than suspicious, so it gets
		// its own status the UI can present calmly.
		if e2ee.KeysOnlyAdded(e2ee.DecodeKeys(entry.Verified), peerKeys) {
			v.Status = "device-added"
		} else {
			v.Status = "changed"
		}
	case entry.Seen != "" && entry.Seen != current:
		if e2ee.KeysOnlyAdded(e2ee.DecodeKeys(entry.Seen), peerKeys) {
			v.Status = "device-added"
		} else {
			v.Status = "changed"
		}
	}
	return v
}

// MarkVerified records the peer's current key as verified (the user compared
// safety numbers and they matched). A later key change flips the status to
// "changed". Returns an error string (empty on success).
func (a *App) MarkVerified(screenName string) string {
	peerKeys, ok := a.client.PeerKeys(screenName)
	if !ok {
		return "No encryption key known for this person yet."
	}
	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	if a.trust == nil {
		a.trust = trust.Store{}
	}
	encoded := e2ee.EncodeKeys(peerKeys)
	a.trust[key] = trust.Entry{Verified: encoded, Seen: encoded}
	snapshot := a.cloneTrustLocked()
	a.trustMu.Unlock()
	if err := trust.Save(a.currentAccount(), snapshot); err != nil {
		return err.Error()
	}
	return ""
}

// Unverify forgets a previously-verified key, dropping the conversation back to
// trust-on-first-use. Returns an error string (empty on success).
func (a *App) Unverify(screenName string) string {
	key := state.NormalizeScreenName(screenName)
	a.trustMu.Lock()
	// Drop the verification but keep the last-seen key: forgetting it entirely
	// would reset trust-on-first-use and silently swallow the next key change.
	entry := a.trust[key]
	entry.Verified = ""
	if entry.Seen == "" {
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

// --- Device linking -------------------------------------------------------

// DeviceInfo describes one device on this account, for the settings list.
type DeviceInfo struct {
	Key         string `json:"key"`         // base64 public key, the removal handle
	Fingerprint string `json:"fingerprint"` // short comparable code
	ThisDevice  bool   `json:"thisDevice"`
}

// ListDevices returns every device this account has keys for.
func (a *App) ListDevices() []DeviceInfo {
	devices := a.deviceKeys()
	out := make([]DeviceInfo, 0, len(devices))
	for _, k := range devices {
		out = append(out, DeviceInfo{
			Key:         e2ee.EncodeKey(k),
			Fingerprint: e2ee.Fingerprint(k),
			ThisDevice:  k == a.e2eePub,
		})
	}
	return out
}

// RemoveDevice drops a device from the account's key set, so senders stop
// encrypting to it. Removing THIS device is refused — it would make every
// incoming message unreadable here while looking like a tidy-up.
func (a *App) RemoveDevice(keyB64 string) string {
	target, err := e2ee.DecodeKey(keyB64)
	if err != nil {
		return "That doesn't look like a device key."
	}
	if target == a.e2eePub {
		return "That's this device — removing it would stop you reading your own messages."
	}
	var kept [][32]byte
	for _, k := range a.deviceKeys() {
		if k != target {
			kept = append(kept, k)
		}
	}
	a.setDeviceKeys(kept)
	if err := trust.SaveDevices(a.currentAccount(), strings.Split(e2ee.EncodeKeys(kept), ",")); err != nil {
		return err.Error()
	}
	// Revoke BEFORE republishing. The server refuses to accept a revoked key, so
	// doing it the other way round would publish the device we are removing and
	// then tombstone it, leaving the account briefly advertising a device the
	// user just took away.
	a.revokeDevices([][32]byte{target})
	// Let this device ask again. markLinkPrompted suppresses a second dialog
	// for a device already prompted this session, which is right for a sibling
	// reconnecting — but after a REMOVAL the next announcement is exactly the
	// one the user needs to see, and swallowing it makes the "approve it again"
	// advice impossible to follow.
	a.forgetLinkPrompt(target)
	// Remember we knew it. A device coming back after removal is a different
	// event from a device appearing for the first time, and the approving side
	// has no other way to tell them apart — the announcement looks identical.
	a.rememberKnownDevice(target)
	a.publishDevices(kept)
	a.store.Notify(state.NoticeInfo,
		"Device removed. Your contacts will see your safety number change.")
	return ""
}

// announceDevice tells this account's other sessions that this machine exists.
// Harmless if nothing else is signed on — nobody hears it.
func (a *App) announceDevice() {
	if !a.cfg.E2EEOn() || !a.e2eeHasKey {
		return
	}
	if err := a.client.SendDeviceMessage(e2ee.DeviceAnnounce, [][32]byte{a.e2eePub}); err != nil {
		slog.Default().Warn("could not announce this device", "err", err)
	}
}

// handleDeviceMessage processes linking traffic from another session on this
// account.
func (a *App) handleDeviceMessage(kind string, keys [][32]byte) {
	switch kind {
	case e2ee.DeviceDeny:
		if len(keys) != 1 || keys[0] != a.e2eePub {
			return // aimed at a different device
		}
		// Sign out rather than sit here unusable. Clearing the saved password
		// matters as much as the message: otherwise the next launch signs
		// straight back in and asks to be approved all over again, which looks
		// like the denial did nothing.
		//
		// This is a courtesy, not a boundary — whoever is here still knows the
		// password and can sign in again. What it buys is that a person who was
		// refused finds out, instead of wondering why nothing decrypts.
		a.store.Notify(state.NoticeError,
			"Your request to link this device was denied, so it can't read encrypted "+
				"messages. You have been signed out and your saved password cleared.")
		a.forgetRemembered()
		go a.SignOff()
		return

	case e2ee.DeviceAnnounce:
		if len(keys) != 1 {
			return
		}
		newKey := keys[0]
		// The server echoes our own announcement back to us; ignore it, or a
		// device would try to approve itself.
		if newKey == a.e2eePub {
			return
		}
		// Already linked: nothing to approve, but do re-share so the other side
		// converges on the full list if it's missing anyone.
		if a.knowsDevice(newKey) {
			a.shareDeviceList()
			return
		}
		// Remember it regardless of whether we prompt. A fingerprint is a hash
		// and cannot be reversed, so linking by code later can only work against
		// keys actually seen — and the cases that need it most (the pop-up was
		// dismissed, or suppressed because this device was prompted earlier) are
		// exactly the ones where the announcement arrived and the dialog did not.
		a.rememberAnnouncedDevice(newKey)

		// Ask once per device per session. A sibling that announces again —
		// reconnecting, or an auto-login racing a manual sign-on — must not
		// stack a second dialog on top of the one already open, which is how
		// the same device ended up being approved twice.
		if !a.markLinkPrompted(newKey) {
			return
		}
		// Otherwise the user has to approve it. Password knowledge alone must not
		// be enough to silently join an account and read everything.
		// Say whether this is a device we have linked before. A machine coming
		// back after being removed is a different event from one appearing for
		// the first time, and calling a laptop you have used for weeks "new"
		// invites approving it without looking — which is the one moment the
		// code comparison actually matters.
		returning := "0"
		if a.wasKnownDevice(newKey) {
			returning = "1"
		}
		runtime.EventsEmit(a.ctx, "device:link-request", map[string]string{
			"key":         e2ee.EncodeKey(newKey),
			"fingerprint": e2ee.Fingerprint(newKey),
			"returning":   returning,
		})

	case e2ee.DeviceShare:
		// An already-linked device sent us the full list. Merge it — this is how
		// a newly-approved machine learns about its siblings.
		merged := append(a.deviceKeys(), keys...)
		merged = append(merged, a.e2eePub)
		a.setDeviceKeys(merged)
		if err := trust.SaveDevices(a.currentAccount(),
			strings.Split(e2ee.EncodeKeys(a.deviceKeys()), ",")); err != nil {
			slog.Default().Warn("could not save merged device list", "err", err)
		}
		a.publishProfile()

		// A list that includes our own key is somebody answering the approval
		// we were waiting on: we're linked now, so stop saying otherwise.
		for _, k := range keys {
			if k == a.e2eePub {
				a.clearLinkPending()
				break
			}
		}
	}
}

// markLinkPrompted records that a key has been shown to the user, returning
// false when it already had been (or was declined) and should not be shown
// again this session.
func (a *App) markLinkPrompted(k [32]byte) bool {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	if a.linkPrompted[k] || a.linkDeclined[k] {
		return false
	}
	if a.linkPrompted == nil {
		a.linkPrompted = map[[32]byte]bool{}
	}
	a.linkPrompted[k] = true
	return true
}

// resetLinkState clears per-session linking memory. Called on sign-on so a new
// session re-asks about a device the user previously declined, rather than
// silently ignoring it forever.
func (a *App) resetLinkState() {
	a.linkMu.Lock()
	a.linkPrompted = map[[32]byte]bool{}
	a.linkDeclined = map[[32]byte]bool{}
	a.linkPending = false
	a.linkNoticeShown = false
	a.linkMu.Unlock()
}

// setLinkPending records that this device is waiting to be approved elsewhere,
// and tells the user how — including this device's own code, which the
// approving machine asks them to compare against.
func (a *App) setLinkPending() {
	if a.setLinkPendingQuiet() {
		a.notifyNotLinked()
	}
}

// setLinkPendingQuiet records the pending state without explaining it, returning
// whether this is the first time this session.
//
// Split out because "unlinked" has two causes that need different words: a
// genuinely NEW device, and one that was REMOVED. Which applies is only known
// after the publish either succeeds or is refused, so the state is recorded
// first and the explanation chosen afterwards. Emitting during the read is what
// produced two contradictory notices at the same instant.
func (a *App) setLinkPendingQuiet() bool {
	a.linkMu.Lock()
	already := a.linkPending
	a.linkPending = true
	a.linkMu.Unlock()
	if already {
		return false
	}
	a.emitLinkState()
	return true
}

// notifyNotLinked explains the NEW-device case.
func (a *App) notifyNotLinked() {
	if !a.claimLinkNotice() {
		return
	}
	a.store.Notify(state.NoticeWarn, fmt.Sprintf(
		"This device isn't linked yet, so it can't read messages encrypted to your "+
			"other devices. Approve it from a device that's already signed in — its "+
			"code is %s.", e2ee.Fingerprint(a.e2eePub)))
}

// claimLinkNotice returns true for the FIRST caller each sign-on that wants to
// explain why this device cannot read encrypted messages.
//
// There are two explanations — "you are new" and "you were removed" — and they
// describe the same state, so emitting both contradicts. Twice now I have tried
// to fix that by ordering the calls, and twice the duplicate survived, which
// means my model of the ordering is wrong rather than the ordering being
// slightly off. A claim makes it structurally impossible instead: whichever
// path gets there first explains it, and the rest stay quiet no matter how they
// interleave or how many goroutines reach them.
func (a *App) claimLinkNotice() bool {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	if a.linkNoticeShown {
		return false
	}
	a.linkNoticeShown = true
	return true
}

// forgetLinkPrompt lets a device raise the approval dialog again.
func (a *App) forgetLinkPrompt(k [32]byte) {
	a.linkMu.Lock()
	delete(a.linkPrompted, k)
	delete(a.linkDeclined, k)
	a.linkMu.Unlock()
}

func (a *App) clearLinkPending() {
	a.linkMu.Lock()
	was := a.linkPending
	a.linkPending = false
	a.linkMu.Unlock()
	if !was {
		return
	}
	a.emitLinkState()
	a.store.Notify(state.NoticeInfo, "This device is now linked to your account.")
}

// DeviceLinkState reports whether this device is still waiting to be approved,
// and its own code so the user can compare it with the approving device.
type DeviceLinkState struct {
	Pending     bool   `json:"pending"`
	Fingerprint string `json:"fingerprint"`
}

// GetDeviceLinkState is read by the settings panel to show the pending banner.
func (a *App) GetDeviceLinkState() DeviceLinkState {
	a.linkMu.Lock()
	pending := a.linkPending
	a.linkMu.Unlock()
	fp := ""
	if a.e2eeHasKey {
		fp = e2ee.Fingerprint(a.e2eePub)
	}
	return DeviceLinkState{Pending: pending, Fingerprint: fp}
}

func (a *App) emitLinkState() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "device:link-state", a.GetDeviceLinkState())
}

// DeclineDevice records that the user refused a link request, so the same
// device announcing again doesn't re-ask for the rest of this session.
func (a *App) DeclineDevice(keyB64 string) string {
	key, err := e2ee.DecodeKey(keyB64)
	if err != nil {
		return "That doesn't look like a device key."
	}
	a.linkMu.Lock()
	if a.linkDeclined == nil {
		a.linkDeclined = map[[32]byte]bool{}
	}
	a.linkDeclined[key] = true
	a.linkMu.Unlock()

	a.rememberKnownDevice(key)

	if a.client != nil && a.client.SignedOn() {
		// Record the refusal on the server FIRST. The live message below only
		// reaches a device that is connected right now, so on its own a denial
		// evaporates if that machine happened to be offline — and it would ask
		// again on its next sign-on as though nothing had been decided. A
		// tombstone makes the answer outlive the moment it was given: the device
		// is refused whenever it next tries to publish.
		a.revokeDevices([][32]byte{key})

		// Then tell it, so a connected device finds out immediately rather than
		// discovering it at some later sign-on. Every session on this account
		// hears this; only the one whose key matches acts on it.
		if err := a.client.SendDeviceMessage(e2ee.DeviceDeny, [][32]byte{key}); err != nil {
			slog.Default().Warn("could not tell the device it was denied", "err", err)
		}
	}
	return ""
}

func (a *App) knowsDevice(k [32]byte) bool {
	for _, have := range a.deviceKeys() {
		if have == k {
			return true
		}
	}
	return false
}

// shareDeviceList broadcasts the full known device set to our other sessions.
func (a *App) shareDeviceList() {
	devices := a.deviceKeys()
	if len(devices) == 0 {
		return
	}
	if err := a.client.SendDeviceMessage(e2ee.DeviceShare, devices); err != nil {
		slog.Default().Warn("could not share the device list", "err", err)
	}
}

// ApproveDevice links a device the user just confirmed: add it, publish, and
// send the full list back so the new machine learns its siblings.
func (a *App) ApproveDevice(keyB64 string) string {
	newKey, err := e2ee.DecodeKey(keyB64)
	if err != nil {
		return "That doesn't look like a device key."
	}
	// Approving something already linked is a no-op, not a second link. Worth
	// being explicit: two dialogs for one device used to be reachable, and
	// re-running the whole publish/share/notify sequence made it look like two
	// devices had joined.
	if a.knowsDevice(newKey) {
		return ""
	}
	// Lift any revocation FIRST. Approving a device the user previously removed
	// is the whole reason the refusal notice tells them to come here, and
	// publishing without clearing the tombstone would simply be refused again —
	// leaving the user in a loop with no way out but wiping both machines.
	if restored, ok := a.client.RestoreDevice(newKey); ok && restored {
		a.store.Notify(state.NoticeInfo,
			"That device had been removed from your account. Its removal has been undone.")
	}

	merged := append(a.deviceKeys(), newKey, a.e2eePub)
	a.setDeviceKeys(merged)
	if err := trust.SaveDevices(a.currentAccount(),
		strings.Split(e2ee.EncodeKeys(a.deviceKeys()), ",")); err != nil {
		return err.Error()
	}
	// publishDevices, not publishProfile: approval has to reach the directory or
	// the device stays unpublished and unreadable to everyone.
	a.publishDevices(a.deviceKeys())
	a.shareDeviceList()
	a.store.Notify(state.NoticeInfo, "Device linked. Messages will now be encrypted to it as well.")
	return ""
}

// rememberAnnouncedDevice records a device key seen in an announcement, keyed by
// the code the user is shown.
func (a *App) rememberAnnouncedDevice(k [32]byte) {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	if a.announcedDevices == nil {
		a.announcedDevices = map[string][32]byte{}
	}
	a.announcedDevices[normalizeDeviceCode(e2ee.Fingerprint(k))] = k
}

// normalizeDeviceCode strips the grouping so a code typed with different spacing
// still matches what was displayed.
func normalizeDeviceCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ApproveDeviceByCode links a device identified by the code it displays.
//
// The pop-up is the usual route, but it depends on catching a live announcement:
// dismiss it, or be on a device that was already prompted this session, and
// there is no way back. Both notices tell the user to approve from another
// device, so there has to be somewhere to do that.
//
// It resolves against announcements seen this session rather than reversing the
// code, which is impossible — the code is a hash of the key.
func (a *App) ApproveDeviceByCode(code string) string {
	want := normalizeDeviceCode(code)
	if want == "" {
		return "Enter the code shown on the other device."
	}
	if want == normalizeDeviceCode(e2ee.Fingerprint(a.e2eePub)) {
		return "That's this device's own code — enter the code shown on the other one."
	}

	a.linkMu.Lock()
	key, found := a.announcedDevices[want]
	a.linkMu.Unlock()

	if !found {
		// Being specific about why beats "invalid code": the usual cause is that
		// the other device has not signed in since this one did, so nothing has
		// announced itself yet.
		return "No device with that code has announced itself yet. Sign in on that " +
			"device (or sign it out and back in), then try again."
	}
	return a.ApproveDevice(e2ee.EncodeKey(key))
}

// rememberKnownDevice records a device this account has linked before, so its
// return can be described as a return.
func (a *App) rememberKnownDevice(k [32]byte) {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	if a.knownDevices == nil {
		a.knownDevices = map[[32]byte]bool{}
	}
	a.knownDevices[k] = true
}

// wasKnownDevice reports whether this account has linked that device before.
func (a *App) wasKnownDevice(k [32]byte) bool {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	return a.knownDevices[k]
}
