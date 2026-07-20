package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/benco-holdings/benchat/internal/wire"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// The account identity: first run, linking a device, and what the UI is told.
//
// Which flow this device is in is answered by the directory alone, per proposal
// §10 — there is no "has this account signed in before" flag anywhere:
//
//	GetIdentityBackup Present=false  → first run: generate an identity and show
//	                                   the recovery key once
//	                  Present=true   → link this device: prompt for the recovery
//	                                   key and sign this device into the manifest
//	                  Present=true,
//	                  key lost       → unrecoverable. An admin clears the
//	                                   identity and the account starts over.
//
// The third case has no clever client-side answer and this file does not
// pretend otherwise; it says so and stops.
//
// # Custody
//
// The identity private key is never written anywhere — not the keyring, not
// disk, not a log line (proposal §5). It exists in this process for exactly two
// windows: between generating it and the user acknowledging their recovery key
// (first run, where §12's ordering requires it), and across a single signing
// operation when linking. Both windows end in Zero().

// errNoKeyDir is what every path here fails with on a server that does not
// carry the directory. There is no fallback: device keys live nowhere else, so
// reporting success would claim an encrypted conversation nobody can join.
var errNoKeyDir = errors.New("this server has no key directory, so encryption keys cannot be published")

// pendingIdentity is a first run that has been generated but NOT persisted.
//
// This struct existing is the crash window §12 closes by ordering. Everything in
// it lives in memory only: if the process dies now, the server still reports
// Present=false, the next launch is a clean first run with a new recovery key,
// and nothing has been lost — because nothing was ever written.
type pendingIdentity struct {
	kp          e2ee.IdentityKey
	recoveryKey string
	// stored records that PutIdentityBackup already succeeded, so a retry after
	// a failed publish does not re-upload a second backup under a fresh salt.
	stored bool
}

// IdentityState is what the UI needs to decide which screen to show.
type IdentityState struct {
	// Flow is one of:
	//   "unavailable" — not signed on, encryption off, or no key directory
	//   "setup"       — no identity exists: first run, show the recovery key
	//   "link"        — an identity exists but this device is not in it
	//   "ready"       — this device is signed into the account's manifest
	Flow string `json:"flow"`
	// Fingerprint is this device's short code.
	Fingerprint string `json:"fingerprint"`
	// Devices is how many machines the current manifest names.
	Devices int `json:"devices"`
	// IssuedAt is when the current manifest was signed, Unix seconds UTC, or 0.
	//
	// ADVISORY ONLY. Nothing rejects a manifest for being old (proposal §4): a
	// wrong clock is far likelier than an attack, and a client that hard-failed
	// on time would brick a conversation over a dead CMOS battery. It is here so
	// the UI can say "this device list is three months old".
	IssuedAt uint64 `json:"issuedAt"`
	// RecoveryWords is how many words a recovery key has, so the UI can lay out
	// the right number of input slots.
	RecoveryWords int `json:"recoveryWords"`
}

// GetIdentityState reports which of the three flows this device is in.
func (a *App) GetIdentityState() IdentityState {
	st := IdentityState{Flow: "unavailable", RecoveryWords: e2ee.RecoveryKeyWords}
	if a.e2eeHasKey {
		st.Fingerprint = e2ee.Fingerprint(a.e2eePub)
	}
	a.trustMu.Lock()
	st.Devices = len(a.e2eeDevices)
	st.IssuedAt = a.manifestIssuedAt
	flow := a.identityFlow
	a.trustMu.Unlock()
	if flow != "" {
		st.Flow = flow
	}
	return st
}

func (a *App) setIdentityFlow(flow string) {
	a.trustMu.Lock()
	changed := a.identityFlow != flow
	a.identityFlow = flow
	a.trustMu.Unlock()
	if changed {
		a.emitIdentityState()
	}
}

func (a *App) emitIdentityState() {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "identity:state", a.GetIdentityState())
}

// setupIdentity runs at sign-on and works out which flow this device is in.
//
// It asks the directory, in this order, because each answer only means anything
// given the last: does an identity exist at all, and if so is this device signed
// into it? A failed round trip is reported as a failure and never as "no
// identity" — acting on that mistake would generate a second identity and orphan
// every device trusting the first.
func (a *App) setupIdentity() {
	if !a.cfg.E2EEOn() || !a.e2eeHasKey {
		a.setIdentityFlow("unavailable")
		a.publishProfile()
		return
	}
	a.publishProfile()

	if !a.client.SupportsKeyDir() {
		a.setIdentityFlow("unavailable")
		slog.Default().Error("server has no key directory; encryption keys cannot be published")
		a.store.Notify(state.NoticeError,
			"This server has no key directory, so BENCchat can't publish this device's "+
				"encryption key. Messages will not be encrypted.")
		return
	}

	backup, ok := a.client.GetIdentityBackup()
	if !ok {
		a.setIdentityFlow("unavailable")
		a.store.Notify(state.NoticeWarn,
			"BENCchat couldn't reach the key directory, so it can't tell whether this "+
				"account has an identity yet. Encryption is unavailable this session.")
		return
	}
	if !backup.Present {
		// Row one: nobody has ever bootstrapped this account.
		a.setIdentityFlow("setup")
		a.store.Notify(state.NoticeInfo,
			"This account needs an encryption identity before it can send or read encrypted "+
				"messages. Setting one up takes a moment and produces a recovery key you'll "+
				"need to keep.")
		return
	}

	// An identity exists. Are we in its manifest? QueryManifest's reply is
	// verified on arrival by the installed verifier, which is also what records
	// the pin, the device set and whether this device is listed.
	if _, ok := a.client.QueryManifest(a.store.Self().ScreenName); !ok {
		a.setIdentityFlow("unavailable")
		a.store.Notify(state.NoticeWarn,
			"BENCchat couldn't read this account's device list. Encryption is unavailable "+
				"this session; try signing in again.")
		return
	}
	if a.isLinked() {
		a.setIdentityFlow("ready")
		return
	}
	// Row two: the identity exists and this machine is not part of it. Not an
	// error and not an alarm — it is what every second device looks like before
	// it is linked.
	a.setIdentityFlow("link")
	a.store.Notify(state.NoticeWarn,
		"This device isn't part of your account's encryption yet, so it can't read "+
			"encrypted messages. Link it with your recovery key in Privacy & Security.")
}

// --- First run (proposal §12) ----------------------------------------------

// RecoveryKeyInfo carries the one and only showing of a recovery key.
type RecoveryKeyInfo struct {
	// RecoveryKey is ten hyphen-separated words. It is not stored anywhere and
	// cannot be re-fetched: nothing retains it, so there is nothing to show
	// again. That is a property of the design, not a policy the UI enforces.
	RecoveryKey string `json:"recoveryKey"`
	Error       string `json:"error"`
}

// BeginIdentitySetup performs steps 1–3 of proposal §12: generate the identity
// keypair IN MEMORY, generate the recovery key, and hand it back for display.
//
// Nothing is written by this call — not on the server, not on disk. That is the
// point of splitting it from ConfirmIdentitySetup: a crash, a force quit or a
// power loss before the user acknowledges leaves the account exactly as it was,
// so the next launch is a clean first run with a new recovery key rather than an
// account encrypted under a key nobody ever saw.
func (a *App) BeginIdentitySetup() RecoveryKeyInfo {
	if !a.e2eeHasKey {
		return RecoveryKeyInfo{Error: "Encryption isn't set up on this device yet."}
	}
	if !a.client.SupportsKeyDir() {
		return RecoveryKeyInfo{Error: errNoKeyDir.Error()}
	}

	// Re-check rather than trusting the flow the UI was showing. Generating a
	// second identity for an account that already has one silently orphans every
	// device signed under the first, and the window between deciding and acting
	// is wide enough for another device to have bootstrapped.
	backup, ok := a.client.GetIdentityBackup()
	if !ok {
		return RecoveryKeyInfo{Error: "BENCchat couldn't reach the key directory. Try again."}
	}
	if backup.Present {
		a.setIdentityFlow("link")
		return RecoveryKeyInfo{Error: "This account already has an identity. Link this device with " +
			"your recovery key instead."}
	}

	a.identityMu.Lock()
	defer a.identityMu.Unlock()
	if a.pending != nil {
		// Already generated and waiting on the gate: show the same key again
		// rather than minting a second one, which would leave the user holding
		// a key that no longer opens anything.
		return RecoveryKeyInfo{RecoveryKey: a.pending.recoveryKey}
	}

	kp, err := e2ee.GenerateIdentityKey() // step 1: memory only
	if err != nil {
		return RecoveryKeyInfo{Error: err.Error()}
	}
	rk, err := e2ee.GenerateRecoveryKey() // step 2
	if err != nil {
		kp.Zero()
		return RecoveryKeyInfo{Error: err.Error()}
	}
	a.pending = &pendingIdentity{kp: kp, recoveryKey: rk}
	return RecoveryKeyInfo{RecoveryKey: rk} // step 3: the UI shows it and gates
}

// ConfirmIdentitySetup performs steps 5–7 of proposal §12, and is only reachable
// once the user has acknowledged their recovery key (step 4).
//
// The acknowledgement gates persistence rather than merely dismissing a screen:
// this is the first call in the whole flow that writes anything anywhere.
//
// On failure the pending identity is KEPT and an error is returned, so the UI
// stays on the screen with the key still visible and can retry. Reporting
// success and failing afterwards would reopen the crash window in miniature.
func (a *App) ConfirmIdentitySetup() string {
	a.identityMu.Lock()
	p := a.pending
	a.identityMu.Unlock()
	if p == nil {
		return "There's no recovery key waiting to be saved. Start again."
	}

	if !p.stored {
		// Step 5: derive, encrypt, upload.
		backup, err := e2ee.SealIdentityBackup(p.kp, p.recoveryKey)
		if err != nil {
			return err.Error()
		}
		stored, ok := a.client.PutIdentityBackup(
			wire.BENCOKDFArgon2id, backup.Params.Encode(), backup.Salt, backup.Blob)
		if !ok {
			return "BENCchat couldn't reach the key directory to save your identity. Your " +
				"recovery key is still on screen — try again."
		}
		if !stored {
			return "The server refused to store your identity. Your recovery key is still on " +
				"screen — try again."
		}
		a.identityMu.Lock()
		p.stored = true
		a.identityMu.Unlock()
	}

	// Step 6: sign and publish the first manifest. Past this point the backup
	// exists, but the user acknowledged the key BEFORE it was uploaded, so even
	// a crash here recovers: the next launch prompts for a key they hold.
	if err := a.publishManifest(p.kp, []e2ee.Device{a.thisDevice()}); err != nil {
		return "Your identity was saved, but publishing this device failed: " + err.Error() +
			" Your recovery key is still on screen — try again."
	}

	// Step 7, and only now. The key has done its work and goes away.
	a.identityMu.Lock()
	a.pending = nil
	a.identityMu.Unlock()
	p.kp.Zero()
	p.recoveryKey = ""

	a.setIdentityFlow("ready")
	a.store.Notify(state.NoticeInfo,
		"Encryption is set up for this account. Keep your recovery key somewhere safe — "+
			"you'll need it to link another device, and it can't be shown again.")
	return ""
}

// CancelIdentitySetup discards a generated-but-unsaved identity.
//
// Safe precisely because nothing was written: the account is untouched and the
// next attempt starts over with a new key.
func (a *App) CancelIdentitySetup() {
	a.identityMu.Lock()
	p := a.pending
	a.pending = nil
	a.identityMu.Unlock()
	if p != nil {
		p.kp.Zero()
		p.recoveryKey = ""
	}
}

// SaveRecoveryKeyToFile writes the pending recovery key to a file the user
// picks, as the other way to satisfy §12's gate.
//
// The file is plain text on purpose. Encrypting it would either replace a
// generated ~110-bit secret with a human-chosen password — moving the weakest
// link rather than removing it — or make the file openable only by BENCchat,
// which may be the very thing that is gone when it is needed. A plaintext key
// can be printed, typed in from paper, or pasted into a password manager.
//
// It also doubles as the escape hatch where there is no clipboard at all: a gate
// with no way to satisfy it would leave the account permanently unusable, which
// is worse than anything it prevents.
func (a *App) SaveRecoveryKeyToFile() string {
	a.identityMu.Lock()
	p := a.pending
	a.identityMu.Unlock()
	if p == nil {
		return "There's no recovery key to save."
	}
	if a.ctx == nil {
		return "No window to ask where to save it."
	}

	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save your BENCchat recovery key",
		DefaultFilename: "bencchat-recovery-key.txt",
	})
	if err != nil {
		return err.Error()
	}
	if path == "" {
		return "" // the user cancelled; not an error, and the gate stays shut
	}

	body := strings.Join([]string{
		"BENCchat recovery key for " + a.store.Self().ScreenName,
		"",
		p.recoveryKey,
		"",
		"This is the only copy. It cannot be shown again, and without it this",
		"account cannot link a new device or remove an old one.",
		"",
		"Put it in a password manager, print it, or keep it where you keep a",
		"passport. Do not leave it in Downloads.",
		"",
	}, "\n")
	// 0600: it is a plaintext account secret, and the mode is the only
	// protection it has.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return err.Error()
	}
	return ""
}

// --- Linking this device (proposal §10, row two) ---------------------------

// LinkDevice signs this machine into an account that already has an identity.
//
// It costs the recovery key, every time, and that is the design rather than an
// oversight: under transient custody (§5) no device retains the identity key, so
// a stolen laptop yields that laptop's key and nothing more. Device linking is
// rare and is exactly the moment when friction is appropriate, because it is the
// one moment the security decision is real.
func (a *App) LinkDevice(recoveryKey string) string {
	if !a.e2eeHasKey {
		return "Encryption isn't set up on this device yet."
	}
	if !a.client.SupportsKeyDir() {
		return errNoKeyDir.Error()
	}
	rk, err := e2ee.ParseRecoveryKey(recoveryKey)
	if err != nil {
		return err.Error()
	}

	backup, ok := a.client.GetIdentityBackup()
	if !ok {
		return "BENCchat couldn't reach the key directory. Try again."
	}
	if !backup.Present {
		a.setIdentityFlow("setup")
		return "This account has no identity yet, so there is nothing to link to. Set one up " +
			"instead."
	}
	if backup.KDF != wire.BENCOKDFArgon2id {
		return "This account's identity backup was written by a newer BENCchat than this one."
	}
	params, err := e2ee.DecodeBackupParams(backup.Params)
	if err != nil {
		return "This account's identity backup is damaged: " + err.Error()
	}

	kp, err := e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
		Params: params,
		Salt:   backup.Salt,
		Blob:   backup.Blob,
	}, rk)
	// Zeroed on the line after acquisition, so no return path — panic included —
	// leaves the identity key sitting in memory.
	defer kp.Zero()
	if err != nil {
		if errors.Is(err, e2ee.ErrBackupOpen) {
			// Deliberately not distinguished from a damaged blob, because
			// secretbox authenticates and genuinely cannot tell us which it was.
			return "That recovery key didn't open this account's identity. Check it and try " +
				"again — if you no longer have it, no device can be linked or removed until " +
				"an administrator clears the account's identity and you start over."
		}
		return err.Error()
	}

	// Learn the current device list before adding ourselves to it, or we would
	// publish a manifest that drops every other machine.
	if _, ok := a.client.QueryManifest(a.store.Self().ScreenName); !ok {
		return "BENCchat couldn't read this account's current device list, and publishing " +
			"without it would remove your other devices. Try again."
	}
	if err := a.publishManifest(kp, a.currentDevices()); err != nil {
		return err.Error()
	}

	a.setSelfIdentityPinIfUnset(kp)
	a.setIdentityFlow("ready")
	a.store.Notify(state.NoticeInfo, "This device is now linked to your account.")
	return ""
}

// setSelfIdentityPinIfUnset records the account identity after a successful
// link, for a device that had nothing pinned.
//
// Only the PUBLIC half is stored. That is what lets this device notice later
// that the account's identity was replaced without it (§6), and it is the one
// piece of the identity that is safe to keep.
func (a *App) setSelfIdentityPinIfUnset(kp e2ee.IdentityKey) {
	pin := a.selfIdentityPin()
	encoded := e2ee.EncodeIdentityPublic(kp.Public)
	if pin.Key == encoded {
		return
	}
	a.setSelfIdentityPin(trust.Identity{Key: encoded, Counter: pin.Counter})
}

// --- Devices ---------------------------------------------------------------

// DeviceInfo describes one device on this account, for the settings list.
type DeviceInfo struct {
	Key         string `json:"key"`         // base64 box key, the removal handle
	Fingerprint string `json:"fingerprint"` // short comparable code
	ThisDevice  bool   `json:"thisDevice"`
}

// ListDevices returns every device named in the account's current manifest.
func (a *App) ListDevices() []DeviceInfo {
	a.trustMu.Lock()
	devices := a.e2eeDevices
	a.trustMu.Unlock()

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

// DeviceCount reports how many devices the account's manifest names.
func (a *App) DeviceCount() int {
	a.trustMu.Lock()
	defer a.trustMu.Unlock()
	return len(a.e2eeDevices)
}

// RemoveDevice takes a machine off the account.
//
// Removal is no longer a server-side tombstone. It is a new manifest at a higher
// counter that simply does not list the device, which is why it costs the
// recovery key: the manifest has to be signed. The upside is that removal is now
// enforced by mathematics rather than by the server's goodwill — a rolled-back
// or hostile server cannot resurrect the device, because every client remembers
// the counter and refuses anything older.
func (a *App) RemoveDevice(keyB64, recoveryKey string) string {
	target, err := e2ee.DecodeKey(keyB64)
	if err != nil {
		return "That doesn't look like a device key."
	}
	if target == a.e2eePub {
		return "That's this device — removing it would stop you reading your own messages."
	}
	if !a.client.SupportsKeyDir() {
		return errNoKeyDir.Error()
	}
	rk, err := e2ee.ParseRecoveryKey(recoveryKey)
	if err != nil {
		return err.Error()
	}

	backup, ok := a.client.GetIdentityBackup()
	if !ok {
		return "BENCchat couldn't reach the key directory. Try again."
	}
	if !backup.Present {
		return "This account has no identity, so its device list can't be signed."
	}
	params, err := e2ee.DecodeBackupParams(backup.Params)
	if err != nil {
		return "This account's identity backup is damaged: " + err.Error()
	}
	kp, err := e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
		Params: params, Salt: backup.Salt, Blob: backup.Blob,
	}, rk)
	defer kp.Zero()
	if err != nil {
		if errors.Is(err, e2ee.ErrBackupOpen) {
			return "That recovery key didn't open this account's identity. Check it and try again."
		}
		return err.Error()
	}

	// Work from the CURRENT manifest, not from whatever this session last saw,
	// so a device another machine added in the meantime is not silently dropped
	// by a removal aimed at something else.
	if _, ok := a.client.QueryManifest(a.store.Self().ScreenName); !ok {
		return "BENCchat couldn't read this account's current device list. Try again."
	}
	kept := make([]e2ee.Device, 0, e2ee.MaxDevices)
	found := false
	for _, d := range a.currentDevices() {
		if d.Box == target {
			found = true
			continue
		}
		kept = append(kept, d)
	}
	if !found {
		return "That device isn't on this account any more."
	}
	if err := a.publishManifest(kp, kept); err != nil {
		return err.Error()
	}
	a.store.Notify(state.NoticeInfo, fmt.Sprintf(
		"Device %s removed. It can no longer read messages sent to this account.",
		e2ee.Fingerprint(target)))
	return ""
}
