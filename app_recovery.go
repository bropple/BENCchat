package main

import (
	"errors"
	"log/slog"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/benco-holdings/benchat/internal/wire"
)

// The recovery key after first run: replacing it (proposal §10) and reporting on
// it (§13).
//
// # Re-keying is not a new identity
//
// This is the distinction §10 exists to draw, and the UI repeats it because the
// person reaching for this feature — someone who thinks their written-down key
// was read over their shoulder — is exactly the person who would otherwise
// destroy and re-bootstrap the account:
//
//	Re-key the backup   same identity, new recovery key   devices stay signed,
//	                                                      nobody's safety number moves
//	New identity        everything re-issued              every device is orphaned,
//	                                                      every contact sees a change
//
// Only the passphrase-derived wrapping around the identity key changes. Nothing
// here signs or publishes a manifest, and the absence of that call is a
// load-bearing property rather than an omission — see ConfirmRecoveryKeyRotation.
//
// # The one safe moment
//
// Under transient custody (§5) the plaintext identity key exists only while the
// user has just supplied the CURRENT recovery key, so that is the only moment a
// re-key is possible — and it is also the right bar, because it requires proving
// possession of the key being replaced. BeginRecoveryKeyRotation therefore takes
// the current key and opens the backup itself rather than borrowing a key some
// earlier call left lying around: an identity key held across UI round trips is
// exactly the durable custody §5 refuses. The cost is one extra argon2id pass
// when a re-key follows a link or a verify, which is a second of a deliberate,
// rare action.

// pendingRotation is a re-key that has been generated but NOT uploaded.
//
// It is pendingIdentity's twin, and it closes a sharper version of the same
// window. First run's crash window costs an account that never existed; this one
// costs an account that does — re-keying REPLACES the stored backup, so the
// moment the new blob is uploaded the old recovery key stops opening it. Upload
// before the user has saved the new key and the identity is unrecoverable.
//
// So kp and newRecoveryKey live here, in memory only, until the §12 gate opens.
// A crash at any point before ConfirmRecoveryKeyRotation leaves the old backup
// on the server untouched and the old key still working.
type pendingRotation struct {
	// kp is the account identity, opened with the CURRENT recovery key. It is
	// unchanged by the rotation — that is the whole point — and is held only so
	// the re-seal does not need the current key a second time.
	kp             e2ee.IdentityKey
	newRecoveryKey string
}

// BeginRecoveryKeyRotation performs steps 1–3 of the §10 re-key: prove
// possession of the current key by opening the backup with it, mint a new key,
// and hand it back for display.
//
// Nothing is written by this call. The stored backup is still the one the
// CURRENT recovery key opens, and stays that way until ConfirmRecoveryKeyRotation.
func (a *App) BeginRecoveryKeyRotation(current string) RecoveryKeyInfo {
	if !a.e2eeHasKey {
		return RecoveryKeyInfo{Error: "Encryption isn't set up on this device yet."}
	}
	if !a.keyDir.SupportsKeyDir() {
		return RecoveryKeyInfo{Error: errNoKeyDir.Error()}
	}

	a.identityMu.Lock()
	if a.pending != nil {
		// A first run and a re-key cannot both be real: one means the account has
		// no identity, the other that it has one. Refusing rather than picking is
		// the safe reading of a state that should not exist.
		a.identityMu.Unlock()
		return RecoveryKeyInfo{Error: "This account is still being set up. Finish that first."}
	}
	if r := a.rotation; r != nil {
		// Already generated and waiting on the gate. Show the SAME key again
		// rather than minting a second one — a user who saved the first would
		// otherwise be holding a key that never gets uploaded.
		a.identityMu.Unlock()
		return RecoveryKeyInfo{RecoveryKey: r.newRecoveryKey}
	}
	a.identityMu.Unlock()

	rk, err := e2ee.ParseRecoveryKey(current)
	if err != nil {
		return RecoveryKeyInfo{Error: recoveryKeyMessage(err)}
	}

	kp, err := a.openIdentityBackup(rk)
	if err != nil {
		return RecoveryKeyInfo{Error: err.Error()}
	}

	// Possession of the current key is now proven, which is the same evidence
	// Verify now produces. Record it even though the key is about to be replaced:
	// if the rotation is abandoned, the old key is still the account's key and
	// this is a true thing to have learned about it.
	a.recordRecoveryKeyVerified()

	newKey, err := e2ee.GenerateRecoveryKey()
	if err != nil {
		kp.Zero()
		return RecoveryKeyInfo{Error: err.Error()}
	}

	a.identityMu.Lock()
	a.rotation = &pendingRotation{kp: kp, newRecoveryKey: newKey}
	a.identityMu.Unlock()
	return RecoveryKeyInfo{RecoveryKey: newKey}
}

// ConfirmRecoveryKeyRotation re-seals the identity under the new key and stores
// it, and is only reachable once the user has satisfied the §12 gate.
//
// This is the first call in the re-key that writes anything, and the instant it
// succeeds the old recovery key is dead. That ordering is the whole design.
//
// It deliberately does NOT publish a manifest. The identity key is byte for byte
// the one every existing manifest was signed with, so every device is still
// signed, every contact's safety number is unchanged, and the counter does not
// move. Publishing "just to be safe" would be the opposite of safe: it would
// spend a counter and re-issue a device list for no reason, and on a client that
// got the device set wrong it would silently drop somebody's machine.
//
// On failure the rotation is KEPT and an error returned, so the UI stays put
// with the new key still on screen — and, crucially, the OLD key still opens the
// backup that is still there.
func (a *App) ConfirmRecoveryKeyRotation() string {
	a.identityMu.Lock()
	r := a.rotation
	a.identityMu.Unlock()
	if r == nil {
		return "There's no new recovery key waiting to be saved. Start again."
	}

	// Re-sealed at the CURRENT default argon2id parameters, which is the other
	// thing §10 buys: a backup written under weaker costs is upgraded here
	// without anything else in the account moving.
	backup, err := e2ee.RekeyIdentityBackup(r.kp, r.newRecoveryKey)
	if err != nil {
		return err.Error()
	}
	stored, ok := a.keyDir.PutIdentityBackup(
		wire.BENCOKDFArgon2id, backup.Params.Encode(), backup.Salt, backup.Blob)
	if !ok {
		return "BENCchat couldn't reach the key directory to store your new recovery key. " +
			"Your old one still works — the new one is still on screen, so try again."
	}
	if !stored {
		return "The server refused to store your new recovery key. Your old one still works — " +
			"the new one is still on screen, so try again."
	}

	// The new key is now the account's key and has never been verified, so the
	// old key's verification date does not carry over: it was evidence about a
	// different secret.
	a.recordRecoveryKeyCreated()

	a.identityMu.Lock()
	a.rotation = nil
	a.identityMu.Unlock()
	r.kp.Zero()
	r.newRecoveryKey = ""

	a.store.Notify(state.NoticeInfo,
		"Your recovery key has been replaced. The old one no longer works. Nothing else about "+
			"your account changed — your devices are still linked and your contacts see no "+
			"difference.")
	return ""
}

// CancelRecoveryKeyRotation discards a generated-but-unstored new recovery key.
//
// Safe precisely because nothing was written: the stored backup is still the one
// the current key opens, so abandoning this costs nothing but the argon2id pass.
func (a *App) CancelRecoveryKeyRotation() {
	a.identityMu.Lock()
	r := a.rotation
	a.rotation = nil
	a.identityMu.Unlock()
	if r != nil {
		r.kp.Zero()
		r.newRecoveryKey = ""
	}
}

// --- The passive Settings line (proposal §13) -------------------------------

// RecoveryKeyStatus is what Settings → Privacy & Security reports about the
// recovery key.
//
// Nothing fires off the back of this. There is no timer, no badge, no notice and
// no prompt anywhere in this file that the user did not ask for: §13 is explicit
// that an alert appearing when nothing is wrong is one people learn to dismiss,
// and this project has already paid for that lesson once with safety-number
// churn. The line is only seen by someone who goes looking, which is exactly the
// person it helps.
type RecoveryKeyStatus struct {
	// Available is whether there is a key to report on at all: signed on, a
	// server with a key directory, and an identity backup that exists.
	Available bool `json:"available"`
	// Created is when the key in force was generated, Unix seconds UTC, or 0 for
	// "not known on this computer" — the ordinary state of a device that was
	// linked rather than bootstrapped, and of any account whose key predates
	// this being recorded. The UI must say unknown rather than guess.
	Created uint64 `json:"created"`
	// LastVerified is the last time THIS device watched the key open the backup,
	// or 0 for never. Only a real decryption sets it.
	LastVerified uint64 `json:"lastVerified"`
	// Error explains an Available=false that is a failure rather than an answer.
	Error string `json:"error"`
}

// GetRecoveryKeyStatus reports on the account's recovery key without touching it.
func (a *App) GetRecoveryKeyStatus() RecoveryKeyStatus {
	st := RecoveryKeyStatus{}
	if !a.e2eeHasKey || !a.keyDir.SupportsKeyDir() {
		return st
	}
	// The dates are local, but whether there is a key at all is not, so ask.
	// Reporting "created 19 July 2026" for an account whose identity an admin
	// cleared would be worse than reporting nothing.
	backup, ok := a.keyDir.GetIdentityBackup()
	if !ok {
		st.Error = "BENCchat couldn't reach the key directory."
		return st
	}
	if !backup.Present {
		return st
	}
	rec := a.recoveryDates()
	st.Available = true
	st.Created = rec.Created
	st.LastVerified = rec.LastVerified
	return st
}

// VerifyRecoveryKey checks that a recovery key still opens this account's
// identity backup, and records the date if it does.
//
// This is the only check that proves anything (§13): the key is stretched and
// the blob is actually decrypted. Success and failure are both evidence rather
// than a self-report, which is why there is no "yes I still have it" button
// anywhere — that would record a date meaning nothing.
//
// It involves no exposure that linking a device does not already involve, and
// the identity key it recovers is zeroed on the way out. A re-key offered off
// the back of this asks for the key again (see the file comment) rather than
// holding the identity across a round trip to the UI.
func (a *App) VerifyRecoveryKey(recoveryKey string) string {
	if !a.e2eeHasKey {
		return "Encryption isn't set up on this device yet."
	}
	if !a.keyDir.SupportsKeyDir() {
		return errNoKeyDir.Error()
	}
	rk, err := e2ee.ParseRecoveryKey(recoveryKey)
	if err != nil {
		return recoveryKeyMessage(err)
	}
	kp, err := a.openIdentityBackup(rk)
	if err != nil {
		// Nothing is recorded on a failure. A date that moved on a wrong key
		// would turn the one honest signal on this screen into a lie.
		return err.Error()
	}
	kp.Zero()
	a.recordRecoveryKeyVerified()
	return ""
}

// --- Shared plumbing --------------------------------------------------------

// openIdentityBackup fetches this account's backup and opens it with a
// recovery key, returning a message fit to show a person on failure.
//
// Shared by the two flows in this file. LinkDevice and RemoveDevice open the
// backup the same way but say more specific things when it fails — linking is
// where "if you no longer have it, no device can be linked or removed" belongs —
// so they keep their own copy rather than losing that wording to a shared one.
//
// The returned key is transient: the caller owns zeroing it, and every caller
// does so on the next line or via defer.
func (a *App) openIdentityBackup(recoveryKey string) (e2ee.IdentityKey, error) {
	backup, ok := a.keyDir.GetIdentityBackup()
	if !ok {
		return e2ee.IdentityKey{}, errors.New("BENCchat couldn't reach the key directory. Try again.")
	}
	if !backup.Present {
		return e2ee.IdentityKey{}, errors.New("This account has no encryption identity yet, so " +
			"there is nothing for a recovery key to open.")
	}
	if backup.KDF != wire.BENCOKDFArgon2id {
		return e2ee.IdentityKey{}, errors.New("This account's identity backup was written by a " +
			"newer BENCchat than this one.")
	}
	params, err := e2ee.DecodeBackupParams(backup.Params)
	if err != nil {
		return e2ee.IdentityKey{}, errors.New("This account's identity backup is damaged: " + err.Error())
	}
	kp, err := e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
		Params: params, Salt: backup.Salt, Blob: backup.Blob,
	}, recoveryKey)
	if err != nil {
		if errors.Is(err, e2ee.ErrBackupOpen) {
			// Not distinguished from a damaged blob, because secretbox
			// authenticates and genuinely cannot tell us which it was.
			return e2ee.IdentityKey{}, errors.New("That recovery key didn't open this account's " +
				"identity. Check it and try again.")
		}
		return e2ee.IdentityKey{}, err
	}
	return kp, nil
}

// recoveryDates reads this device's record of the account's recovery key.
func (a *App) recoveryDates() trust.Recovery {
	rec, err := trust.LoadRecovery(a.currentAccount())
	if err != nil {
		slog.Default().Warn("could not read the recovery key dates", "err", err)
	}
	return rec
}

// setRecoveryDates writes the record whole. See trust.SaveRecovery for why it is
// not field by field.
func (a *App) setRecoveryDates(rec trust.Recovery) {
	if err := trust.SaveRecovery(a.currentAccount(), rec); err != nil {
		slog.Default().Warn("could not save the recovery key dates", "err", err)
	}
}

// recordRecoveryKeyCreated notes that a recovery key was just generated, and
// that nothing has yet proven it works.
//
// Called from the two places a key comes into existence: first run and a
// rotation. Not from linking a device — the key was made somewhere else, on some
// other day, and stamping today's date on it would be an invention.
func (a *App) recordRecoveryKeyCreated() {
	a.setRecoveryDates(trust.Recovery{Created: uint64(time.Now().UTC().Unix())})
}

// recordRecoveryKeyVerified notes that the key was just watched opening the
// account's identity backup.
//
// Called from every path that successfully decrypts it, not only from Verify
// now: linking a device and removing one are the same proof, obtained the same
// way, and a user who links a laptop has demonstrably still got their key.
func (a *App) recordRecoveryKeyVerified() {
	rec := a.recoveryDates()
	rec.LastVerified = uint64(time.Now().UTC().Unix())
	a.setRecoveryDates(rec)
}
