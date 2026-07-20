package main

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/client"
	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/trust"
	"github.com/benco-holdings/benchat/internal/wire"
)

// These tests are slow on purpose: every one of them pays a real argon2id pass
// at the production parameters (512 MiB, ~0.6s each). Turning those down for the
// tests would mean testing a KDF nobody ships — and since the whole re-key flow
// is about which blob is openable with which key at which moment, the actual
// seal and open are the thing under test.

// fakeKeyDir is a key directory that holds one identity backup and counts what
// it is asked to do.
//
// The counting is the point. Proposal §10's rule that a re-key must NOT publish
// a manifest is invisible to a test that can only look at the final state, since
// a spurious publish leaves the backup looking exactly right.
type fakeKeyDir struct {
	backup client.IdentityBackup
	// publishes counts PublishManifest calls, which must stay at zero across a
	// re-key.
	publishes int
	// refusePut makes the server reject a store, standing in for the failure
	// that must leave the OLD backup in place.
	refusePut bool
	// unreachable makes every call fail the round trip.
	unreachable bool
}

func (f *fakeKeyDir) SupportsKeyDir() bool { return true }

func (f *fakeKeyDir) QueryManifest(string) (client.SignedManifest, bool) {
	return client.SignedManifest{}, !f.unreachable
}

func (f *fakeKeyDir) PublishManifest([]byte, uint8, []byte) (bool, uint64, bool) {
	f.publishes++
	return true, 1, true
}

func (f *fakeKeyDir) PutIdentityBackup(kdf uint8, params, salt, blob []byte) (bool, bool) {
	if f.unreachable {
		return false, false
	}
	if f.refusePut {
		return false, true
	}
	f.backup = client.IdentityBackup{Present: true, KDF: kdf, Params: params, Salt: salt, Blob: blob}
	return true, true
}

func (f *fakeKeyDir) GetIdentityBackup() (client.IdentityBackup, bool) {
	if f.unreachable {
		return client.IdentityBackup{}, false
	}
	return f.backup, true
}

// opensWith reports whether the backup the fake currently holds is openable with
// a given recovery key. This is the only question these tests really ask.
func (f *fakeKeyDir) opensWith(t *testing.T, recoveryKey string) bool {
	t.Helper()
	if !f.backup.Present {
		t.Fatal("the fake directory holds no backup at all")
	}
	params, err := e2ee.DecodeBackupParams(f.backup.Params)
	if err != nil {
		t.Fatalf("DecodeBackupParams: %v", err)
	}
	kp, err := e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
		Params: params, Salt: f.backup.Salt, Blob: f.backup.Blob,
	}, recoveryKey)
	if err != nil {
		return false
	}
	kp.Zero()
	return true
}

// appWithBackup returns an App holding an account whose identity is already
// bootstrapped, plus the recovery key that opens it and the identity itself.
func appWithBackup(t *testing.T) (*App, *fakeKeyDir, string, e2ee.IdentityKey) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	kp, err := e2ee.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	rk, err := e2ee.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}
	backup, err := e2ee.SealIdentityBackup(kp, rk)
	if err != nil {
		t.Fatalf("SealIdentityBackup: %v", err)
	}

	dir := &fakeKeyDir{backup: client.IdentityBackup{
		Present: true,
		KDF:     wire.BENCOKDFArgon2id,
		Params:  backup.Params.Encode(),
		Salt:    backup.Salt,
		Blob:    backup.Blob,
	}}
	a := &App{store: state.NewStore(), keyDir: dir}
	a.histAccount = "us" // what currentAccount() names the trust file after
	a.e2eeHasKey = true
	return a, dir, rk, kp
}

// The ordering rule, and the reason §10 needs one at all: re-keying REPLACES the
// stored backup, so an upload that happens before the user has saved the new key
// makes the identity unrecoverable. Begin must therefore write nothing, and the
// OLD key must keep working right up until Confirm.
func TestRotationLeavesTheOldBackupOpenableUntilConfirm(t *testing.T) {
	a, dir, oldKey, kp := appWithBackup(t)
	defer kp.Zero()

	info := a.BeginRecoveryKeyRotation(oldKey)
	if info.Error != "" {
		t.Fatalf("BeginRecoveryKeyRotation: %s", info.Error)
	}
	if info.RecoveryKey == "" || info.RecoveryKey == oldKey {
		t.Fatal("Begin did not produce a new recovery key")
	}
	newKey := info.RecoveryKey

	// This is the crash window. Everything generated so far lives in memory, and
	// the server still holds the blob the OLD key opens.
	if !dir.opensWith(t, oldKey) {
		t.Error("the old recovery key stopped working before Confirm; the crash window is open")
	}
	if dir.opensWith(t, newKey) {
		t.Error("the new key already opens the backup; Begin uploaded something it must not have")
	}

	// Abandoning here must cost nothing at all.
	a.CancelRecoveryKeyRotation()
	if !dir.opensWith(t, oldKey) {
		t.Error("cancelling a rotation broke the old recovery key")
	}
}

// After Confirm the swap is complete and total: the new key opens the backup and
// the old one does not. A rotation that left the old key working would be no
// rotation at all — the reason to run it is that the old key may be compromised.
func TestConfirmedRotationSwapsTheKeyAndPublishesNothing(t *testing.T) {
	a, dir, oldKey, kp := appWithBackup(t)
	defer kp.Zero()

	info := a.BeginRecoveryKeyRotation(oldKey)
	if info.Error != "" {
		t.Fatalf("BeginRecoveryKeyRotation: %s", info.Error)
	}
	newKey := info.RecoveryKey

	if msg := a.ConfirmRecoveryKeyRotation(); msg != "" {
		t.Fatalf("ConfirmRecoveryKeyRotation: %s", msg)
	}

	if !dir.opensWith(t, newKey) {
		t.Error("the new recovery key does not open the stored backup")
	}
	if dir.opensWith(t, oldKey) {
		t.Error("the old recovery key still opens the backup; the rotation did not replace it")
	}

	// §10's whole point: the IDENTITY is unchanged, so no manifest is re-issued,
	// no counter is spent, and nobody's safety number moves. A publish here would
	// be a silent regression — the backup would look correct either way.
	if dir.publishes != 0 {
		t.Errorf("a re-key published %d manifest(s); it must publish none", dir.publishes)
	}

	// And the identity really is the same one, which is what makes that safe.
	params, err := e2ee.DecodeBackupParams(dir.backup.Params)
	if err != nil {
		t.Fatalf("DecodeBackupParams: %v", err)
	}
	reopened, err := e2ee.OpenIdentityBackup(e2ee.IdentityBackup{
		Params: params, Salt: dir.backup.Salt, Blob: dir.backup.Blob,
	}, newKey)
	if err != nil {
		t.Fatalf("OpenIdentityBackup: %v", err)
	}
	defer reopened.Zero()
	if e2ee.EncodeIdentityPublic(reopened.Public) != e2ee.EncodeIdentityPublic(kp.Public) {
		t.Error("the re-keyed backup holds a DIFFERENT identity; a re-key is not a new identity")
	}

	// The new key has never been proven, so its verification date must not have
	// been inherited from the key it replaced.
	rec, err := trust.LoadRecovery("us")
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if rec.Created == 0 {
		t.Error("a rotation did not record when the new key was created")
	}
	if rec.LastVerified != 0 {
		t.Error("the old key's verification date carried onto the new key")
	}
}

// A failed upload must leave the account exactly as it was, with the key the
// user still holds still working — and must keep the new key pending so the UI
// can stay put and retry, rather than dropping it and stranding them.
func TestRefusedRotationLeavesTheOldKeyWorking(t *testing.T) {
	a, dir, oldKey, kp := appWithBackup(t)
	defer kp.Zero()

	info := a.BeginRecoveryKeyRotation(oldKey)
	if info.Error != "" {
		t.Fatalf("BeginRecoveryKeyRotation: %s", info.Error)
	}
	dir.refusePut = true
	if msg := a.ConfirmRecoveryKeyRotation(); msg == "" {
		t.Fatal("a refused store reported success")
	}
	if !dir.opensWith(t, oldKey) {
		t.Error("a refused rotation broke the old recovery key")
	}
	a.identityMu.Lock()
	pendingStill := a.rotation != nil
	a.identityMu.Unlock()
	if !pendingStill {
		t.Error("the new key was discarded on a failure; the user has no way to retry")
	}
}

// Beginning a rotation without the current key must be impossible: possession of
// the key being replaced is the entire authorisation for replacing it.
func TestRotationRequiresTheCurrentKey(t *testing.T) {
	a, dir, _, kp := appWithBackup(t)
	defer kp.Zero()

	other, err := e2ee.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}
	if info := a.BeginRecoveryKeyRotation(other); info.Error == "" {
		t.Fatal("a rotation began without the current recovery key")
	}
	a.identityMu.Lock()
	started := a.rotation != nil
	a.identityMu.Unlock()
	if started {
		t.Error("a rotation was left pending after the current key failed to open the backup")
	}
	if dir.publishes != 0 {
		t.Error("a failed rotation published a manifest")
	}
}

// §13: the date is evidence, not a self-report. It may only move when the key
// has actually been watched decrypting the backup.
func TestVerifyRecordsADateOnlyOnSuccess(t *testing.T) {
	a, _, rk, kp := appWithBackup(t)
	defer kp.Zero()

	wrong, err := e2ee.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}
	if msg := a.VerifyRecoveryKey(wrong); msg == "" {
		t.Fatal("a wrong recovery key verified")
	}
	rec, err := trust.LoadRecovery("us")
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if rec.LastVerified != 0 {
		t.Fatal("a failed verification recorded a date; the line would then be reporting a lie")
	}

	if msg := a.VerifyRecoveryKey(rk); msg != "" {
		t.Fatalf("VerifyRecoveryKey: %s", msg)
	}
	rec, err = trust.LoadRecovery("us")
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if rec.LastVerified == 0 {
		t.Error("a successful verification recorded nothing")
	}
}

// An unreachable directory is not evidence of anything, and must never be
// reported as a key that failed — nor as one that worked.
func TestVerifyDoesNotRecordWhenTheDirectoryIsUnreachable(t *testing.T) {
	a, dir, rk, kp := appWithBackup(t)
	defer kp.Zero()
	dir.unreachable = true

	if msg := a.VerifyRecoveryKey(rk); msg == "" {
		t.Fatal("an unreachable directory reported a successful verification")
	}
	rec, err := trust.LoadRecovery("us")
	if err != nil {
		t.Fatalf("LoadRecovery: %v", err)
	}
	if rec.LastVerified != 0 {
		t.Error("an unreachable directory recorded a verification date")
	}
	if st := a.GetRecoveryKeyStatus(); st.Available || st.Error == "" {
		t.Error("an unreachable directory was reported as a known-good recovery key state")
	}
}
