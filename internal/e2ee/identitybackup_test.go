package e2ee

import (
	"bytes"
	"errors"
	"testing"
)

// The real parameters cost the better part of a second and half a gigabyte per
// call, which is the point of them — so every test that does not specifically
// care about the cost uses these instead. The KDF is exercised identically
// either way; only the price changes.
func testBackupParams() BackupParams {
	return BackupParams{Time: 1, Memory: 8 * 1024, Threads: 1}
}

func newTestIdentity(t *testing.T) IdentityKey {
	t.Helper()
	kp, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	t.Cleanup(kp.Zero)
	return kp
}

func TestIdentityBackupRoundTrip(t *testing.T) {
	kp := newTestIdentity(t)
	key, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("recovery key: %v", err)
	}

	backup, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(backup.Salt) != backupSaltLen {
		t.Fatalf("salt is %d bytes, want %d", len(backup.Salt), backupSaltLen)
	}

	got, err := OpenIdentityBackup(backup, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer got.Zero()
	if !got.Public.Equal(kp.Public) {
		t.Fatal("opened backup yielded a different identity")
	}

	// And the recovered key must actually sign as the original.
	manifest := []byte("manifest bytes")
	sig, err := SignManifest(got, manifest)
	if err != nil {
		t.Fatalf("sign with recovered key: %v", err)
	}
	if err := VerifyManifest(kp.Public, manifest, sig); err != nil {
		t.Fatalf("recovered key does not sign as the original: %v", err)
	}
}

func TestIdentityBackupRejectsTheWrongRecoveryKey(t *testing.T) {
	kp := newTestIdentity(t)
	right, _ := GenerateRecoveryKey()
	wrong, _ := GenerateRecoveryKey()
	if right == wrong {
		t.Fatal("two generated recovery keys collided; the generator is broken")
	}

	backup, err := sealIdentityBackup(kp, right, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenIdentityBackup(backup, wrong); !errors.Is(err, ErrBackupOpen) {
		t.Fatalf("opened with the wrong recovery key: %v", err)
	}

	// One word different is the realistic case — a misread word off paper — and
	// must fail just as completely as an entirely different key.
	words := splitRecoveryKey(right)
	other, _ := RecoveryKeyWordAt(0)
	if words[3] == other {
		other, _ = RecoveryKeyWordAt(1)
	}
	words[3] = other
	nearMiss := joinWords(words)
	if _, err := OpenIdentityBackup(backup, nearMiss); !errors.Is(err, ErrBackupOpen) {
		t.Fatalf("opened with a one-word-off recovery key: %v", err)
	}
}

func joinWords(w []string) string {
	out := w[0]
	for _, s := range w[1:] {
		out += "-" + s
	}
	return out
}

// A key typed differently is still the same key. If normalisation were dropped
// from the derivation, this is the test that would catch it — and the bug would
// otherwise look like a correct recovery key being rejected.
func TestIdentityBackupOpensWithDifferentlyTypedKey(t *testing.T) {
	kp := newTestIdentity(t)
	key, _ := GenerateRecoveryKey()

	backup, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	messy := "  " + joinWordsWith(splitRecoveryKey(key), " ") + "\n"
	got, err := OpenIdentityBackup(backup, upper(messy))
	if err != nil {
		t.Fatalf("open with a differently-typed key: %v", err)
	}
	got.Zero()
}

func joinWordsWith(w []string, sep string) string {
	out := w[0]
	for _, s := range w[1:] {
		out += sep + s
	}
	return out
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func TestIdentityBackupDetectsTampering(t *testing.T) {
	kp := newTestIdentity(t)
	key, _ := GenerateRecoveryKey()
	backup, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for i := range backup.Blob {
		tampered := IdentityBackup{Params: backup.Params, Salt: backup.Salt, Blob: bytes.Clone(backup.Blob)}
		tampered.Blob[i] ^= 0x01
		if _, err := OpenIdentityBackup(tampered, key); err == nil {
			t.Fatalf("blob byte %d altered and the backup still opened", i)
		}
	}

	// A tampered salt derives a different key, so it fails as authentication.
	badSalt := IdentityBackup{Params: backup.Params, Salt: bytes.Clone(backup.Salt), Blob: backup.Blob}
	badSalt.Salt[0] ^= 0x01
	if _, err := OpenIdentityBackup(badSalt, key); !errors.Is(err, ErrBackupOpen) {
		t.Fatalf("altered salt: %v", err)
	}

	if _, err := OpenIdentityBackup(IdentityBackup{Params: backup.Params, Salt: backup.Salt, Blob: []byte{1, 2, 3}}, key); err == nil {
		t.Fatal("opened a truncated blob")
	}
}

func TestSealingEachTimeProducesADifferentBlob(t *testing.T) {
	kp := newTestIdentity(t)
	key, _ := GenerateRecoveryKey()

	a, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(a.Salt, b.Salt) {
		t.Fatal("two seals reused a salt")
	}
	if bytes.Equal(a.Blob, b.Blob) {
		t.Fatal("two seals of the same key produced identical blobs")
	}
}

func TestBackupParamsRoundTripAndValidation(t *testing.T) {
	p := DefaultBackupParams()
	got, err := DecodeBackupParams(p.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != p {
		t.Fatalf("params did not round trip: %+v vs %+v", got, p)
	}
	if n := len(p.Encode()); n != backupParamsLen {
		t.Fatalf("encoded params are %d bytes, want %d", n, backupParamsLen)
	}

	if _, err := DecodeBackupParams([]byte{1, 2, 3}); err == nil {
		t.Fatal("accepted params of the wrong length")
	}

	// Hostile values from an untrusted server must be refused rather than
	// handed to argon2, which would panic or try to allocate the machine.
	for name, bad := range map[string]BackupParams{
		"zero time":     {Time: 0, Memory: 64 * 1024, Threads: 1},
		"zero threads":  {Time: 1, Memory: 64 * 1024, Threads: 0},
		"tiny memory":   {Time: 1, Memory: 1, Threads: 4},
		"absurd memory": {Time: 1, Memory: 64 * 1024 * 1024, Threads: 4},
		"absurd time":   {Time: 1 << 20, Memory: 64 * 1024, Threads: 4},
	} {
		if _, err := DecodeBackupParams(bad.Encode()); err == nil {
			t.Errorf("%s: accepted %+v", name, bad)
		}
		if _, err := OpenIdentityBackup(IdentityBackup{Params: bad, Salt: make([]byte, 16), Blob: make([]byte, 200)}, "x"); err == nil {
			t.Errorf("%s: opened with %+v", name, bad)
		}
	}
}

func TestOpenIdentityBackupRejectsAMalformedRecoveryKey(t *testing.T) {
	kp := newTestIdentity(t)
	key, _ := GenerateRecoveryKey()
	backup, err := sealIdentityBackup(kp, key, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A key with the wrong shape must be reported as such, not as a failed
	// decryption: "that's 3 words" is actionable, "wrong recovery key" is not.
	var lerr *RecoveryLengthError
	if _, err := OpenIdentityBackup(backup, "one two three"); !errors.As(err, &lerr) {
		t.Fatalf("got %v, want a *RecoveryLengthError", err)
	}
}

// Re-keying keeps the identity — and therefore every signature and every
// safety number — while replacing only the wrapping. Proposal §10 turns on
// this distinction, so it is asserted rather than assumed.
func TestRekeyKeepsTheIdentity(t *testing.T) {
	kp := newTestIdentity(t)
	oldKey, _ := GenerateRecoveryKey()
	newKey, _ := GenerateRecoveryKey()

	backup, err := sealIdentityBackup(kp, oldKey, testBackupParams())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := OpenIdentityBackup(backup, oldKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Zero()

	rekeyed, err := sealIdentityBackup(opened, newKey, testBackupParams())
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	again, err := OpenIdentityBackup(rekeyed, newKey)
	if err != nil {
		t.Fatalf("open after rekey: %v", err)
	}
	defer again.Zero()

	if !again.Public.Equal(kp.Public) {
		t.Fatal("re-keying changed the identity; it must not")
	}
	if _, err := OpenIdentityBackup(rekeyed, oldKey); !errors.Is(err, ErrBackupOpen) {
		t.Fatal("the old recovery key still opens the re-keyed backup")
	}
}

func TestSealIdentityBackupRefusesAZeroedKey(t *testing.T) {
	kp, _ := GenerateIdentityKey()
	kp.Zero()
	key, _ := GenerateRecoveryKey()
	if _, err := SealIdentityBackup(kp, key); !errors.Is(err, ErrIdentityKeyZeroed) {
		t.Fatalf("got %v, want ErrIdentityKeyZeroed", err)
	}
}

// The one test that pays the real cost, so the shipped parameters are known to
// work end to end and their price is visible in the test output. Skipped under
// -short because it allocates 512 MiB.
func TestIdentityBackupWithProductionParams(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2id at the production cost; skipped under -short")
	}
	kp := newTestIdentity(t)
	key, _ := GenerateRecoveryKey()

	backup, err := SealIdentityBackup(kp, key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if backup.Params != DefaultBackupParams() {
		t.Fatalf("sealed under %+v, want the defaults %+v", backup.Params, DefaultBackupParams())
	}
	got, err := OpenIdentityBackup(backup, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer got.Zero()
	if !got.Public.Equal(kp.Public) {
		t.Fatal("production-parameter round trip changed the identity")
	}
}
