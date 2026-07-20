// Package secret stores the user's password in the OS secret store — KWallet or
// GNOME Keyring via the Secret Service API on Linux, and the platform
// equivalents elsewhere — so BENCchat can offer opt-in auto-login without ever
// keeping the password in its own config or on disk in the clear. The OS owns
// the encryption key; BENCchat never sees it.
package secret

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// service is the keyring service name BENCchat's entries live under.
const service = "BENCchat"

// Store saves a password for an account, keyed by screen name.
func Store(account, password string) error {
	return keyring.Set(service, account, password)
}

// Retrieve returns the stored password for an account, or "" (no error) when
// nothing is stored — the common "nothing remembered yet" case.
func Retrieve(account string) (string, error) {
	pw, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return pw, err
}

// Clear removes an account's stored password. A missing entry is not an error.
func Clear(account string) error {
	if err := keyring.Delete(service, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// e2eeUser namespaces the end-to-end-encryption private key so it never collides
// with the login password for the same account.
func e2eeUser(account string) string { return "e2ee:" + account }

// StorePrivateKey saves an account's E2EE private key (base64).
func StorePrivateKey(account, keyB64 string) error {
	return keyring.Set(service, e2eeUser(account), keyB64)
}

// RetrievePrivateKey returns the stored E2EE private key, or "" if none.
func RetrievePrivateKey(account string) (string, error) {
	k, err := keyring.Get(service, e2eeUser(account))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return k, err
}

// signUser namespaces the room-message signing seed, separate again from both
// the login password and the encryption key.
func signUser(account string) string { return "sign:" + account }

// StoreSigningSeed saves an account's Ed25519 signing seed (base64).
func StoreSigningSeed(account, seedB64 string) error {
	return keyring.Set(service, signUser(account), seedB64)
}

// RetrieveSigningSeed returns the stored signing seed, or "" if none.
func RetrieveSigningSeed(account string) (string, error) {
	s, err := keyring.Get(service, signUser(account))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return s, err
}

// ClearPrivateKey removes an account's E2EE private key. Missing is not an error.
func ClearPrivateKey(account string) error {
	if err := keyring.Delete(service, e2eeUser(account)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// historyUser namespaces the key that encrypts an account's on-disk scrollback.
// Separate from the E2EE key on purpose: that one is an identity peers verify,
// this one is a local file key with an entirely different lifecycle. Rotating or
// losing one must not disturb the other.
func historyUser(account string) string { return "hist:" + account }

// StoreHistoryKey saves an account's history-file encryption key (base64).
func StoreHistoryKey(account, keyB64 string) error {
	return keyring.Set(service, historyUser(account), keyB64)
}

// RetrieveHistoryKey returns the stored history key, or "" if none is stored.
//
// The caller must distinguish "" from an error: a keyring that could not be
// reached is not the same answer as an account that has no key yet, and only
// one of them means "generate one". Getting that wrong would mint a fresh key
// over readable history and make it permanently unreadable.
func RetrieveHistoryKey(account string) (string, error) {
	k, err := keyring.Get(service, historyUser(account))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return k, err
}

// ClearHistoryKey removes an account's history key. Missing is not an error.
func ClearHistoryKey(account string) error {
	if err := keyring.Delete(service, historyUser(account)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}
