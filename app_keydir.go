package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
)

// App-layer use of the BENCO device key directory (foodgroup 0xBE00).
//
// The directory replaces publishing device keys inside the Locate profile. Every
// path here degrades: when the server does not advertise the foodgroup, BENCchat
// falls back to the profile marker exactly as before, so it still works against
// a stock open-oscar-server.

// ownPublishedKeys reads what this account currently advertises.
//
// has distinguishes "the account publishes nothing" from ok=false, "we could not
// find out". The caller must never read a failure as an empty set: doing so
// would make this device believe it is the account's first, skipping the
// approval a genuinely new machine needs.
func (a *App) ownPublishedKeys() (keys [][32]byte, has bool, ok bool) {
	self := a.store.Self().ScreenName
	if self == "" {
		return nil, false, false
	}

	// The directory answers from storage, so it lists every device including
	// machines that are currently offline. The profile only ever showed devices
	// online at that moment, which is why the local record had to be merged in.
	if a.client.SupportsKeyDir() {
		devices, queried := a.client.QueryDevices(self)
		if queried {
			return e2ee.BoxKeysOf(devices), len(devices) > 0, true
		}
		slog.Default().Warn("key directory query for our own devices failed; falling back to the profile")
	}

	return a.client.FetchOwnPublishedKeys(5 * time.Second)
}

// publishDevices publishes this account's device set.
//
// It writes to the directory when the server has one AND still writes the
// profile marker. The marker is transitional: a peer running an older BENCchat
// reads only profiles, and dropping it would make this account unreachable to
// them. It can go once every client speaks the directory.
func (a *App) publishDevices(boxKeys [][32]byte) {
	// The profile is written regardless — it is also where the away message and
	// user-visible profile text live, so this is not purely about keys.
	a.publishProfile()

	if !a.client.SupportsKeyDir() {
		return
	}

	// Only this device's signing key is ours to publish. We learned other
	// devices' encryption keys but never their signing keys, so they appear
	// without one until they republish for themselves.
	devices := make([]e2ee.Device, 0, len(boxKeys))
	for _, k := range boxKeys {
		d := e2ee.Device{Box: k}
		if k == a.e2eePub && a.hasSignKey {
			d.Sign = a.signPub
		}
		devices = append(devices, d)
	}

	refused, ok := a.client.PublishDevices(devices)
	if !ok {
		slog.Default().Warn("could not publish device keys to the directory; the profile marker still carries them")
		return
	}

	// A refused key is a device the user removed announcing itself again. The
	// server declined to resurrect it — that refusal is what makes "remove
	// device" durable — so this is a question for the user, not a retry.
	for _, d := range refused {
		a.onRevokedDeviceReturned(d.Box)
	}
}

// publishedDeviceCount reports how many devices the SERVER actually holds.
//
// The local list is what we tried to publish, which is not the same thing once
// the server starts refusing revoked keys. Announcing "this account has 3
// devices" in the same breath as two of them being refused is worse than saying
// nothing, so this asks rather than assumes. Falls back to the local count when
// the directory is unavailable, where the local list IS the best answer.
func (a *App) publishedDeviceCount(localCount int) int {
	if !a.client.SupportsKeyDir() {
		return localCount
	}
	self := a.store.Self().ScreenName
	if self == "" {
		return localCount
	}
	devices, ok := a.client.QueryDevices(self)
	if !ok {
		return localCount
	}
	return len(devices)
}

// onRevokedDeviceReturned handles a removed device reappearing.
//
// This is the case that only exists because revocation is durable. Under the old
// scheme the machine simply republished itself and nobody heard about it.
func (a *App) onRevokedDeviceReturned(box [32]byte) {
	if box == a.e2eePub {
		// THIS machine is the one that was removed. Say so plainly: encryption
		// will not work here until the user re-approves from another device, and
		// without this the failure is invisible.
		//
		// This supersedes the generic "not linked yet" notice. Both describe the
		// same state and firing both — as happened before — gives the user two
		// different explanations at the same instant, one of which ("approve
		// this new device") is the wrong mental model for a device that used to
		// be linked and was removed.
		a.suppressLinkPendingNotice()
		a.store.Notify(state.NoticeWarn,
			"This device was removed from your account, so it can no longer receive encrypted "+
				"messages. Approve it again from another signed-in device to restore it.")
		a.setLinkPending()
		return
	}

	a.store.Notify(state.NoticeWarn, fmt.Sprintf(
		"A device you removed (%s) tried to rejoin your account and was refused. "+
			"If this was you, approve it in Privacy & Security.", e2ee.Fingerprint(box)))
}

// revokeDevices removes devices from the directory so they cannot republish.
//
// Without this, removal is cosmetic: the removed machine keeps its keypair and
// silently re-adds itself on next sign-on, with the same key, so peers who
// already verified it see no change at all.
func (a *App) revokeDevices(keys [][32]byte) {
	if !a.client.SupportsKeyDir() {
		// Worth saying out loud rather than failing quietly. On a server without
		// the directory there is no authority to make removal stick.
		slog.Default().Warn("server has no key directory; device removal is local only and will not persist")
		return
	}
	for _, k := range keys {
		if _, ok := a.client.RevokeDevice(k); !ok {
			slog.Default().Warn("could not revoke a device key", "fingerprint", e2ee.Fingerprint(k))
		}
	}
}
