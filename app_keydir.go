package main

import (
	"fmt"
	"log/slog"

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
	// machines that are currently offline.
	if !a.client.SupportsKeyDir() {
		slog.Default().Error("server has no key directory; cannot read our own published devices")
		return nil, false, false
	}
	devices, queried := a.client.QueryDevices(self)
	if !queried {
		// Report failure rather than "no devices". A query that did not complete
		// is not evidence that nothing is published, and treating it as such
		// would invite the caller to republish over a set it could not read.
		slog.Default().Warn("key directory query for our own devices failed")
		return nil, false, false
	}
	return e2ee.BoxKeysOf(devices), len(devices) > 0, true
}

// publishDevices publishes this account's device set to the key directory.
//
// The profile is no longer part of key publication. It is still written here so
// that an account whose profile carries a marker from an older BENCchat gets it
// overwritten on the next publish rather than leaving a stale key on display.
func (a *App) publishDevices(boxKeys [][32]byte) (accepted int, selfRefused bool) {
	a.publishProfile()

	if !a.client.SupportsKeyDir() {
		// Without a directory there is nowhere left to publish keys. Say so
		// rather than reporting success: the caller's count would otherwise
		// claim devices are reachable when no peer can discover them.
		slog.Default().Error("server has no key directory; device keys cannot be published")
		return 0, false
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

	accepted, refused, ok := a.client.PublishDevices(devices)
	if !ok {
		slog.Default().Warn("could not publish device keys to the directory; the profile marker still carries them")
		return len(boxKeys), false
	}

	// A refused key is a device the user removed announcing itself again. The
	// server declined to resurrect it — that refusal is what makes "remove
	// device" durable — so this is a question for the user, not a retry.
	for _, d := range refused {
		if d.Box == a.e2eePub {
			selfRefused = true
		}
		a.onRevokedDeviceReturned(d.Box)
	}
	return accepted, selfRefused
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
		// Claim before setLinkPending, which would otherwise emit the generic
		// "you are new" wording for the same state.
		if a.claimLinkNotice() {
			a.store.Notify(state.NoticeWarn,
				"This device was removed from your account, so it can no longer receive "+
					"encrypted messages. Approve it again from another signed-in device to "+
					"restore it.")
		}
		a.setLinkPendingQuiet()
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
