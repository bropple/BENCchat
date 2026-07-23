package client

import (
	"testing"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
	"github.com/benco-holdings/benchat/internal/wire"
)

// queryReply builds the wire body of a directory answer about screenName, the
// way a server pushing one would. The manifest bytes are junk on purpose: the
// tests below install their own verifier, so what matters is whether the
// verifier is consulted at all, not what it decides.
func queryReply(t *testing.T, screenName string) []byte {
	t.Helper()
	return marshal(t, wire.SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
		ScreenName: screenName,
		Present:    1,
		Manifest:   []byte{0xBE, 0xEF},
		SigAlg:     wire.BENCOAlgEd25519,
		Signature:  []byte{0x01},
	})
}

// A query reply correlated to no request this client made must be dropped
// before the verifier ever sees it. Verification cannot stand in for
// correlation: a manifest is checked against the identity key carried inside
// itself, so a hostile server can push a "valid" manifest for any screen name —
// including our own, where the app layer's response to a replaced identity is
// to sign the user out and delete their saved password. The one thing tying a
// reply to reality is that we asked.
func TestUnsolicitedQueryReplyIsDroppedUnread(t *testing.T) {
	c, _ := newTestClient(t)
	verified := 0
	c.SetManifestVerifier(func(sm SignedManifest) ([]e2ee.Device, bool) {
		verified++
		return []e2ee.Device{{Box: [32]byte{1}}}, true
	})

	c.handleKeyDir(wire.SNACFrame{
		FoodGroup: wire.BENCOKeyDir,
		SubGroup:  wire.BENCOKeyDirQueryReply,
		RequestID: 7, // no request with this ID was ever sent
	}, queryReply(t, "bob"))

	if verified != 0 {
		t.Errorf("the verifier ran %d time(s) on an unsolicited reply; it must never see one", verified)
	}
	if _, held := c.PeerKeys("bob"); held {
		t.Error("keys were learned from a reply nobody asked for")
	}
}

// The gate must not eat the answers we DID ask for: a reply arriving while its
// request is outstanding still teaches keys and reaches its waiter.
func TestSolicitedQueryReplyStillLearnsAndDelivers(t *testing.T) {
	c, _ := newTestClient(t)
	c.SetManifestVerifier(func(sm SignedManifest) ([]e2ee.Device, bool) {
		return []e2ee.Device{{Box: [32]byte{1}}}, true
	})

	ch, done := c.waitKeyDir(7)
	defer done()
	c.handleKeyDir(wire.SNACFrame{
		FoodGroup: wire.BENCOKeyDir,
		SubGroup:  wire.BENCOKeyDirQueryReply,
		RequestID: 7,
	}, queryReply(t, "bob"))

	if _, held := c.PeerKeys("bob"); !held {
		t.Error("a solicited reply taught no keys; the gate is refusing our own answers")
	}
	select {
	case r := <-ch:
		if !r.manifest.Present {
			t.Error("the waiter received an empty reply")
		}
	default:
		t.Error("the waiter never received the reply")
	}
}

// A device challenge that cannot be answered must be visible. It comes once,
// the server never re-asks, and under enforcement an unattested session is
// refused everything for its lifetime — a failure that used to be a single log
// line, presenting as a client that mysteriously stopped working and then
// "fixed itself" on the next sign-on.
func TestUnanswerableChallengeIsVisible(t *testing.T) {
	c, store := newTestClient(t) // no signing key installed

	var notices []string
	unsub := store.Subscribe(func(e state.Event) {
		if e.Kind == state.EventNotice {
			notices = append(notices, e.Notice)
		}
	})
	defer unsub()

	c.handleKeyDir(wire.SNACFrame{
		FoodGroup: wire.BENCOKeyDir,
		SubGroup:  wire.BENCOKeyDirAttestChallenge,
	}, marshal(t, wire.SNAC_0xBE00_0x000A_BENCOKeyDirAttestChallenge{
		Version: wire.BENCOKeyDirVersion,
		Nonce:   make([]byte, e2ee.AttestNonceLen),
	}))

	if len(notices) == 0 {
		t.Fatal("a challenge arrived with no signing key to answer it and nothing was said to the user")
	}
}

// attestReply builds the server's outcome SNAC body.
func attestReply(t *testing.T, accepted uint8) []byte {
	t.Helper()
	return marshal(t, wire.SNAC_0xBE00_0x000C_BENCOKeyDirAttestReply{
		Version:  wire.BENCOKeyDirVersion,
		Accepted: accepted,
	})
}

func attestReplyFrame() wire.SNACFrame {
	return wire.SNACFrame{FoodGroup: wire.BENCOKeyDir, SubGroup: wire.BENCOKeyDirAttestReply}
}

// A rejection must alarm the user ONLY when we believe this device is enrolled.
// While it is not — the ordinary window between a linking device answering the
// sign-on challenge and publishing the manifest that enrols it — the rejection
// is expected and self-healing, and a "you were removed, link again" scare there
// resolves itself a breath later.
func TestAttestRejectionNoticeGatedOnEnrollment(t *testing.T) {
	t.Run("not enrolled: no alarm", func(t *testing.T) {
		c, store := newTestClient(t)
		c.attestMu.Lock()
		c.deviceEnrolled = false
		c.attestMu.Unlock()

		var notices int
		unsub := store.Subscribe(func(e state.Event) {
			if e.Kind == state.EventNotice {
				notices++
			}
		})
		defer unsub()

		c.handleKeyDir(attestReplyFrame(), attestReply(t, 0))
		if notices != 0 {
			t.Fatalf("a rejection during the linking window alarmed the user (%d notices)", notices)
		}
	})

	t.Run("enrolled: surfaced", func(t *testing.T) {
		c, store := newTestClient(t)
		c.attestMu.Lock()
		c.deviceEnrolled = true
		c.attestMu.Unlock()

		var notices int
		unsub := store.Subscribe(func(e state.Event) {
			if e.Kind == state.EventNotice {
				notices++
			}
		})
		defer unsub()

		c.handleKeyDir(attestReplyFrame(), attestReply(t, 0))
		if notices == 0 {
			t.Fatal("an enrolled device's rejection was not surfaced to the user")
		}
	})
}

// A challenge stores its nonce so we can answer it AGAIN after enrolment, and a
// fresh challenge means the session is no longer attested until it re-proves.
func TestChallengeStoresNonceAndResetsAttested(t *testing.T) {
	c, _ := newTestClient(t)
	c.attestMu.Lock()
	c.attested = true // pretend a prior attestation
	c.attestMu.Unlock()

	nonce := make([]byte, e2ee.AttestNonceLen)
	for i := range nonce {
		nonce[i] = 7
	}
	c.handleKeyDir(
		wire.SNACFrame{FoodGroup: wire.BENCOKeyDir, SubGroup: wire.BENCOKeyDirAttestChallenge},
		marshal(t, wire.SNAC_0xBE00_0x000A_BENCOKeyDirAttestChallenge{
			Version: wire.BENCOKeyDirVersion,
			Nonce:   nonce,
		}),
	)

	c.attestMu.Lock()
	gotNonce := append([]byte(nil), c.attestNonce...)
	stillAttested := c.attested
	c.attestMu.Unlock()

	if len(gotNonce) != e2ee.AttestNonceLen || gotNonce[0] != 7 {
		t.Fatalf("challenge nonce was not stored for re-answer: %v", gotNonce)
	}
	if stillAttested {
		t.Fatal("a fresh challenge left the session marked attested")
	}
}

// Becoming enrolled re-answers a held challenge — observable here, with no
// signing key installed, as the "no signing key" notice sendAttestation emits
// when it tries. And an already-attested session does NOT re-answer.
func TestEnrollmentReanswersHeldChallenge(t *testing.T) {
	t.Run("re-answers when a nonce is held and not yet attested", func(t *testing.T) {
		c, store := newTestClient(t) // no signing key
		c.attestMu.Lock()
		c.attestNonce = make([]byte, e2ee.AttestNonceLen)
		c.attested = false
		c.deviceEnrolled = false
		c.attestMu.Unlock()

		var notices int
		unsub := store.Subscribe(func(e state.Event) {
			if e.Kind == state.EventNotice {
				notices++
			}
		})
		defer unsub()

		c.SetDeviceEnrolled(true)
		if notices == 0 {
			t.Fatal("becoming enrolled did not re-answer the held challenge")
		}
	})

	t.Run("skips when already attested", func(t *testing.T) {
		c, store := newTestClient(t)
		c.attestMu.Lock()
		c.attestNonce = make([]byte, e2ee.AttestNonceLen)
		c.attested = true
		c.attestMu.Unlock()

		var notices int
		unsub := store.Subscribe(func(e state.Event) {
			if e.Kind == state.EventNotice {
				notices++
			}
		})
		defer unsub()

		c.SetDeviceEnrolled(true)
		if notices != 0 {
			t.Fatal("re-answered a challenge despite already being attested")
		}
	})
}
