package client

import (
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/e2ee"
	"github.com/benco-holdings/benchat/internal/state"
)

// setKeyLookupProbe replaces the directory round trip in RefreshPeerKeys.
func (c *Client) setKeyLookupProbe(fn func(screenName string) peerKeyLookup) {
	c.e2eeMu.Lock()
	c.keyLookupProbe = fn
	c.e2eeMu.Unlock()
}

// encryptingClient is a client that holds a keypair and has E2EE on, i.e. one
// that would encrypt if it knew the peer's keys.
func encryptingClient(t *testing.T) *Client {
	t.Helper()
	c, _ := newTestClient(t)
	kp, err := e2ee.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	c.SetE2EEKeyPair(kp, true)
	c.SetE2EEOn(true)
	return c
}

// TestSendRefusesWhenDirectoryWontAnswer: "I could not find out whether this
// peer has keys" must never be spent as "they have none". Falling back to
// plaintext on a failed lookup is how a server that simply declines to answer
// reads a conversation it holds no key for, and the only signal to the user
// would be a lock that never appears.
func TestSendRefusesWhenDirectoryWontAnswer(t *testing.T) {
	c := encryptingClient(t)
	c.setKeyLookupProbe(func(string) peerKeyLookup { return peerKeysUnavailable })

	wireText, encrypted, err := c.sealOutbound("bob", "meet me at the usual place")
	if err == nil {
		t.Fatal("a send went ahead despite the directory giving no answer")
	}
	if encrypted {
		t.Error("reported as encrypted despite failing")
	}
	if wireText != "" {
		t.Errorf("text was produced for the wire despite the refusal: %q", wireText)
	}
}

// TestSendGoesPlaintextWhenPeerHasNoKeys: the refusal above must not swallow the
// ordinary case. An answer of "this account has published nothing" is a real
// answer — a non-BENCchat user — and plaintext is the only thing that will ever
// work for them.
func TestSendGoesPlaintextWhenPeerHasNoKeys(t *testing.T) {
	c := encryptingClient(t)
	c.setKeyLookupProbe(func(string) peerKeyLookup { return peerKeysAbsent })

	wireText, encrypted, err := c.sealOutbound("bob", "hello")
	if err != nil {
		t.Fatalf("a send to a keyless peer was refused: %v", err)
	}
	if encrypted || wireText != "hello" {
		t.Errorf("expected plaintext passthrough, got %q (encrypted=%v)", wireText, encrypted)
	}
}

// TestNoKeyDirectoryStillSends: against a server with no key directory at all,
// nobody has keys and no retry changes that. Refusing every send there would be
// a worse failure than sending as the client always has.
func TestNoKeyDirectoryStillSends(t *testing.T) {
	c := encryptingClient(t) // no session, so SupportsKeyDir is false
	if _, encrypted, err := c.sealOutbound("bob", "hello"); err != nil || encrypted {
		t.Fatalf("send against a directory-less server: encrypted=%v err=%v", encrypted, err)
	}
}

// TestStaleKeysAreRecheckedWithoutBlocking: nothing else expires the key cache,
// and the case it exists for is invisible from here — a device the peer removed
// decrypts everything we send it, so no failure ever prompts a re-fetch. The
// re-check must happen, and must not put a round trip in front of the send.
func TestStaleKeysAreRecheckedWithoutBlocking(t *testing.T) {
	c := encryptingClient(t)
	peer, _ := e2ee.GenerateKeyPair()
	c.learnPeerKeys("bob", [][32]byte{peer.Public})

	refreshed := make(chan string, 1)
	c.setKeyLookupProbe(func(sn string) peerKeyLookup {
		select {
		case refreshed <- sn:
		default:
		}
		return peerKeysFound
	})

	// Fresh keys: no re-check.
	if _, encrypted, err := c.sealOutbound("bob", "hi"); err != nil || !encrypted {
		t.Fatalf("send with fresh keys: encrypted=%v err=%v", encrypted, err)
	}
	select {
	case <-refreshed:
		t.Fatal("re-read the directory for keys learned moments ago")
	case <-time.After(100 * time.Millisecond):
	}

	// Age them past the TTL.
	c.e2eeMu.Lock()
	c.e2eeKeysAt[state.NormalizeScreenName("bob")] = time.Now().Add(-2 * peerKeyTTL)
	c.e2eeMu.Unlock()
	if !c.peerKeysStale("bob") {
		t.Fatal("keys older than the TTL were not considered stale")
	}

	// Still encrypts — the re-check bounds the staleness window, it is not a
	// correctness gate on this message.
	if _, encrypted, err := c.sealOutbound("bob", "hi again"); err != nil || !encrypted {
		t.Fatalf("send with stale keys: encrypted=%v err=%v", encrypted, err)
	}
	select {
	case sn := <-refreshed:
		if state.NormalizeScreenName(sn) != "bob" {
			t.Errorf("refreshed the wrong peer: %q", sn)
		}
	case <-time.After(2 * time.Second):
		t.Error("stale keys were never re-read against the directory")
	}
}

// TestSignOffForgetsPeerKeys: device sets belong to the session that learned
// them. Carrying them across sign-off would hand one account's view of who holds
// which keys to the next account signed on here.
func TestSignOffForgetsPeerKeys(t *testing.T) {
	c := encryptingClient(t)
	peer, _ := e2ee.GenerateKeyPair()
	c.learnPeerKeys("bob", [][32]byte{peer.Public})
	if !c.CanEncryptTo("bob") {
		t.Fatal("keys were not learned")
	}

	c.forgetPeerKeys()

	if c.CanEncryptTo("bob") {
		t.Error("a peer's keys survived sign-off")
	}
	if !c.peerKeysStale("bob") {
		t.Error("the staleness clock survived sign-off")
	}
}
