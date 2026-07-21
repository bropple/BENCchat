package e2ee

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// TestChainRoomMessageRoundTrips: seal under a chain, open with a view of it.
func TestChainRoomMessageRoundTrips(t *testing.T) {
	signer := mustSigner(t)
	chain, err := NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	view := chain.View() // handed over before anything was sent
	views := map[string]ChainView{view.ID: view}

	for i := 0; i < 5; i++ {
		env, err := SealRoomChain("r", "message", &chain, signer)
		if err != nil {
			t.Fatalf("SealRoomChain: %v", err)
		}
		if !IsRoomEnvelope(env) || !IsRoomChainEnvelope(env) {
			t.Fatal("output is not recognized as a chain room envelope")
		}
		if strings.Contains(env, "message") {
			t.Fatal("plaintext went onto the wire")
		}
		got, err := OpenRoomChain("r", env, views, []ed25519.PublicKey{signer.Public})
		if err != nil {
			t.Fatalf("OpenRoomChain: %v", err)
		}
		if got.Text != "message" || !got.Verified {
			t.Fatalf("opened = %+v", got)
		}
		if got.SentAt.IsZero() {
			t.Error("no stamp on a chain-sealed message")
		}
	}
}

// TestChainRoomMessageHidesPreJoinHistory is R5, end to end at the envelope.
//
// A member handed the chain partway through must not be able to read what was
// said before they arrived — without anybody having re-keyed anything.
func TestChainRoomMessageHidesPreJoinHistory(t *testing.T) {
	signer := mustSigner(t)
	chain, _ := NewChain()

	var before []string
	for i := 0; i < 5; i++ {
		env, _ := SealRoomChain("r", "said before they joined", &chain, signer)
		before = append(before, env)
	}

	// Somebody joins here and is given the chain where it stands.
	joiner := map[string]ChainView{chain.ID: chain.View()}

	for i, env := range before {
		_, err := OpenRoomChain("r", env, joiner, []ed25519.PublicKey{signer.Public})
		if !errors.Is(err, ErrChainRewind) {
			t.Errorf("message %d before the join was readable (err=%v)", i, err)
		}
	}

	after, _ := SealRoomChain("r", "said after they joined", &chain, signer)
	got, err := OpenRoomChain("r", after, joiner, []ed25519.PublicKey{signer.Public})
	if err != nil || got.Text != "said after they joined" {
		t.Fatalf("a post-join message was not readable: %+v err=%v", got, err)
	}
}

// TestChainRoomMessageNamesAnUnknownChain: a chain we were never given is a
// distinct, reportable condition rather than a decryption failure.
func TestChainRoomMessageNamesAnUnknownChain(t *testing.T) {
	signer := mustSigner(t)
	chain, _ := NewChain()
	env, _ := SealRoomChain("r", "hello", &chain, signer)

	_, err := OpenRoomChain("r", env, map[string]ChainView{}, []ed25519.PublicKey{signer.Public})
	if !errors.Is(err, ErrUnknownChain) {
		t.Errorf("an unknown chain reported as %v, want ErrUnknownChain", err)
	}
}

// TestChainRoomEnvelopeIndexIsAuthenticated: the position rides outside the
// sealed part because it is needed to derive the key. Flipping it must not
// silently open something else — a different position derives a different key,
// and the wrong key fails to authenticate.
func TestChainRoomEnvelopeIndexIsAuthenticated(t *testing.T) {
	signer := mustSigner(t)
	chain, _ := NewChain()
	view := chain.View()
	views := map[string]ChainView{view.ID: view}

	for i := 0; i < 3; i++ {
		SealRoomChain("r", "filler", &chain, signer)
	}
	env, _ := SealRoomChain("r", "the real message", &chain, signer)

	id, index, ok := RoomEnvelopeChain(env)
	if !ok || index != 3 {
		t.Fatalf("parsed chain=%s index=%d, want index 3", id, index)
	}

	// Claim an earlier position for the same ciphertext.
	tampered := strings.Replace(env, ":"+"3"+":", ":"+"1"+":", 1)
	if tampered == env {
		t.Fatal("test did not actually alter the index")
	}
	if _, err := OpenRoomChain("r", tampered, views, []ed25519.PublicKey{signer.Public}); err == nil {
		t.Error("a message with a rewritten index opened anyway")
	}
}
