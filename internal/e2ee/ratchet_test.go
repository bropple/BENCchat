package e2ee

import (
	"errors"
	"testing"
)

// TestChainKeysMatchAcrossSenderAndRecipient: the whole thing is worthless if
// the two sides derive different keys for the same position.
func TestChainKeysMatchAcrossSenderAndRecipient(t *testing.T) {
	sender, err := NewChain()
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	view := sender.View() // handed over at position 0

	for i := 0; i < 50; i++ {
		want, index := sender.Next()
		got, err := view.MessageKey(index)
		if err != nil {
			t.Fatalf("position %d: MessageKey: %v", index, err)
		}
		if got != want {
			t.Fatalf("position %d: recipient derived a different key", index)
		}
	}
}

// TestChainCannotBeWoundBackwards is the property the whole design exists for.
//
// Somebody handed the chain partway through must not be able to read what came
// before — that is what makes a newcomer unable to read pre-join history without
// re-keying anybody.
func TestChainCannotBeWoundBackwards(t *testing.T) {
	sender, _ := NewChain()

	var early [][32]byte
	for i := 0; i < 10; i++ {
		k, _ := sender.Next()
		early = append(early, k)
	}
	// A newcomer joins here and is handed the chain where it stands.
	newcomer := sender.View()

	for i := range early {
		if _, err := newcomer.MessageKey(uint32(i)); !errors.Is(err, ErrChainRewind) {
			t.Errorf("a newcomer derived the key for pre-join position %d (err=%v)", i, err)
		}
	}

	// Everything from here on is readable, which is the point of joining.
	want, index := sender.Next()
	got, err := newcomer.MessageKey(index)
	if err != nil {
		t.Fatalf("newcomer could not read a message sent after they joined: %v", err)
	}
	if got != want {
		t.Error("newcomer derived the wrong key for a post-join message")
	}
}

// TestMessageKeyDoesNotRevealTheChain: handing somebody one message key must not
// hand them the rest of the chain. That is what the domain separation is for.
func TestMessageKeyDoesNotRevealTheChain(t *testing.T) {
	c, _ := NewChain()
	state := c.state

	if messageKey(state) == step(state) {
		t.Fatal("the message key and the next chain state are the same bytes — " +
			"one leaked message key would hand over the whole chain")
	}
}

// TestChainViewSurvivesTransport: a view is handed over inside an invite, so it
// has to round-trip exactly — a state off by one byte silently decrypts nothing.
func TestChainViewSurvivesTransport(t *testing.T) {
	sender, _ := NewChain()
	for i := 0; i < 7; i++ {
		sender.Next()
	}
	original := sender.View()

	got, err := DecodeChainView(EncodeChainView(original))
	if err != nil {
		t.Fatalf("DecodeChainView: %v", err)
	}
	if got.ID != original.ID || got.Index != original.Index || got.state != original.state {
		t.Fatalf("view did not round-trip: got %+v want %+v", got, original)
	}

	// And it still derives the right keys on the far side.
	want, index := sender.Next()
	k, err := got.MessageKey(index)
	if err != nil || k != want {
		t.Errorf("a transported view derived the wrong key (err=%v)", err)
	}
}

// TestChainRefusesImplausibleSkips: the index arrives from the wire, so without
// a cap a sender claiming position four billion makes us hash four billion
// times. Refusing is the only answer that does not hang.
func TestChainRefusesImplausibleSkips(t *testing.T) {
	c, _ := NewChain()
	view := c.View()

	if _, err := view.MessageKey(maxChainSkip + 1); !errors.Is(err, ErrChainSkipTooLarge) {
		t.Errorf("an absurd index was accepted (err=%v)", err)
	}
	// A large but plausible gap — somebody away for a long conversation — works.
	if _, err := view.MessageKey(maxChainSkip); err != nil {
		t.Errorf("a large but legitimate gap was refused: %v", err)
	}
}

// TestAdvanceDiscardsHistory: winding a view forward is how retention gets
// bounded, so it must genuinely lose the ability to read what it passed.
func TestAdvanceDiscardsHistory(t *testing.T) {
	sender, _ := NewChain()
	view := sender.View()

	var keys [][32]byte
	for i := 0; i < 20; i++ {
		k, _ := sender.Next()
		keys = append(keys, k)
	}

	// Before advancing, everything opens.
	if got, err := view.MessageKey(5); err != nil || got != keys[5] {
		t.Fatalf("setup: position 5 should be readable (err=%v)", err)
	}

	wound := view.Advance(10)
	if wound.Index != 10 {
		t.Fatalf("Advance left the index at %d", wound.Index)
	}
	if _, err := wound.MessageKey(5); !errors.Is(err, ErrChainRewind) {
		t.Error("an advanced view could still read a position it passed")
	}
	if got, err := wound.MessageKey(15); err != nil || got != keys[15] {
		t.Errorf("an advanced view lost a position it should still hold (err=%v)", err)
	}
	// Advancing backwards is a no-op rather than a way to regain history.
	if back := wound.Advance(2); back.Index != 10 {
		t.Error("Advance went backwards")
	}
}

// TestSenderCannotReReadItsOwnPastMessages: the sender's own chain advances past
// each key as it uses it, so a compromised sender cannot re-derive keys it has
// finished with.
func TestSenderCannotReReadItsOwnPastMessages(t *testing.T) {
	c, _ := NewChain()
	first, _ := c.Next()
	for i := 0; i < 5; i++ {
		c.Next()
	}
	if _, err := c.View().MessageKey(0); !errors.Is(err, ErrChainRewind) {
		t.Error("a sender could still derive the key for a message it already sent")
	}
	_ = first
}

// TestChainSurvivesStorage: a chain reloaded from disk must keep sealing where
// it left off. Restarting at an earlier position would reuse message keys.
func TestChainSurvivesStorage(t *testing.T) {
	c, _ := NewChain()
	for i := 0; i < 9; i++ {
		c.Next()
	}
	restored, err := DecodeChain(EncodeChain(c))
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if restored.ID != c.ID || restored.Index != c.Index {
		t.Fatalf("restored %+v, want id=%s index=%d", restored, c.ID, c.Index)
	}
	want, wi := c.Next()
	got, gi := restored.Next()
	if wi != gi || got != want {
		t.Errorf("a restored chain diverged at position %d/%d", gi, wi)
	}
}
