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

	wound, ok := view.Advance(10)
	if !ok {
		t.Fatal("Advance refused a legitimate move")
	}
	if wound.Index != 10 {
		t.Fatalf("Advance left the index at %d", wound.Index)
	}
	if _, err := wound.MessageKey(5); !errors.Is(err, ErrChainRewind) {
		t.Error("an advanced view could still read a position it passed")
	}
	if got, err := wound.MessageKey(15); err != nil || got != keys[15] {
		t.Errorf("an advanced view lost a position it should still hold (err=%v)", err)
	}
	// Advancing backwards is a no-op rather than a way to regain history, and it
	// reports that it did not move.
	back, moved := wound.Advance(2)
	if moved || back.Index != 10 {
		t.Error("Advance went backwards")
	}
	// A gap too large to hash must report failure rather than silently returning
	// the view unmoved — a caller that treats that as success ships an unwound
	// view into an invite bundle, which is the disclosure winding exists to stop.
	if _, moved := wound.Advance(wound.Index + maxChainSkip + 1); moved {
		t.Error("Advance claimed to move past the skip cap")
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

// TestContinuesProvesSameChain: a view may only replace one it can hash forward
// to. This is what makes a chain view safe to take from somebody who is not its
// owner — chain IDs are self-asserted, so "same ID, lower index" proves nothing.
func TestContinuesProvesSameChain(t *testing.T) {
	c, _ := NewChain()
	early := c.View()
	for i := 0; i < 6; i++ {
		c.Next()
	}
	later := c.View()

	if !early.Continues(later) {
		t.Error("a genuine earlier view of the same chain was rejected")
	}
	if later.Continues(early) {
		t.Error("a LATER view was accepted as continuous with an earlier one")
	}
	if !later.Continues(later) {
		t.Error("a view is not continuous with itself")
	}

	// The attack: somebody else's chain state wearing this chain's ID at a lower
	// index. Under a plain lowest-index-wins rule this always won.
	impostor, _ := NewChain()
	forged := ChainView{ID: later.ID, Index: 0}
	forged.state = impostor.View().state
	if forged.Continues(later) {
		t.Error("a substituted chain state was accepted as continuous")
	}

	// A different chain's ID never matches, whatever the indices.
	if impostor.View().Continues(later) {
		t.Error("a view with a different chain ID was accepted")
	}
}

// TestContinuesRefusesUnboundedWork: the gap comes off the wire, so proving
// continuity must not be an arbitrary amount of hashing on request.
func TestContinuesRefusesUnboundedWork(t *testing.T) {
	c, _ := NewChain()
	early := c.View()
	far, ok := early.Advance(maxContinuityCheck + 1)
	if !ok {
		t.Fatal("setup: could not advance")
	}
	if early.Continues(far) {
		t.Error("Continues proved a link across more steps than it should hash")
	}
}
