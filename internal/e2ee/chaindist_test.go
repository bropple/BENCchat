package e2ee

import (
	"errors"
	"strings"
	"testing"
)

func devices(t *testing.T, n int) []KeyPair {
	t.Helper()
	out := make([]KeyPair, n)
	for i := range out {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		out[i] = kp
	}
	return out
}

func pubs(kps []KeyPair) [][32]byte {
	out := make([][32]byte, len(kps))
	for i, kp := range kps {
		out[i] = kp.Public
	}
	return out
}

// TestChainBroadcastReachesEveryRecipient: one message, every member opens their
// own slot and gets the same chain.
func TestChainBroadcastReachesEveryRecipient(t *testing.T) {
	sender := devices(t, 1)[0]
	members := devices(t, 12)

	chain, _ := NewChain()
	for i := 0; i < 4; i++ {
		chain.Next()
	}
	view := chain.View()

	body, err := EncodeChainBroadcast(view, pubs(members), sender.Private)
	if err != nil {
		t.Fatalf("EncodeChainBroadcast: %v", err)
	}
	if !IsChainBroadcast(body) {
		t.Fatal("output not recognized as a chain broadcast")
	}

	for i, m := range members {
		got, err := DecodeChainBroadcast(body, []KeyPair{m}, [][32]byte{sender.Public})
		if err != nil {
			t.Fatalf("member %d: %v", i, err)
		}
		if got.ID != view.ID || got.Index != view.Index || got.state != view.state {
			t.Errorf("member %d got a different chain", i)
		}
	}
}

// TestChainBroadcastExcludesTheRemoved is the property a rotation needs: the
// person being removed receives the message like everybody else and can open
// nothing in it.
func TestChainBroadcastExcludesTheRemoved(t *testing.T) {
	sender := devices(t, 1)[0]
	staying := devices(t, 5)
	removed := devices(t, 1)[0]

	chain, _ := NewChain()
	body, err := EncodeChainBroadcast(chain.View(), pubs(staying), sender.Private)
	if err != nil {
		t.Fatalf("EncodeChainBroadcast: %v", err)
	}

	if _, err := DecodeChainBroadcast(body, []KeyPair{removed}, [][32]byte{sender.Public}); !errors.Is(err, ErrNoSlotForUs) {
		t.Errorf("a removed member got %v, want ErrNoSlotForUs", err)
	}
	if _, err := DecodeChainBroadcast(body, []KeyPair{staying[0]}, [][32]byte{sender.Public}); err != nil {
		t.Errorf("a remaining member could not open their slot: %v", err)
	}
}

// TestChainBroadcastCarriesNoPlaintextState: the chain state must not be
// recoverable by anyone without a slot, including the server relaying it.
func TestChainBroadcastCarriesNoPlaintextState(t *testing.T) {
	sender := devices(t, 1)[0]
	members := devices(t, 3)
	chain, _ := NewChain()
	view := chain.View()

	body, _ := EncodeChainBroadcast(view, pubs(members), sender.Private)
	if strings.Contains(body, EncodeKey(view.state)) {
		t.Fatal("the raw chain state appears in the broadcast")
	}
}

// TestChainBroadcastFindsOneOfSeveralOurDevices: a slot is addressed to a
// device, not an account, so a multi-device client has to find whichever of its
// devices was included.
func TestChainBroadcastFindsOneOfSeveralOurDevices(t *testing.T) {
	sender := devices(t, 1)[0]
	ours := devices(t, 3)
	others := devices(t, 4)

	chain, _ := NewChain()
	// Only our SECOND device was included.
	recipients := append(pubs(others), ours[1].Public)
	body, _ := EncodeChainBroadcast(chain.View(), recipients, sender.Private)

	got, err := DecodeChainBroadcast(body, ours, [][32]byte{sender.Public})
	if err != nil {
		t.Fatalf("did not find our slot among several devices: %v", err)
	}
	if got.ID != chain.ID {
		t.Error("opened the wrong chain")
	}
}

// TestChainBroadcastRefusesOversizedRooms: past the slot ceiling the caller has
// to chunk, and a silent truncation would leave members unable to read.
func TestChainBroadcastRefusesOversizedRooms(t *testing.T) {
	sender := devices(t, 1)[0]
	chain, _ := NewChain()

	too := make([][32]byte, MaxChainSlotsPerBroadcast()+1)
	for i := range too {
		too[i][0] = byte(i % 256)
		too[i][1] = byte(i / 256)
	}
	if _, err := EncodeChainBroadcast(chain.View(), too, sender.Private); err == nil {
		t.Error("an oversized broadcast was built instead of refused")
	}
}

// TestChainBundleRoundTrips: what a newcomer is handed 1:1, since a broadcast
// only reaches people already in the room.
func TestChainBundleRoundTrips(t *testing.T) {
	var views []ChainView
	for i := 0; i < 4; i++ {
		c, _ := NewChain()
		for j := 0; j < i*3; j++ {
			c.Next()
		}
		views = append(views, c.View())
	}

	encoded, err := EncodeChainBundle(views)
	if err != nil {
		t.Fatalf("EncodeChainBundle: %v", err)
	}
	got, err := DecodeChainBundle(encoded)
	if err != nil {
		t.Fatalf("DecodeChainBundle: %v", err)
	}
	if len(got) != len(views) {
		t.Fatalf("got %d chains, want %d", len(got), len(views))
	}
	for i := range views {
		if got[i].ID != views[i].ID || got[i].Index != views[i].Index || got[i].state != views[i].state {
			t.Errorf("chain %d did not round-trip", i)
		}
	}
	if empty, err := DecodeChainBundle(""); err != nil || empty != nil {
		t.Errorf("an empty bundle should decode to nothing, got %v err=%v", empty, err)
	}
}
