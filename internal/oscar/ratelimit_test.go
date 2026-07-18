package oscar

import (
	"bytes"
	"testing"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// A representative reply: two classes and a group map, mirroring the shape
// open-oscar-server sends (classes count-prefixed, groups greedy to EOF).
func sampleRateReply() wire.SNAC_0x01_0x07_OServiceRateParamsReply {
	return wire.SNAC_0x01_0x07_OServiceRateParamsReply{
		RateClasses: []wire.RateParamsSNAC{
			{ID: 1, WindowSize: 80, ClearLevel: 2500, AlertLevel: 2000, LimitLevel: 1500, DisconnectLevel: 800, CurrentLevel: 6000, MaxLevel: 6000},
			{ID: 3, WindowSize: 20, ClearLevel: 5100, AlertLevel: 5000, LimitLevel: 4000, DisconnectLevel: 3000, CurrentLevel: 6000, MaxLevel: 6000},
		},
		RateGroups: []wire.RateGroup{
			{ClassID: 1, Pairs: []wire.RateGroupPair{{FoodGroup: wire.OService, SubGroup: wire.OServiceClientOnline}}},
			{ClassID: 3, Pairs: []wire.RateGroupPair{
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent},
			}},
		},
	}
}

// The reply must survive a marshal/unmarshal round-trip byte-for-byte — the
// greedy (unprefixed) RateGroups slice is the part most likely to desync.
func TestRateParamsReplyRoundTrip(t *testing.T) {
	want := sampleRateReply()

	var buf bytes.Buffer
	if err := wire.MarshalBE(want, &buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := buf.Bytes()

	var got wire.SNAC_0x01_0x07_OServiceRateParamsReply
	if err := wire.UnmarshalBE(&got, bytes.NewReader(encoded)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.RateClasses) != 2 {
		t.Fatalf("classes: got %d, want 2", len(got.RateClasses))
	}
	if len(got.RateGroups) != 2 {
		t.Fatalf("groups: got %d, want 2 (greedy slice under- or over-read)", len(got.RateGroups))
	}
	if got.RateGroups[1].ClassID != 3 || len(got.RateGroups[1].Pairs) != 2 {
		t.Fatalf("group[1]: got id=%d pairs=%d, want id=3 pairs=2",
			got.RateGroups[1].ClassID, len(got.RateGroups[1].Pairs))
	}
	if got.RateClasses[1].WindowSize != 20 || got.RateClasses[1].AlertLevel != 5000 {
		t.Fatalf("class[1] fields desynced: %+v", got.RateClasses[1])
	}

	// A second marshal must reproduce the exact same bytes.
	var buf2 bytes.Buffer
	if err := wire.MarshalBE(got, &buf2); err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, buf2.Bytes()) {
		t.Fatalf("round-trip changed bytes:\n first: %x\nsecond: %x", encoded, buf2.Bytes())
	}
}

// Spaced-out sends are never paced; an unmapped SNAC type is never paced.
func TestRateLimiterNoPacingWhenSpaced(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rl := newRateLimiter(sampleRateReply(), func() time.Time { return now })

	for i := 0; i < 50; i++ {
		now = now.Add(10 * time.Second) // well beyond any window
		if d := rl.reserve(wire.ICBM, wire.ICBMChannelMsgToHost); d != 0 {
			t.Fatalf("spaced send %d was paced by %v", i, d)
		}
	}

	// Feedbag isn't in the group map here, so it must never be throttled.
	now = time.Unix(1_000_000, 0)
	for i := 0; i < 100; i++ {
		if d := rl.reserve(wire.Feedbag, wire.FeedbagQuery); d != 0 {
			t.Fatalf("unmapped SNAC was paced by %v", d)
		}
	}
}

// A rapid burst eventually gets paced, and the delay it hands back is exactly
// what's needed to keep the moving average from crossing into the drop zone.
func TestRateLimiterPacesBurst(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rl := newRateLimiter(sampleRateReply(), func() time.Time { return now })

	// Class 3: window 20, alert 5000, limit 4000, max 6000, starting avg 6000.
	// Hammer it at the same instant. The average decays by the recurrence until
	// a wait is required; once required, the wait pins the average at alert.
	var firstPaced int = -1
	for i := 0; i < 8; i++ {
		d := rl.reserve(wire.ICBM, wire.ICBMChannelMsgToHost)
		if d > 0 {
			if firstPaced < 0 {
				firstPaced = i
			}
			// Simulate the caller waiting, so the recorded state stays truthful.
			now = now.Add(d)
		}
	}
	if firstPaced < 0 {
		t.Fatal("a same-instant burst was never paced")
	}
	if firstPaced == 0 {
		t.Fatal("the very first send was paced; a fresh session should start clear")
	}

	// The whole point: after pacing engages, the class average must stay at or
	// above LimitLevel (4000 for class 3 here) — that is the threshold below
	// which the server silently drops. Staying >= limit means nothing is dropped.
	const class3Limit = 4000
	if c := rl.classes[3]; c.curAvg < class3Limit {
		t.Fatalf("moving average %d fell below LimitLevel %d — pacing failed to prevent drops", c.curAvg, class3Limit)
	}
}

// The per-send wait is capped so a pathological flood can't stall a message
// indefinitely.
func TestRateLimiterCapsWait(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rl := newRateLimiter(sampleRateReply(), func() time.Time { return now })
	for i := 0; i < 40; i++ {
		d := rl.reserve(wire.ICBM, wire.ICBMChannelMsgToHost) // never advance the clock
		if d > maxPace {
			t.Fatalf("wait %v exceeded cap %v", d, maxPace)
		}
	}
}
