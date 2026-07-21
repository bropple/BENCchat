package oscar

import (
	"sync"
	"time"

	"github.com/benco-holdings/benchat/internal/wire"
)

// maxPace bounds how long reserve() will ask a caller to wait. Past it the send
// is REFUSED rather than sent early — sending anyway lands over the server's
// limit, and the server discards those without a word, so the message is lost
// with no error and no acknowledgement. Refusing surfaces something the user can
// see and resend. Generous on purpose: with a sanely tuned server class, normal
// conversation never waits at all, so reaching this means something is wrong.
const maxPace = 30 * time.Second

// rateClass is the client's live view of one server rate class, plus the moving
// average and last-send time we track to pace ourselves the way the server paces
// us. Levels are milliseconds, matching wire.RateParamsSNAC and the server's
// CheckRateLimit.
type rateClass struct {
	window int64
	// target is the moving-average level we pace toward: LimitLevel (the drop
	// threshold) plus half the headroom up to AlertLevel. That keeps the average
	// safely clear of drops while allowing more throughput than pinning to alert.
	target   int64
	max      int64
	curAvg   int64     // moving average of the gap between our sends (ms)
	lastSend time.Time // when our most recent send in this class landed
}

// rateLimiter paces outbound SNACs so their per-class moving average never falls
// below the level at which the server would start silently dropping them.
//
// The server computes, for each SNAC we send, a moving average of the time since
// our previous send in that class (see open-oscar-server CheckRateLimit): newAvg
// = (avg*(W-1) + gapMs) / W, clamped to MaxLevel. Below LimitLevel it drops the
// SNAC; below DisconnectLevel it drops the session. We run the same recurrence
// ahead of each send and, if sending now would pull the average below a safe
// target (AlertLevel — comfortably above LimitLevel), return how long to wait so
// it lands exactly at the target instead. The server, seeing the same gap we
// enforced, computes the same safe average.
type rateLimiter struct {
	mu      sync.Mutex
	classes map[uint16]*rateClass // by rate-class ID
	snacs   map[uint32]uint16     // (foodgroup<<16 | subgroup) -> class ID
	clock   func() time.Time
}

// newRateLimiter builds a limiter from a decoded RateParamsReply. clock is
// injectable so tests can drive time; pass time.Now in production. A class with
// a zero window is skipped (its recurrence would divide by zero); an unmapped
// SNAC type is simply never paced.
func newRateLimiter(reply wire.SNAC_0x01_0x07_OServiceRateParamsReply, clock func() time.Time) *rateLimiter {
	rl := &rateLimiter{
		classes: make(map[uint16]*rateClass, len(reply.RateClasses)),
		snacs:   make(map[uint32]uint16),
		clock:   clock,
	}
	now := clock()
	for _, c := range reply.RateClasses {
		if c.WindowSize == 0 {
			continue
		}
		limit, alert := int64(c.LimitLevel), int64(c.AlertLevel)
		target := limit
		if alert > limit {
			target = limit + (alert-limit)/2
		}
		rl.classes[c.ID] = &rateClass{
			window: int64(c.WindowSize),
			target: target,
			max:    int64(c.MaxLevel),
			// Start at the class max: a freshly signed-on session is in good
			// standing, exactly as the server initializes it.
			curAvg:   int64(c.MaxLevel),
			lastSend: now,
		}
	}
	for _, g := range reply.RateGroups {
		if _, ok := rl.classes[g.ClassID]; !ok {
			continue
		}
		for _, p := range g.Pairs {
			rl.snacs[snacKey(p.FoodGroup, p.SubGroup)] = g.ClassID
		}
	}
	return rl
}

func snacKey(fg, sg uint16) uint32 { return uint32(fg)<<16 | uint32(sg) }

// reserve accounts for one imminent send of the given SNAC type and returns how
// long the caller should wait before actually writing it. It returns 0 for an
// unthrottled SNAC type or when the send is already safe (the common case). It
// updates the class's moving average and last-send time as if the send happens
// after the returned delay, so concurrent callers naturally queue behind one
// another.
// reserve returns how long to wait before sending this SNAC, and whether the
// send is allowed at all. false means the required wait exceeds maxPace: the
// caller must fail the send rather than transmit into a rate limit and have it
// silently discarded.
func (rl *rateLimiter) reserve(fg, sg uint16) (time.Duration, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	id, ok := rl.snacs[snacKey(fg, sg)]
	if !ok {
		return 0, true // unmapped SNAC types are never paced
	}
	c := rl.classes[id]

	now := rl.clock()
	elapsed := now.Sub(c.lastSend).Milliseconds()

	// The gap that would land the moving average exactly on the safe target:
	//   target = (avg*(W-1) + gap) / W  ->  gap = target*W - avg*(W-1)
	required := c.target*c.window - c.curAvg*(c.window-1)

	var waitMs, gap int64
	if elapsed >= required {
		waitMs, gap = 0, elapsed // already safe; record the real gap
	} else {
		waitMs, gap = required-elapsed, required // wait, then land on target
	}
	if waitMs > maxPace.Milliseconds() {
		// Refuse rather than send early. Sending anyway (what this used to do) put
		// the SNAC over the server's limit, and the server discards those silently
		// — the message simply vanished. A refusal the caller can surface, and the
		// user can resend, beats a message that quietly evaporates. Nothing is
		// mutated: this send never happened.
		return 0, false
	}

	newAvg := (c.curAvg*(c.window-1) + gap) / c.window
	if newAvg > c.max {
		newAvg = c.max
	}
	c.curAvg = newAvg
	c.lastSend = now.Add(time.Duration(waitMs) * time.Millisecond)
	return time.Duration(waitMs) * time.Millisecond, true
}
