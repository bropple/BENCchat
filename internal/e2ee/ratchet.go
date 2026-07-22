package e2ee

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Per-sender message chains.
//
// A room's single shared key has one property that cannot be fixed by rotating
// it: anybody handed the key can read everything ever sealed under it, including
// what was said before they arrived. Rotating on join papers over that by
// minting a new key each time somebody joins, which costs every member a retired
// key on disk forever and does it at the most frequent moment in a room's life.
//
// A chain removes the need. Each SENDER keeps a forward-only chain; every
// message names its position, and a recipient handed the chain at position N can
// derive keys for N onward and — because the step is a one-way hash — cannot
// walk back to N-1. So a newcomer is given the chain where it currently stands
// and simply has no way to read what came before. No re-keying, nothing retired,
// and the boundary is arithmetic rather than a policy somebody has to remember
// to apply.
//
// This is Megolm's shape, arrived at for Megolm's reasons. The one thing not
// borrowed is its four-part ratchet, which exists so a client can skip a very
// long way forward cheaply. A single chain costs one hash per position skipped;
// at the scale of these rooms that is microseconds, and one chain is markedly
// easier to reason about than four with staggered reseeding.
//
// What a chain does NOT provide is forward secrecy against the holder of its
// current state: whoever has position N can derive every key from N onward,
// forever. That is inherent — it is the same property that lets a member read
// messages sent while they were offline — and it is why removing somebody still
// means starting a fresh chain rather than advancing this one.

const (
	// chainIDLen is how many bytes name a chain. Random rather than derived, so
	// the name stays constant while the state underneath it advances.
	chainIDLen = 8

	// maxChainSkip bounds how far a single message may drag us forward.
	//
	// The index arrives from the wire, so without a cap a sender claiming
	// position four billion makes the recipient hash four billion times. This is
	// a denial-of-service guard, not a protocol limit: a gap this large means
	// something is wrong, and the honest answer is to refuse rather than to hang.
	maxChainSkip = 100000
)

// ErrChainRewind means a message names a position EARLIER than the chain state
// we hold. It is the ratchet working, not a failure: we were given the chain
// partway through and cannot walk backwards to read what came before.
var ErrChainRewind = errors.New("e2ee: message predates the chain state we hold")

// ErrChainSkipTooLarge means a message names a position implausibly far ahead.
var ErrChainSkipTooLarge = errors.New("e2ee: message is too far ahead of our chain state")

// Chain is a sender's own outbound message chain.
type Chain struct {
	// ID names the chain for its whole life, including across advances.
	ID string
	// state is the chain value AT Index.
	state [32]byte
	// Index is the position the NEXT message will use.
	Index uint32
}

// ChainView is somebody else's chain as we hold it: a state, the position it
// belongs to, and nothing that lets us go back further.
type ChainView struct {
	ID    string
	state [32]byte
	Index uint32
}

// domain separates the two things derived from a chain state. Without it the
// message key and the next state would be the same bytes, and handing somebody a
// message key would hand them the rest of the chain.
const (
	domainMessage = 0x01
	domainRatchet = 0x02
)

// NewChain mints a fresh outbound chain starting at position zero.
func NewChain() (Chain, error) {
	var c Chain
	if _, err := rand.Read(c.state[:]); err != nil {
		return Chain{}, fmt.Errorf("e2ee: chain seed: %w", err)
	}
	id := make([]byte, chainIDLen)
	if _, err := rand.Read(id); err != nil {
		return Chain{}, fmt.Errorf("e2ee: chain id: %w", err)
	}
	c.ID = hex.EncodeToString(id)
	return c, nil
}

// step advances a chain state by one position.
func step(state [32]byte) [32]byte {
	mac := hmac.New(sha256.New, state[:])
	mac.Write([]byte{domainRatchet})
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// messageKey derives the key sealing the message at a state's own position.
func messageKey(state [32]byte) [32]byte {
	mac := hmac.New(sha256.New, state[:])
	mac.Write([]byte{domainMessage})
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Next returns the key for the next message and advances the chain past it.
//
// The state for the position just used is destroyed by the advance: this is the
// sender's own copy, and keeping it would mean a compromised sender could
// re-derive keys they no longer need.
func (c *Chain) Next() (key [32]byte, index uint32) {
	key = messageKey(c.state)
	index = c.Index
	c.state = step(c.state)
	c.Index++
	return key, index
}

// View is the chain as it should be handed to somebody else: the state where it
// currently stands, which grants everything from here on and nothing before.
func (c Chain) View() ChainView {
	return ChainView{ID: c.ID, state: c.state, Index: c.Index}
}

// MessageKey derives the key for a given position.
//
// The stored state is NOT advanced. A recipient keeps the earliest state it was
// given so that history stays readable, and ratchets a copy forward for each
// message — the alternative, advancing in place, would make every message
// destroy the ability to re-read the ones before it.
func (v ChainView) MessageKey(index uint32) ([32]byte, error) {
	if index < v.Index {
		return [32]byte{}, ErrChainRewind
	}
	if index-v.Index > maxChainSkip {
		return [32]byte{}, ErrChainSkipTooLarge
	}
	state := v.state
	for i := v.Index; i < index; i++ {
		state = step(state)
	}
	return messageKey(state), nil
}

// Advance moves a view forward, discarding the ability to read anything before
// the new position. ok reports whether it actually moved.
//
// This is the room-side retention control: a view kept at position zero can open
// the whole chain forever, which is what makes a leaked key file worth so much.
// Winding it forward past what history still needs bounds that without losing
// anything, since the plaintext lives in the history file under a different key.
//
// ok exists because the failure is silent and the callers were treating it as
// success. A gap past maxChainSkip returns the view UNMOVED, and a caller that
// ships that into an invite hands a newcomer the whole chain — the same
// disclosure the winding was there to prevent, reached by a different route.
// Callers must fail closed on !ok rather than send what they were given.
func (v ChainView) Advance(to uint32) (ChainView, bool) {
	if to <= v.Index {
		return v, false
	}
	if to-v.Index > maxChainSkip {
		return v, false
	}
	state := v.state
	for i := v.Index; i < to; i++ {
		state = step(state)
	}
	return ChainView{ID: v.ID, state: state, Index: to}, true
}

// maxContinuityCheck bounds how far Continues will hash to prove a link. Ten
// thousand steps is a couple of milliseconds; past that we decline rather than
// let a caller hand us an expensive proof obligation.
const maxContinuityCheck = 10000

// Continues reports whether v is the SAME chain as prior, reaching further back.
//
// This is what makes a chain view safe to accept from somebody who is not its
// owner. Chain IDs are self-asserted — they ride in the clear on every message
// and nothing binds one to an account — so "same ID, lower index" is not a
// reason to believe anything. It is exactly the claim an attacker makes when
// they broadcast their own random state under somebody else's chain ID, and
// under a lowest-index-wins rule that claim always won.
//
// Continuity is checkable without trusting anyone: hash the offered state
// forward and see whether it arrives at the state we already hold. Only the
// chain's real owner can produce a state that does, because the step is one-way.
// A relay legitimately handing us more read-back passes; a stranger substituting
// a different chain cannot.
func (v ChainView) Continues(prior ChainView) bool {
	if v.ID != prior.ID || v.Index > prior.Index {
		return false
	}
	if prior.Index-v.Index > maxContinuityCheck {
		return false
	}
	s := v.state
	for i := v.Index; i < prior.Index; i++ {
		s = step(s)
	}
	return subtle.ConstantTimeCompare(s[:], prior.state[:]) == 1
}

// EncodeChainView renders a view for transport in an invite: id, index, state.
func EncodeChainView(v ChainView) string {
	buf := make([]byte, 0, 4+32)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], v.Index)
	buf = append(buf, idx[:]...)
	buf = append(buf, v.state[:]...)
	return v.ID + ":" + base64.StdEncoding.EncodeToString(buf)
}

// DecodeChainView parses one.
func DecodeChainView(s string) (ChainView, error) {
	var v ChainView
	i := strings.Index(s, ":")
	if i <= 0 {
		return v, errors.New("e2ee: malformed chain view")
	}
	id := s[:i]
	if len(id) != chainIDLen*2 {
		return v, fmt.Errorf("e2ee: chain id is %d chars, want %d", len(id), chainIDLen*2)
	}
	if _, err := hex.DecodeString(id); err != nil {
		return v, fmt.Errorf("e2ee: chain id: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(s[i+1:])
	if err != nil {
		return v, fmt.Errorf("e2ee: decode chain view: %w", err)
	}
	if len(raw) != 4+32 {
		return v, fmt.Errorf("e2ee: chain view is %d bytes, want %d", len(raw), 4+32)
	}
	v.ID = id
	v.Index = binary.BigEndian.Uint32(raw[:4])
	copy(v.state[:], raw[4:])
	return v, nil
}

// EncodeChain renders our own outbound chain for storage.
//
// Separate from EncodeChainView because the two are not interchangeable: a view
// is what we hand somebody else, and a chain is the thing we advance. Storing a
// view where a chain belongs would silently lose the ability to send.
func EncodeChain(c Chain) string {
	buf := make([]byte, 0, 4+32)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], c.Index)
	buf = append(buf, idx[:]...)
	buf = append(buf, c.state[:]...)
	return c.ID + ":" + base64.StdEncoding.EncodeToString(buf)
}

// DecodeChain parses a stored outbound chain.
func DecodeChain(s string) (Chain, error) {
	v, err := DecodeChainView(s)
	if err != nil {
		return Chain{}, err
	}
	return Chain{ID: v.ID, state: v.state, Index: v.Index}, nil
}
