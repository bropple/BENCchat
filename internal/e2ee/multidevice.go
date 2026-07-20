package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Multi-device support.
//
// One account can be signed in from several machines, and no private key ever
// leaves the machine that generated it. Instead each device has its own keypair
// and the account's profile publishes the whole SET of device public keys. A
// sender encrypts to every listed device, so every device can read every
// message.
//
// The alternative — copying one private key between machines — was rejected: it
// makes the user hand-carry secret material around, and a single leak
// compromises the whole account rather than one device.
//
// The wire format is a multi-recipient envelope: the body is encrypted once
// under a random per-message key, and that key is separately wrapped to each
// recipient device. Cost grows by ~72 bytes per device rather than by a whole
// copy of the message. Group chat needs exactly this shape, so it's shared.

const (
	// maxDevices bounds the device list. Far above any real use; it exists so a
	// malformed or hostile profile can't make us allocate unboundedly, and so
	// the count fits in one byte on the wire.
	maxDevices = 32

	// The v2 and v3 profile markers are no longer written — see StripMarkerAll.
	// They remain here only so an old bio can be recognized and stripped.
	profileMarkerOpenV2 = "<!--BENCO-E2EE:v2:"
	profileMarkerOpenV3 = "<!--BENCO-E2EE:v3:"
	envelopePrefixV2    = "\x1bBENCO-E2EE:v2:"

	envelopeVersion2 = 2
	wrappedKeyLen    = 32 + box.Overhead // a 32-byte message key, sealed
)

// ErrNotForUs means a multi-recipient envelope carried no slot this device's
// key could open — normally because the sender didn't know about this device
// yet, not because anything is corrupt.
var ErrNotForUs = errors.New("e2ee: message was not encrypted to this device")

// Device is one of an account's machines: its encryption key and, from marker
// v3 onward, the signing key it uses for room messages.
type Device struct {
	Box  [32]byte
	Sign ed25519.PublicKey // nil for a peer publishing an older marker
}

// SigningKeysOf returns just the signing keys from a device set.
func SigningKeysOf(devices []Device) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, d := range devices {
		if len(d.Sign) > 0 {
			out = append(out, d.Sign)
		}
	}
	return out
}

// BoxKeysOf returns just the encryption keys from a device set.
func BoxKeysOf(devices []Device) [][32]byte {
	out := make([][32]byte, 0, len(devices))
	for _, d := range devices {
		out = append(out, d.Box)
	}
	return dedupeKeys(out)
}

// StripMarkerAll removes any marker version from a profile.
//
// Nothing writes these markers any more, but a profile written before the key
// directory existed still carries one, and it must not render as bio text.
func StripMarkerAll(profile string) string {
	if i := strings.Index(profile, profileMarkerOpenV3); i >= 0 {
		rest := profile[i:]
		j := strings.Index(rest, profileMarkerClose)
		if j < 0 {
			return strings.TrimRight(profile[:i], " \n\r\t")
		}
		profile = strings.TrimRight(profile[:i], " \n\r\t") + rest[j+len(profileMarkerClose):]
	}
	if i := strings.Index(profile, profileMarkerOpenV2); i >= 0 {
		rest := profile[i:]
		j := strings.Index(rest, profileMarkerClose)
		if j < 0 {
			return strings.TrimRight(profile[:i], " \n\r\t")
		}
		profile = strings.TrimRight(profile[:i], " \n\r\t") + rest[j+len(profileMarkerClose):]
	}
	return StripMarker(profile)
}

// dedupeKeys sorts a key set and drops duplicates, so the same device listed
// twice doesn't get two envelope slots and set comparisons stay meaningful.
func dedupeKeys(keys [][32]byte) [][32]byte {
	if len(keys) == 0 {
		return nil
	}
	sorted := make([][32]byte, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i][:]) < string(sorted[j][:])
	})
	out := sorted[:1]
	for _, k := range sorted[1:] {
		if k != out[len(out)-1] {
			out = append(out, k)
		}
	}
	if len(out) > maxDevices {
		out = out[:maxDevices]
	}
	return out
}

// IsEnvelopeAny reports whether a body is an E2EE envelope of either version.
func IsEnvelopeAny(body string) bool {
	return IsEnvelope(body) || strings.HasPrefix(body, envelopePrefixV2)
}

// SealFor encrypts message to every recipient device, signed with senderPriv.
//
// With exactly one recipient it emits the v1 single-recipient envelope, which
// an older BENCchat can still open. More than one device requires the v2
// multi-recipient form.
func SealFor(message string, recipients [][32]byte, senderPriv [32]byte) (string, error) {
	recipients = dedupeKeys(recipients)
	switch len(recipients) {
	case 0:
		return "", errors.New("e2ee: no recipient devices")
	case 1:
		return Seal(message, recipients[0], senderPriv)
	}

	// One random key encrypts the body; only that key is wrapped per device.
	var msgKey [32]byte
	if _, err := rand.Read(msgKey[:]); err != nil {
		return "", fmt.Errorf("e2ee: message key: %w", err)
	}
	var bodyNonce [24]byte
	if _, err := rand.Read(bodyNonce[:]); err != nil {
		return "", fmt.Errorf("e2ee: nonce: %w", err)
	}

	buf := make([]byte, 0, 1+24+1+len(recipients)*(24+wrappedKeyLen)+len(message)+secretbox.Overhead)
	buf = append(buf, envelopeVersion2)
	buf = append(buf, bodyNonce[:]...)
	buf = append(buf, byte(len(recipients)))

	for _, pub := range recipients {
		var wrapNonce [24]byte
		if _, err := rand.Read(wrapNonce[:]); err != nil {
			return "", fmt.Errorf("e2ee: wrap nonce: %w", err)
		}
		wrapped := box.Seal(nil, msgKey[:], &wrapNonce, &pub, &senderPriv)
		if len(wrapped) != wrappedKeyLen {
			return "", fmt.Errorf("e2ee: wrapped key is %d bytes, want %d", len(wrapped), wrappedKeyLen)
		}
		buf = append(buf, wrapNonce[:]...)
		buf = append(buf, wrapped...)
	}
	buf = secretbox.Seal(buf, []byte(message), &bodyNonce, &msgKey)

	return envelopePrefixV2 + base64.StdEncoding.EncodeToString(buf), nil
}

// OpenAny decrypts either envelope version with this device's private key.
//
// For a multi-recipient envelope it tries each wrapped slot until one opens —
// the sender doesn't label which slot belongs to whom, since that would leak
// the recipient set to anyone watching the wire.
func OpenAny(envelope string, senderPub, ourPriv [32]byte) (string, error) {
	if IsEnvelope(envelope) {
		return Open(envelope, senderPub, ourPriv)
	}
	if !strings.HasPrefix(envelope, envelopePrefixV2) {
		return "", errors.New("e2ee: not an envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(envelope[len(envelopePrefixV2):])
	if err != nil {
		return "", fmt.Errorf("e2ee: decode envelope: %w", err)
	}
	if len(raw) < 1+24+1 || raw[0] != envelopeVersion2 {
		return "", errors.New("e2ee: malformed envelope")
	}

	var bodyNonce [24]byte
	copy(bodyNonce[:], raw[1:25])
	count := int(raw[25])
	if count == 0 || count > maxDevices {
		return "", errors.New("e2ee: implausible recipient count")
	}
	slotLen := 24 + wrappedKeyLen
	headerLen := 1 + 24 + 1 + count*slotLen
	if len(raw) < headerLen {
		return "", errors.New("e2ee: truncated envelope")
	}

	for i := 0; i < count; i++ {
		off := 1 + 24 + 1 + i*slotLen
		var wrapNonce [24]byte
		copy(wrapNonce[:], raw[off:off+24])
		msgKeyBytes, ok := box.Open(nil, raw[off+24:off+slotLen], &wrapNonce, &senderPub, &ourPriv)
		if !ok {
			continue // a slot for a different device
		}
		var msgKey [32]byte
		copy(msgKey[:], msgKeyBytes)
		plain, ok := secretbox.Open(nil, raw[headerLen:], &bodyNonce, &msgKey)
		if !ok {
			return "", errors.New("e2ee: body failed authentication")
		}
		return string(plain), nil
	}
	return "", ErrNotForUs
}

// SafetyNumberSet is the safety number for two accounts identified by their
// device sets, rather than by a single key each.
//
// Both sides sort their own keys and the two sides are ordered against each
// other, so the number is identical from either perspective. Adding a device
// necessarily changes it — with no signing identity key there is nothing
// stable underneath to derive from — so callers must distinguish "keys were
// added" from "keys were replaced" before deciding how loudly to react. See
// KeysOnlyAdded.
func SafetyNumberSet(ours, theirs [][32]byte) string {
	a := flatten(dedupeKeys(ours))
	b := flatten(dedupeKeys(theirs))
	x, y := a, b
	if x > y {
		x, y = y, x
	}
	sum := sha256.Sum256([]byte(x + y))
	groups := make([]string, 6)
	for i := range groups {
		n := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % 100000
		groups[i] = fmt.Sprintf("%05d", n)
	}
	return strings.Join(groups, " ")
}

func flatten(keys [][32]byte) string {
	var sb strings.Builder
	for _, k := range keys {
		sb.Write(k[:])
	}
	return sb.String()
}

// KeysOnlyAdded reports whether every previously-seen key is still present.
//
// This is the difference between "they set up a second machine" — expected, and
// merely worth mentioning — and "a key we relied on is gone", which is what a
// substitution attack looks like and deserves a warning.
func KeysOnlyAdded(before, after [][32]byte) bool {
	if len(before) == 0 {
		return true
	}
	have := make(map[[32]byte]bool, len(after))
	for _, k := range after {
		have[k] = true
	}
	for _, k := range before {
		if !have[k] {
			return false
		}
	}
	return true
}

// EncodeKeys renders a device set for storage (sorted, comma-separated).
func EncodeKeys(keys [][32]byte) string {
	keys = dedupeKeys(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = EncodeKey(k)
	}
	return strings.Join(parts, ",")
}

// DecodeKeys parses what EncodeKeys wrote. Unparseable entries are skipped.
func DecodeKeys(s string) [][32]byte {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out [][32]byte
	for _, part := range strings.Split(s, ",") {
		if k, err := DecodeKey(part); err == nil {
			out = append(out, k)
		}
	}
	return dedupeKeys(out)
}

// --- Device linking -------------------------------------------------------
//
// Devices on one account discover each other by messaging the account itself:
// the server relays a self-addressed IM to every signed-on session. A new
// machine announces its public key; an existing machine — after the user
// approves — replies with the full device list so both converge.
//
// These messages are deliberately NOT encrypted: a device that hasn't been
// linked yet is exactly the one whose key nobody holds. Nothing secret is in
// them (public keys only), and the approval step is what supplies trust — the
// channel itself proves only that the sender knows the account password.

const (
	deviceMsgPrefix = "\x1bBENCO-DEVICE:v1:"

	// DeviceAnnounce says "this is my public key" — sent by a device on sign-on.
	DeviceAnnounce = "announce"
	// DeviceShare carries the approving device's full known device list back.
	DeviceShare = "share"
	// DeviceDeny tells a device its link request was refused. Without it the
	// refused machine sits signed in and unable to read anything, with nothing
	// on screen explaining why — the approval happened somewhere else entirely.
	DeviceDeny = "deny"
)

// IsDeviceMessage reports whether a message body is device-linking traffic
// rather than something a human sent. Such messages must never be shown in a
// conversation.
func IsDeviceMessage(body string) bool { return strings.HasPrefix(body, deviceMsgPrefix) }

// EncodeDeviceMessage builds a device-linking message body.
func EncodeDeviceMessage(kind string, keys [][32]byte) string {
	return deviceMsgPrefix + kind + ":" + EncodeKeys(keys)
}

// DecodeDeviceMessage parses one. ok is false for anything malformed or for a
// kind we don't recognize, so a future message type is ignored rather than
// misread.
func DecodeDeviceMessage(body string) (kind string, keys [][32]byte, ok bool) {
	if !IsDeviceMessage(body) {
		return "", nil, false
	}
	rest := body[len(deviceMsgPrefix):]
	i := strings.Index(rest, ":")
	if i < 0 {
		return "", nil, false
	}
	kind = rest[:i]
	// Every kind must be listed here. A constant defined elsewhere but missing
	// from this check decodes to nothing and the message is silently dropped —
	// which is exactly how DeviceDeny appeared to do nothing at all.
	if kind != DeviceAnnounce && kind != DeviceShare && kind != DeviceDeny {
		return "", nil, false
	}
	keys = DecodeKeys(rest[i+1:])
	if len(keys) == 0 {
		return "", nil, false
	}
	return kind, keys, true
}

// Fingerprint renders a short human-comparable code for one device key, so the
// user approving a link can check it against what the new machine displays.
func Fingerprint(pub [32]byte) string {
	sum := sha256.Sum256(pub[:])
	groups := make([]string, 4)
	for i := range groups {
		n := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % 100000
		groups[i] = fmt.Sprintf("%05d", n)
	}
	return strings.Join(groups, " ")
}

// MaxDevices is the ceiling on an account's device set, exported so callers can
// warn before they reach it.
const MaxDevices = maxDevices

// PickDevices chooses which keys survive when a device set is over the cap.
//
// dedupeKeys truncates by key order, which is fine as a bound on a peer's list
// but wrong for our own: public keys sort randomly, so it evicts an arbitrary
// device — possibly the one running this code, which then cannot read messages
// sent to its own account and has no way to say why.
//
// Here `ours` is always kept, and the remaining slots go to the most recently
// seen keys. Eviction then means "this machine hasn't been seen in a long
// time", which is the only thing that can be said honestly about a key set.
// Ties break on key order so the result is deterministic.
func PickDevices(ours [32]byte, keys [][32]byte, seen map[string]int64) [][32]byte {
	keys = dedupeAll(keys)
	if len(keys) <= maxDevices {
		return keys
	}

	rest := make([][32]byte, 0, len(keys))
	for _, k := range keys {
		if k != ours {
			rest = append(rest, k)
		}
	}
	sort.SliceStable(rest, func(i, j int) bool {
		si, sj := seen[EncodeKey(rest[i])], seen[EncodeKey(rest[j])]
		if si != sj {
			return si > sj // most recently seen first
		}
		return string(rest[i][:]) < string(rest[j][:])
	})

	out := [][32]byte{ours}
	for _, k := range rest {
		if len(out) == maxDevices {
			break
		}
		out = append(out, k)
	}
	return dedupeAll(out)
}

// dedupeAll sorts and removes duplicates WITHOUT applying the cap, so the
// selection above decides what to drop rather than having it decided already.
func dedupeAll(keys [][32]byte) [][32]byte {
	if len(keys) == 0 {
		return nil
	}
	sorted := make([][32]byte, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i][:]) < string(sorted[j][:])
	})
	out := sorted[:1]
	for _, k := range sorted[1:] {
		if k != out[len(out)-1] {
			out = append(out, k)
		}
	}
	return out
}
