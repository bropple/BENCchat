package e2ee

import (
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// TestSealForReachesEveryDevice is the whole point of multi-device: a single
// sent message must be readable on every machine the account has published,
// not just whichever one published last.
func TestSealForReachesEveryDevice(t *testing.T) {
	sender := mustKey(t)
	laptop, phone, desktop := mustKey(t), mustKey(t), mustKey(t)
	devices := [][32]byte{laptop.Public, phone.Public, desktop.Public}

	env, err := SealFor("multi-device hello 🔒", devices, sender.Private)
	if err != nil {
		t.Fatalf("SealFor: %v", err)
	}
	if !IsEnvelopeAny(env) {
		t.Fatal("output is not recognized as an envelope")
	}
	if strings.Contains(env, "multi-device hello") {
		t.Fatal("plaintext leaked into the envelope")
	}

	for name, dev := range map[string]KeyPair{"laptop": laptop, "phone": phone, "desktop": desktop} {
		got, err := OpenAny(env, sender.Public, dev.Private)
		if err != nil {
			t.Errorf("%s could not open the message: %v", name, err)
			continue
		}
		if got != "multi-device hello 🔒" {
			t.Errorf("%s decrypted %q, want the original", name, got)
		}
	}
}

// TestSealForExcludesStrangers: a device that isn't in the recipient set gets
// ErrNotForUs, and must not be able to read the body.
func TestSealForExcludesStrangers(t *testing.T) {
	sender, laptop, stranger := mustKey(t), mustKey(t), mustKey(t)

	env, err := SealFor("private", [][32]byte{laptop.Public}, sender.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAny(env, sender.Public, stranger.Private); err == nil {
		t.Fatal("a non-recipient decrypted the message")
	}

	// And the same for the multi-recipient form.
	env, err = SealFor("private", [][32]byte{laptop.Public, mustKey(t).Public}, sender.Private)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenAny(env, sender.Public, stranger.Private)
	if !errors.Is(err, ErrNotForUs) {
		t.Errorf("stranger got %v, want ErrNotForUs", err)
	}
}

// TestSingleRecipientStaysV1 keeps older BENCchat installs working: with one
// device there's no reason to emit a format they can't parse.
func TestSingleRecipientStaysV1(t *testing.T) {
	sender, only := mustKey(t), mustKey(t)
	env, err := SealFor("hi", [][32]byte{only.Public}, sender.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(env) {
		t.Fatal("a single-recipient message should use the v1 envelope for compatibility")
	}
	// The old opener must still handle it.
	got, err := Open(env, sender.Public, only.Private)
	if err != nil || got != "hi" {
		t.Fatalf("v1 Open on a single-recipient envelope: %q, %v", got, err)
	}
}

// TestOpenAnyAcceptsV1 covers the receive side of that compatibility.
func TestOpenAnyAcceptsV1(t *testing.T) {
	sender, recip := mustKey(t), mustKey(t)
	env, err := Seal("legacy", recip.Public, sender.Private)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAny(env, sender.Public, recip.Private)
	if err != nil || got != "legacy" {
		t.Fatalf("OpenAny on a v1 envelope: %q, %v", got, err)
	}
}

// TestTamperedBodyFails: authentication must reject a modified body rather than
// returning garbage plaintext.
func TestTamperedBodyFails(t *testing.T) {
	sender := mustKey(t)
	a, b := mustKey(t), mustKey(t)
	env, err := SealFor("original", [][32]byte{a.Public, b.Public}, sender.Private)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte near the end (inside the body ciphertext).
	corrupt := []byte(env)
	corrupt[len(corrupt)-3] ^= 0x01
	if _, err := OpenAny(string(corrupt), sender.Public, a.Private); err == nil {
		t.Fatal("a tampered envelope decrypted successfully")
	}
}

// TestProfileMarkerRoundTrip covers publication and discovery of a device set,
// including that a single device still uses the v1 marker.
func TestDeviceSetMarkerRoundTrip(t *testing.T) {
	one, two, three := mustKey(t), mustKey(t), mustKey(t)

	single := ProfileMarkerFor([][32]byte{one.Public})
	if !strings.Contains(single, "v1:") {
		t.Errorf("single-device marker = %q, want the v1 form", single)
	}
	got, ok := ExtractKeys("bio\n" + single)
	if !ok || len(got) != 1 || got[0] != one.Public {
		t.Fatalf("single-device extract = %v (ok=%v)", got, ok)
	}

	multi := ProfileMarkerFor([][32]byte{one.Public, two.Public, three.Public})
	if !strings.Contains(multi, "v2:") {
		t.Errorf("multi-device marker = %q, want the v2 form", multi)
	}
	got, ok = ExtractKeys("bio\n" + multi)
	if !ok || len(got) != 3 {
		t.Fatalf("multi-device extract returned %d keys (ok=%v), want 3", len(got), ok)
	}

	// Extraction is order-independent: publication order must not change the set.
	other, _ := ExtractKeys("bio\n" + ProfileMarkerFor([][32]byte{three.Public, one.Public, two.Public}))
	if EncodeKeys(got) != EncodeKeys(other) {
		t.Error("the same device set extracted differently depending on publication order")
	}
}

// TestStripMarkerAllHidesBothVersions: the key marker must never be shown to a
// user as profile text.
func TestStripMarkerAllHidesBothVersions(t *testing.T) {
	one, two := mustKey(t), mustKey(t)
	for _, marker := range []string{
		ProfileMarkerFor([][32]byte{one.Public}),
		ProfileMarkerFor([][32]byte{one.Public, two.Public}),
	} {
		got := StripMarkerAll("my bio\n" + marker)
		if strings.Contains(got, "BENCO-E2EE") {
			t.Errorf("marker survived stripping: %q", got)
		}
		if !strings.Contains(got, "my bio") {
			t.Errorf("stripping ate the profile text: %q", got)
		}
	}
}

// TestSafetyNumberSetIsOrderIndependent: both parties must compute the same
// number from opposite perspectives, or comparing them proves nothing.
func TestSafetyNumberSetIsOrderIndependent(t *testing.T) {
	ours := [][32]byte{mustKey(t).Public, mustKey(t).Public}
	theirs := [][32]byte{mustKey(t).Public}

	a := SafetyNumberSet(ours, theirs)
	b := SafetyNumberSet(theirs, ours)
	if a != b {
		t.Errorf("safety number differs by perspective: %q vs %q", a, b)
	}
	if len(strings.Fields(a)) != 6 {
		t.Errorf("safety number %q should be 6 groups", a)
	}
	// A different device set must produce a different number.
	if SafetyNumberSet(ours, [][32]byte{mustKey(t).Public}) == a {
		t.Error("an unrelated key set produced the same safety number")
	}
}

// TestKeysOnlyAdded is what separates "they added a laptop" from "a key was
// swapped out", which get very different treatment in the UI.
func TestKeysOnlyAdded(t *testing.T) {
	a, b, c := mustKey(t).Public, mustKey(t).Public, mustKey(t).Public

	if !KeysOnlyAdded([][32]byte{a}, [][32]byte{a, b}) {
		t.Error("adding a device should count as only-added")
	}
	if KeysOnlyAdded([][32]byte{a, b}, [][32]byte{a, c}) {
		t.Error("replacing a device key must NOT count as only-added")
	}
	if KeysOnlyAdded([][32]byte{a}, [][32]byte{b}) {
		t.Error("a wholesale key swap must NOT count as only-added")
	}
	if !KeysOnlyAdded(nil, [][32]byte{a}) {
		t.Error("a first sighting has nothing to lose, so it is only-added")
	}
	if KeysOnlyAdded([][32]byte{a, b}, [][32]byte{a}) {
		t.Error("removing a device key must NOT count as only-added")
	}
}

// TestMalformedEnvelopesAreRejected: a hostile or corrupt body must produce an
// error, never a panic or bogus plaintext.
func TestMalformedEnvelopesAreRejected(t *testing.T) {
	ours := mustKey(t)
	sender := mustKey(t)
	for _, bad := range []string{
		envelopePrefixV2 + "!!!not base64!!!",
		envelopePrefixV2 + "",
		envelopePrefixV2 + "AgAA",         // truncated header
		envelopePrefixV2 + "AwAAAAAAAAA=", // wrong version byte
		"plain text, not an envelope",
	} {
		if _, err := OpenAny(bad, sender.Public, ours.Private); err == nil {
			t.Errorf("malformed envelope %q was accepted", bad)
		}
	}
}

// TestDeviceMessageRoundTrip covers the linking wire format, including that
// unknown kinds are rejected rather than half-parsed.
func TestDeviceMessageRoundTrip(t *testing.T) {
	a, b := mustKey(t).Public, mustKey(t).Public

	body := EncodeDeviceMessage(DeviceAnnounce, [][32]byte{a})
	if !IsDeviceMessage(body) {
		t.Fatal("encoded device message is not recognized as one")
	}
	kind, keys, ok := DecodeDeviceMessage(body)
	if !ok || kind != DeviceAnnounce || len(keys) != 1 || keys[0] != a {
		t.Fatalf("announce round-trip failed: kind=%q keys=%d ok=%v", kind, len(keys), ok)
	}

	kind, keys, ok = DecodeDeviceMessage(EncodeDeviceMessage(DeviceShare, [][32]byte{a, b}))
	if !ok || kind != DeviceShare || len(keys) != 2 {
		t.Fatalf("share round-trip failed: kind=%q keys=%d ok=%v", kind, len(keys), ok)
	}

	for _, bad := range []string{
		"hello, a normal message",
		deviceMsgPrefix + "bogus:" + EncodeKey(a),
		deviceMsgPrefix + "announce",
		deviceMsgPrefix + "announce:not-base64!!",
	} {
		if _, _, ok := DecodeDeviceMessage(bad); ok {
			t.Errorf("malformed device message accepted: %q", bad)
		}
	}
	// A human message must never be mistaken for linking traffic.
	if IsDeviceMessage("BENCO-DEVICE: is a cool prefix") {
		t.Error("a plain message was treated as device-linking traffic")
	}
}

// TestFingerprintDistinguishesKeys: the code the user compares when approving a
// device has to actually differ between devices.
func TestFingerprintDistinguishesKeys(t *testing.T) {
	a, b := mustKey(t).Public, mustKey(t).Public
	fa, fb := Fingerprint(a), Fingerprint(b)
	if fa == fb {
		t.Fatal("two different device keys produced the same fingerprint")
	}
	if Fingerprint(a) != fa {
		t.Error("fingerprint is not stable for the same key")
	}
	if len(strings.Fields(fa)) != 4 {
		t.Errorf("fingerprint %q should be 4 groups", fa)
	}
}

// The cap used to truncate by key order. Public keys sort randomly, so that
// evicted an arbitrary device — including possibly this one, which then could
// not read messages sent to its own account.
func TestPickDevicesNeverEvictsThisDevice(t *testing.T) {
	ours, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := [][32]byte{ours.Public}
	seen := map[string]int64{}
	for i := 0; i < MaxDevices*2; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, kp.Public)
		seen[EncodeKey(kp.Public)] = int64(i) // later index == more recent
	}
	// Deliberately the STALEST entry, so recency alone would evict it. Only the
	// "never drop ourselves" rule can save it.
	seen[EncodeKey(ours.Public)] = -1

	got := PickDevices(ours.Public, keys, seen)
	if len(got) != MaxDevices {
		t.Fatalf("kept %d devices, want the cap of %d", len(got), MaxDevices)
	}
	found := false
	for _, k := range got {
		if k == ours.Public {
			found = true
		}
	}
	if !found {
		t.Fatal("this device was evicted from its own key set — it could not read its own messages")
	}
}

// What survives should be the machines still in use, not an arbitrary subset.
func TestPickDevicesKeepsMostRecentlySeen(t *testing.T) {
	ours, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := [][32]byte{ours.Public}
	seen := map[string]int64{EncodeKey(ours.Public): 1000}

	var stale, fresh [32]byte
	for i := 0; i < MaxDevices+5; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, kp.Public)
		switch i {
		case 0:
			stale = kp.Public
			seen[EncodeKey(kp.Public)] = 1 // ancient
		case 1:
			fresh = kp.Public
			seen[EncodeKey(kp.Public)] = 9999 // just now
		default:
			seen[EncodeKey(kp.Public)] = 500
		}
	}

	got := PickDevices(ours.Public, keys, seen)
	has := func(want [32]byte) bool {
		for _, k := range got {
			if k == want {
				return true
			}
		}
		return false
	}
	if !has(fresh) {
		t.Error("the most recently seen device was evicted")
	}
	if has(stale) {
		t.Error("the least recently seen device survived; eviction is not by recency")
	}
}

// Under the cap nothing is dropped, whatever the timestamps say.
func TestPickDevicesUnderCapKeepsEverything(t *testing.T) {
	ours, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := [][32]byte{ours.Public}
	for i := 0; i < 5; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, kp.Public)
	}
	if got := PickDevices(ours.Public, keys, nil); len(got) != 6 {
		t.Errorf("kept %d of 6 devices while under the cap", len(got))
	}
}
