package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// transferParty is one device: a box keypair and a signing keypair, which is
// what a manifest entry amounts to.
type transferParty struct {
	box    KeyPair
	sign   SigningKeyPair
	signID string
}

func newTransferParty(t *testing.T) transferParty {
	t.Helper()
	box, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sign, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	return transferParty{box: box, sign: sign, signID: SignerID(sign.Public)}
}

// TestTransferRoundTrips: the whole point is that a new device ends up holding
// what the old one sent, byte for byte.
func TestTransferRoundTrips(t *testing.T) {
	old, fresh := newTransferParty(t), newTransferParty(t)
	payload := []byte("history and chain views, whatever shape the app layer gives them")

	sealed, err := SealTransfer("me", fresh.signID, fresh.box.Public, payload, old.box.Private, old.sign, 1_700_000_000)
	if err != nil {
		t.Fatalf("SealTransfer: %v", err)
	}
	body, err := EncodeTransfer(sealed)
	if err != nil {
		t.Fatalf("EncodeTransfer: %v", err)
	}
	if !IsTransfer(body) {
		t.Fatal("output not recognized as a transfer")
	}
	got, err := DecodeTransfer(body)
	if err != nil {
		t.Fatalf("DecodeTransfer: %v", err)
	}

	out, err := OpenTransfer(got, "me", fresh.signID,
		[]ed25519.PublicKey{old.sign.Public}, [][32]byte{old.box.Public}, fresh.box.Private)
	if err != nil {
		t.Fatalf("OpenTransfer: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("payload changed in transit:\n got %q\nwant %q", out, payload)
	}
}

// TestATransferOnlyOpensForItsRecipient. Sealing already makes it unreadable by
// anyone else; naming the recipient turns a misdirected bundle into a clear
// refusal instead of a decryption failure nobody can interpret.
func TestATransferOnlyOpensForItsRecipient(t *testing.T) {
	old, fresh, third := newTransferParty(t), newTransferParty(t), newTransferParty(t)

	sealed, _ := SealTransfer("me", fresh.signID, fresh.box.Public, []byte("mine"), old.box.Private, old.sign, 1)

	_, err := OpenTransfer(sealed, "me", third.signID,
		[]ed25519.PublicKey{old.sign.Public}, [][32]byte{old.box.Public}, third.box.Private)
	if !errors.Is(err, ErrTransferNotForUs) {
		t.Errorf("a bundle for another device gave %v, want ErrTransferNotForUs", err)
	}
	// And even lying about who we are does not open it, because the seal is the
	// real control and the name is only there for the error message.
	if _, err := OpenTransfer(sealed, "me", fresh.signID,
		[]ed25519.PublicKey{old.sign.Public}, [][32]byte{old.box.Public}, third.box.Private); err == nil {
		t.Error("a third device opened a bundle by claiming the recipient's ID")
	}
}

// TestATransferMustComeFromTheAccount: the sender's signing key has to be one
// the account's manifest publishes. Anything else is a stranger offering to
// furnish our device with history we would then believe.
func TestATransferMustComeFromTheAccount(t *testing.T) {
	old, fresh, stranger := newTransferParty(t), newTransferParty(t), newTransferParty(t)

	forged, _ := SealTransfer("me", fresh.signID, fresh.box.Public, []byte("planted"), stranger.box.Private, stranger.sign, 1)

	// Verified against the account's real device keys, which do not include the
	// stranger's.
	_, err := OpenTransfer(forged, "me", fresh.signID,
		[]ed25519.PublicKey{old.sign.Public}, [][32]byte{old.box.Public}, fresh.box.Private)
	if !errors.Is(err, ErrTransferSignature) {
		t.Errorf("a stranger's bundle gave %v, want ErrTransferSignature", err)
	}

	// An EMPTY key set is "we have not verified the manifest yet", which is not
	// the same as a bad signature — and must not be mistaken for a good one.
	real, _ := SealTransfer("me", fresh.signID, fresh.box.Public, []byte("real"), old.box.Private, old.sign, 1)
	if _, err := OpenTransfer(real, "me", fresh.signID, nil, [][32]byte{old.box.Public}, fresh.box.Private); err == nil {
		t.Error("a bundle was accepted with no keys to check it against")
	}
}

// TestATransferIsBoundToItsAccount: without this a bundle captured from one
// account could be replayed into another's client, which is a way to write
// somebody else's history into your conversations.
func TestATransferIsBoundToItsAccount(t *testing.T) {
	old, fresh := newTransferParty(t), newTransferParty(t)
	sealed, _ := SealTransfer("alice", fresh.signID, fresh.box.Public, []byte("alice's life"), old.box.Private, old.sign, 1)

	if _, err := OpenTransfer(sealed, "bob", fresh.signID,
		[]ed25519.PublicKey{old.sign.Public}, [][32]byte{old.box.Public}, fresh.box.Private); err == nil {
		t.Error("a bundle for one account opened in another's client")
	}
}

// TestTheTransferSignatureCoversEverything: anything a recipient acts on must be
// signed, or an attacker edits the part that is not.
func TestTheTransferSignatureCoversEverything(t *testing.T) {
	old, fresh := newTransferParty(t), newTransferParty(t)
	base, _ := SealTransfer("me", fresh.signID, fresh.box.Public, []byte("payload"), old.box.Private, old.sign, 99)

	tamper := map[string]func(Transfer) Transfer{
		"account":   func(x Transfer) Transfer { x.Account = "someone-else"; return x },
		"recipient": func(x Transfer) Transfer { x.Recipient = "another-device"; return x },
		"payload":   func(x Transfer) Transfer { x.Payload = append([]byte{}, "swapped"...); return x },
		"timestamp": func(x Transfer) Transfer { x.IssuedAt = 1; return x },
	}
	for name, edit := range tamper {
		got := edit(base)
		ctx := transferSigningContext(got)
		if ed25519.Verify(old.sign.Public, ctx, got.Signature) {
			t.Errorf("editing the %s left the signature valid", name)
		}
	}
}

// TestTransferFieldsAreUnambiguous: several variable-length fields in a row, so
// one field's content must not be readable as another's boundary.
func TestTransferFieldsAreUnambiguous(t *testing.T) {
	a := transferSigningContext(Transfer{Account: "a\x00b", Recipient: "c", Payload: []byte("p")})
	b := transferSigningContext(Transfer{Account: "a", Recipient: "b\x00c", Payload: []byte("p")})
	if bytes.Equal(a, b) {
		t.Error("a NUL shifted a field boundary; length prefixes are missing")
	}
}

// TestTransferIsNotAnotherSignature: the device signing key also signs room
// messages, rosters and attestations. None may spell another.
func TestTransferIsNotAnotherSignature(t *testing.T) {
	p := newTransferParty(t)
	ctx := transferSigningContext(Transfer{Account: "me", Recipient: "dev", Payload: []byte("x")})
	if !strings.HasPrefix(string(ctx), transferDomain) {
		t.Fatal("the transfer context does not begin with its domain tag")
	}

	nonce := []byte("a-32-byte-nonce-for-attestation!")
	if VerifyAttestation("me", nonce, p.sign.Public, ed25519.Sign(p.sign.Private, ctx)) {
		t.Error("a transfer signature verified as a device attestation")
	}
	// And a roster signature must not pass as a transfer.
	r, _ := SignRoster(Roster{Room: "r", Members: []string{"me"}, Owner: "me", Author: "me"}, p.sign)
	if ed25519.Verify(p.sign.Public, ctx, r.Signature) {
		t.Error("a roster signature verified as a transfer")
	}
}

// TestTransferRefusesJunk: everything here arrives from outside — a file the
// user picked, or a socket.
func TestTransferRefusesJunk(t *testing.T) {
	for name, body := range map[string]string{
		"not a transfer": "hello",
		"bad base64":     TransferPrefix + "!!!not-base64",
		"truncated":      TransferPrefix + "AAAA",
		"empty":          TransferPrefix,
	} {
		if _, err := DecodeTransfer(body); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	p := newTransferParty(t)
	if _, err := SealTransfer("", p.signID, p.box.Public, nil, p.box.Private, p.sign, 1); err == nil {
		t.Error("a transfer with no account was sealed")
	}
	if _, err := SealTransfer("me", "", p.box.Public, nil, p.box.Private, p.sign, 1); err == nil {
		t.Error("a transfer naming no recipient was sealed")
	}
}
