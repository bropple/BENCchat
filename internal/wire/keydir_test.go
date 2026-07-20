package wire

import (
	"bytes"
	"reflect"
	"testing"
)

// Round-trip coverage for the key directory v2 payloads.
//
// These are the tests that catch the failure OSCAR is worst at reporting: a
// length prefix that is one byte off produces a confusing disconnect rather
// than an error, and it does so on a live server, hours away from the change
// that caused it.

// roundTrip marshals a value, unmarshals it into a fresh one of the same type,
// and returns the encoding plus the result.
func roundTrip[T any](t *testing.T, in T) (T, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := MarshalBE(in, &buf); err != nil {
		t.Fatalf("marshal %T: %v", in, err)
	}
	var out T
	if err := UnmarshalBE(&out, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("unmarshal %T: %v", in, err)
	}
	return out, buf.Bytes()
}

func testKey(alg uint8, b byte, n int) BENCOKey {
	k := make([]byte, n)
	for i := range k {
		k[i] = b
	}
	return BENCOKey{Alg: alg, Key: k}
}

func TestBENCOKeyRoundTrip(t *testing.T) {
	in := testKey(BENCOAlgX25519, 0x11, BENCOX25519KeyLen)
	out, enc := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the key: %+v -> %+v", in, out)
	}
	// One algorithm byte, a uint16 length, then the key itself. Pinned because
	// the whole point of the length prefix is to carry a key of another size
	// later, and a silent change of prefix width would break that quietly.
	if want := 1 + 2 + BENCOX25519KeyLen; len(enc) != want {
		t.Errorf("encoded key is %d bytes, want %d: %x", len(enc), want, enc)
	}
}

// A reserved algorithm must survive encoding even though nothing implements it.
// The server refuses such a request, and that refusal is only reachable if the
// value gets there intact.
func TestBENCOKeyCarriesReservedAlgorithms(t *testing.T) {
	in := testKey(BENCOAlgMLDSA65, 0x44, 100)
	out, _ := roundTrip(t, in)
	if out.Alg != BENCOAlgMLDSA65 || len(out.Key) != 100 {
		t.Fatalf("reserved algorithm did not survive: %+v", out)
	}
}

func TestBENCODeviceV2RoundTrip(t *testing.T) {
	in := BENCODeviceV2{
		Box:   testKey(BENCOAlgX25519, 0x22, BENCOX25519KeyLen),
		Sign:  testKey(BENCOAlgEd25519, 0x33, BENCOEd25519KeyLen),
		Label: "thinkpad",
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the device: %+v -> %+v", in, out)
	}
}

// An empty label is the DEFAULT, not an edge case: it is metadata the server can
// read, so clients ship it blank unless the user opts in. It has to encode.
func TestBENCODeviceV2EmptyLabel(t *testing.T) {
	in := BENCODeviceV2{
		Box:  testKey(BENCOAlgX25519, 0x22, BENCOX25519KeyLen),
		Sign: testKey(BENCOAlgEd25519, 0x33, BENCOEd25519KeyLen),
	}
	out, _ := roundTrip(t, in)
	if out.Label != "" {
		t.Fatalf("empty label came back as %q", out.Label)
	}
	if !bytes.Equal(out.Box.Key, in.Box.Key) || !bytes.Equal(out.Sign.Key, in.Sign.Key) {
		t.Fatal("an empty label disturbed the surrounding fields")
	}
}

func testManifest() BENCOManifest {
	return BENCOManifest{
		Version:    BENCOKeyDirVersion,
		ScreenName: "alice",
		Counter:    7,
		IssuedAt:   1_700_000_000,
		Identity:   testKey(BENCOAlgEd25519, 0x99, BENCOEd25519KeyLen),
		Devices: []BENCODeviceV2{
			{
				Box:   testKey(BENCOAlgX25519, 0x01, BENCOX25519KeyLen),
				Sign:  testKey(BENCOAlgEd25519, 0x02, BENCOEd25519KeyLen),
				Label: "desktop",
			},
			{
				Box:  testKey(BENCOAlgX25519, 0x03, BENCOX25519KeyLen),
				Sign: testKey(BENCOAlgEd25519, 0x04, BENCOEd25519KeyLen),
			},
		},
	}
}

func TestBENCOManifestRoundTrip(t *testing.T) {
	in := testManifest()
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the manifest:\n got %+v\nwant %+v", out, in)
	}
}

// A manifest with no devices is a legitimate statement — it is what removing the
// last device looks like — and must not be confused with a truncated one.
func TestBENCOManifestNoDevices(t *testing.T) {
	in := testManifest()
	in.Devices = nil
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("an empty device set did not round trip: %+v", out)
	}
}

// The signature covers the ENCODED manifest, so encoding has to be
// deterministic. If it were not, a client that encoded once to sign and again to
// send would produce a signature over bytes nobody ever receives, and the bug
// would present as a verification failure rather than an encoding one.
func TestEncodeManifestIsDeterministic(t *testing.T) {
	m := testManifest()
	first, err := EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("two encodings of one manifest differ:\n%x\n%x", first, second)
	}
}

// Decoding then re-encoding must also reproduce the original bytes. Nothing in
// the client is allowed to rely on this — a received manifest is verified as
// received — but if it ever stopped holding, that would mean the encoder and
// decoder disagree about the format, which is worth catching here.
func TestManifestDecodeEncodeIsStable(t *testing.T) {
	want, err := EncodeManifest(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifest(want)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := EncodeManifest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("re-encoding a decoded manifest changed it:\n%x\n%x", want, got)
	}
}

func TestDecodeManifestRejectsTruncation(t *testing.T) {
	enc, err := EncodeManifest(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(enc[:len(enc)-5]); err == nil {
		t.Fatal("a truncated manifest decoded without error")
	}
}

func TestPublishRequestRoundTrip(t *testing.T) {
	manifest, err := EncodeManifest(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, BENCOEd25519SigLen)
	for i := range sig {
		sig[i] = byte(i)
	}
	in := SNAC_0xBE00_0x0002_BENCOKeyDirPublishRequest{
		Version:   BENCOKeyDirVersion,
		Manifest:  manifest,
		SigAlg:    BENCOAlgEd25519,
		Signature: sig,
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatal("publish request did not round trip")
	}
	// The bytes the server stores must be the bytes that were signed.
	if !bytes.Equal(out.Manifest, manifest) {
		t.Fatal("the manifest was altered in transit; every signature over it is now void")
	}
}

func TestPublishReplyRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0003_BENCOKeyDirPublishReply{Accepted: 1, Counter: 42}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("publish reply did not round trip: %+v", out)
	}
}

func TestQueryRequestRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0004_BENCOKeyDirQueryRequest{
		Version:    BENCOKeyDirVersion,
		ScreenName: "bob",
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("query request did not round trip: %+v", out)
	}
}

func TestQueryReplyRoundTrip(t *testing.T) {
	manifest, err := EncodeManifest(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	in := SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{
		ScreenName: "alice",
		Present:    1,
		Manifest:   manifest,
		SigAlg:     BENCOAlgEd25519,
		Signature:  bytes.Repeat([]byte{0xAB}, BENCOEd25519SigLen),
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatal("query reply did not round trip")
	}
}

// "Nothing published" is a normal answer, and its encoding is the one most
// likely to be got wrong, because every variable-length field is empty at once.
func TestQueryReplyAbsentManifest(t *testing.T) {
	in := SNAC_0xBE00_0x0005_BENCOKeyDirQueryReply{ScreenName: "nobody"}
	out, _ := roundTrip(t, in)
	if out.ScreenName != "nobody" || out.Present != 0 {
		t.Fatalf("absent reply did not round trip: %+v", out)
	}
	if len(out.Manifest) != 0 || len(out.Signature) != 0 {
		t.Fatalf("empty fields came back non-empty: %+v", out)
	}
}

func TestPutBackupRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0006_BENCOKeyDirPutBackupRequest{
		Version: BENCOKeyDirVersion,
		KDF:     BENCOKDFArgon2id,
		Params:  []byte{0, 3, 0, 0, 0x40, 0, 4},
		Salt:    bytes.Repeat([]byte{0x5A}, 16),
		Blob:    bytes.Repeat([]byte{0x7E}, 72),
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("put backup request did not round trip: %+v", out)
	}
}

func TestPutBackupReplyRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0007_BENCOKeyDirPutBackupReply{Stored: 1}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("put backup reply did not round trip: %+v", out)
	}
}

func TestGetBackupRequestRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0008_BENCOKeyDirGetBackupRequest{Version: BENCOKeyDirVersion}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("get backup request did not round trip: %+v", out)
	}
}

func TestGetBackupReplyRoundTrip(t *testing.T) {
	in := SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{
		Present: 1,
		KDF:     BENCOKDFArgon2id,
		Params:  []byte{0, 3, 0, 0, 0x40, 0, 4},
		Salt:    bytes.Repeat([]byte{0x5A}, 16),
		Blob:    bytes.Repeat([]byte{0x7E}, 72),
	}
	out, _ := roundTrip(t, in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("get backup reply did not round trip: %+v", out)
	}
}

// An account with no stored identity: Present = 0 and three empty fields, which
// is what a first run reads to decide it must bootstrap.
func TestGetBackupReplyAbsent(t *testing.T) {
	in := SNAC_0xBE00_0x0009_BENCOKeyDirGetBackupReply{}
	out, _ := roundTrip(t, in)
	if out.Present != 0 || len(out.Blob) != 0 || len(out.Salt) != 0 || len(out.Params) != 0 {
		t.Fatalf("absent backup did not round trip: %+v", out)
	}
}

// The subgroup numbers are pinned against BENCoscar rather than against the
// proposal document, which assigned the backup pairs 0x000A–0x000D on the
// assumption v1 would keep 0x0006–0x0009. v1 was deleted and the server reused
// them. Getting this wrong routes a backup request at the old revoke handler.
func TestSubgroupNumbersMatchTheServer(t *testing.T) {
	for name, got := range map[string]uint16{
		"Err":              BENCOKeyDirErr,
		"PublishRequest":   BENCOKeyDirPublishRequest,
		"PublishReply":     BENCOKeyDirPublishReply,
		"QueryRequest":     BENCOKeyDirQueryRequest,
		"QueryReply":       BENCOKeyDirQueryReply,
		"PutBackupRequest": BENCOKeyDirPutBackupRequest,
		"PutBackupReply":   BENCOKeyDirPutBackupReply,
		"GetBackupRequest": BENCOKeyDirGetBackupRequest,
		"GetBackupReply":   BENCOKeyDirGetBackupReply,
	} {
		want := map[string]uint16{
			"Err": 0x0001, "PublishRequest": 0x0002, "PublishReply": 0x0003,
			"QueryRequest": 0x0004, "QueryReply": 0x0005,
			"PutBackupRequest": 0x0006, "PutBackupReply": 0x0007,
			"GetBackupRequest": 0x0008, "GetBackupReply": 0x0009,
		}[name]
		if got != want {
			t.Errorf("%s is 0x%04x, want 0x%04x", name, got, want)
		}
	}
	if BENCOKeyDir != 0xBE00 {
		t.Errorf("foodgroup is 0x%04x, want 0xBE00", BENCOKeyDir)
	}
	if BENCOKeyDirVersion != 2 {
		t.Errorf("payload version is %d, want 2", BENCOKeyDirVersion)
	}
}
