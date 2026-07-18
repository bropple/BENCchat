package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestMarshalICBMMessageTextCanonicalBytes pins the exact wire bytes for a
// plain ASCII message, matching what open-oscar-server builds:
//
//	05 01 00 03 01 01 02            capabilities fragment
//	01 01 00 06 00 00 00 00 68 69   message fragment: len 6, charset 0, lang 0, "hi"
func TestMarshalICBMMessageTextCanonicalBytes(t *testing.T) {
	got, err := MarshalICBMMessageText("hi")
	if err != nil {
		t.Fatalf("MarshalICBMMessageText: %v", err)
	}
	want := []byte{
		0x05, 0x01, 0x00, 0x03, 0x01, 0x01, 0x02,
		0x01, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 'h', 'i',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("message body:\n got %x\nwant %x", got, want)
	}
}

func TestICBMMessageTextRoundTrip(t *testing.T) {
	for _, text := range []string{
		"hi",
		"",
		"hello, world",
		"a longer message with punctuation! -- and dashes?",
	} {
		b, err := MarshalICBMMessageText(text)
		if err != nil {
			t.Fatalf("marshal %q: %v", text, err)
		}
		got, err := UnmarshalICBMMessageText(b)
		if err != nil {
			t.Fatalf("unmarshal %q: %v", text, err)
		}
		if got != text {
			t.Errorf("round trip: got %q, want %q", got, text)
		}
	}
}

// TestICBMMessageTextUnicodeRoundTrip covers the non-ASCII path, which must
// switch to UCS-2 big-endian.
func TestICBMMessageTextUnicodeRoundTrip(t *testing.T) {
	const text = "héllo — naïve café"

	b, err := MarshalICBMMessageText(text)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify the charset field actually says Unicode rather than silently
	// shipping UTF-8 bytes labelled ASCII.
	var frag ICBMCh1Fragment
	r := bytes.NewReader(b)
	if err := UnmarshalBE(&frag, r); err != nil { // capabilities fragment
		t.Fatalf("decode caps fragment: %v", err)
	}
	if err := UnmarshalBE(&frag, r); err != nil { // message fragment
		t.Fatalf("decode message fragment: %v", err)
	}
	var msg ICBMCh1Message
	if err := UnmarshalBE(&msg, bytes.NewReader(frag.Payload)); err != nil {
		t.Fatalf("decode message: %v", err)
	}
	if msg.Charset != ICBMCharsetUnicode {
		t.Fatalf("charset = 0x%04x, want Unicode (0x0002)", msg.Charset)
	}

	got, err := UnmarshalICBMMessageText(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != text {
		t.Errorf("round trip: got %q, want %q", got, text)
	}
}

// TestICBMMessageTextASCIIStaysASCII guards against needlessly doubling the
// size of every ordinary message.
func TestICBMMessageTextASCIIStaysASCII(t *testing.T) {
	b, _ := MarshalICBMMessageText("plain")
	if !bytes.Contains(b, []byte("plain")) {
		t.Error("7-bit clean text should be sent as ASCII, not UCS-2")
	}
}

// TestDecodeLatin1 covers the charset the server explicitly does NOT transcode:
// each byte is its own code point, so passing the bytes through as a Go string
// would yield invalid UTF-8.
func TestDecodeLatin1(t *testing.T) {
	// 0xE9 is 'é' in Latin-1 but an invalid UTF-8 byte on its own.
	got, err := decodeICBMText(ICBMCharsetLatin1, []byte{'c', 'a', 'f', 0xE9})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != "café" {
		t.Fatalf("Latin-1 decode = %q, want %q", got, "café")
	}
}

// TestDecodeASCIIWithInvalidUTF8 ensures a malformed message is repaired rather
// than dropped.
func TestDecodeASCIIWithInvalidUTF8(t *testing.T) {
	got, err := decodeICBMText(ICBMCharsetASCII, []byte{'h', 'i', 0xFF})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(got, "hi") {
		t.Fatalf("decode = %q, want the valid prefix preserved", got)
	}
}

func TestDecodeUCS2RejectsOddLength(t *testing.T) {
	if _, err := decodeUTF16BE([]byte{0x00}); err == nil {
		t.Fatal("expected error for odd-length UCS-2 payload")
	}
}

func TestDecodeUCS2SkipsNulPadding(t *testing.T) {
	// Some clients pad with NUL code units; they are not real characters.
	got, err := decodeUTF16BE([]byte{0x00, 'h', 0x00, 'i', 0x00, 0x00})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != "hi" {
		t.Fatalf("decode = %q, want %q", got, "hi")
	}
}

// TestEncodeUTF16RoundTripsEmoji verifies astral-plane characters (emoji)
// survive via surrogate pairs — the whole point of using UTF-16 over UCS-2.
func TestEncodeUTF16RoundTripsEmoji(t *testing.T) {
	const msg = "a😀b 🎉"
	b, err := encodeUTF16BE(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Each astral char encodes as a surrogate pair (2 units), so the emoji don't
	// collapse to a single replacement unit the way strict UCS-2 forced.
	if len(b) != 14 {
		t.Fatalf("encoded length = %d, want 14 (2 astral chars → surrogate pairs)", len(b))
	}
	got, err := decodeUTF16BE(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != msg {
		t.Fatalf("round-trip = %q, want %q", got, msg)
	}
}

func TestUnmarshalICBMMessageTextWithoutFragment(t *testing.T) {
	// Only a capabilities fragment, no message fragment.
	body := []byte{0x05, 0x01, 0x00, 0x03, 0x01, 0x01, 0x02}
	if _, err := UnmarshalICBMMessageText(body); !errors.Is(err, ErrNoMessageFragment) {
		t.Fatalf("got %v, want ErrNoMessageFragment", err)
	}
}

// TestICBMChannelMsgToHostLayout pins the outbound message header layout.
func TestICBMChannelMsgToHostLayout(t *testing.T) {
	msg := SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     0x0102030405060708,
		ChannelID:  ICBMChannelIM,
		ScreenName: "triy",
	}
	msg.Append(NewTLVBE(ICBMTLVRequestHostAck, []byte{}))

	buf := &bytes.Buffer{}
	if err := MarshalBE(msg, buf); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // cookie (uint64)
		0x00, 0x01, // channel
		0x04, 't', 'r', 'i', 'y', // uint8-prefixed screen name
		0x00, 0x03, 0x00, 0x00, // TLV 0x03, empty value
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("ChannelMsgToHost:\n got %x\nwant %x", buf.Bytes(), want)
	}
}
