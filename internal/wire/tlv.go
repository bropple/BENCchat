package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TLV (type-length-value) is OSCAR's dynamically-typed field. Most SNAC bodies
// are built out of these. The value is length-prefixed with a uint16.
type TLV struct {
	Tag   uint16
	Value []byte `oscar:"len_prefix=uint16"`
}

// NewTLVBE builds a TLV whose value is val marshalled big-endian. A []byte val
// is stored verbatim; anything else is run through MarshalBE.
func NewTLVBE(tag uint16, val any) TLV {
	return newTLV(tag, val, binary.BigEndian)
}

// NewTLVLE builds a TLV whose value is val marshalled little-endian (ICQ).
func NewTLVLE(tag uint16, val any) TLV {
	return newTLV(tag, val, binary.LittleEndian)
}

func newTLV(tag uint16, val any, order binary.ByteOrder) TLV {
	t := TLV{Tag: tag}
	if b, ok := val.([]byte); ok {
		t.Value = b
		return t
	}
	buf := &bytes.Buffer{}
	var err error
	if order == binary.LittleEndian {
		err = MarshalLE(val, buf)
	} else {
		err = MarshalBE(val, buf)
	}
	if err != nil {
		// Callers pass statically-known types; a failure here is a programming
		// error, not a runtime condition, so panicking is appropriate.
		panic(fmt.Sprintf("wire: unable to build TLV tag 0x%04x: %s", tag, err))
	}
	t.Value = buf.Bytes()
	return t
}

// Uint8 interprets the value as a single byte.
func (t TLV) Uint8() uint8 {
	if len(t.Value) > 0 {
		return t.Value[0]
	}
	return 0
}

// Uint16BE interprets the value as a big-endian uint16.
func (t TLV) Uint16BE() uint16 { return binary.BigEndian.Uint16(t.Value) }

// Uint32BE interprets the value as a big-endian uint32.
func (t TLV) Uint32BE() uint32 { return binary.BigEndian.Uint32(t.Value) }

// TLVList is an ordered list of TLVs with typed accessors keyed by tag.
type TLVList []TLV

func (s *TLVList) Append(tlv TLV)        { *s = append(*s, tlv) }
func (s *TLVList) AppendList(tlvs []TLV) { *s = append(*s, tlvs...) }

// Remove deletes every TLV carrying tag.
func (s *TLVList) Remove(tag uint16) {
	out := (*s)[:0]
	for _, tlv := range *s {
		if tlv.Tag != tag {
			out = append(out, tlv)
		}
	}
	*s = out
}

// Set replaces any existing TLV(s) carrying tlv.Tag with tlv. The replaced tag
// moves to the end of the list.
func (s *TLVList) Set(tlv TLV) {
	s.Remove(tlv.Tag)
	*s = append(*s, tlv)
}

// HasTag reports whether any TLV in the list carries tag.
func (s *TLVList) HasTag(tag uint16) bool {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			return true
		}
	}
	return false
}

// Bytes returns the raw value for the first TLV with tag.
func (s *TLVList) Bytes(tag uint16) ([]byte, bool) {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			return tlv.Value, true
		}
	}
	return nil, false
}

// String returns the value for tag interpreted as a string.
func (s *TLVList) String(tag uint16) (string, bool) {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// Uint8 returns the value for tag as a single byte.
func (s *TLVList) Uint8(tag uint16) (uint8, bool) {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			if len(tlv.Value) == 0 {
				return 0, false
			}
			return tlv.Value[0], true
		}
	}
	return 0, false
}

// Uint16BE returns the value for tag as a big-endian uint16.
func (s *TLVList) Uint16BE(tag uint16) (uint16, bool) {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			return tlv.Uint16BE(), true
		}
	}
	return 0, false
}

// Uint32BE returns the value for tag as a big-endian uint32.
func (s *TLVList) Uint32BE(tag uint16) (uint32, bool) {
	for _, tlv := range *s {
		if tlv.Tag == tag {
			return tlv.Uint32BE(), true
		}
	}
	return 0, false
}

// Uint16SliceBE returns the value for tag decoded as a packed array of
// big-endian uint16s. This is how the feedbag encodes ordering lists (TLV
// 0x00C8): a group's child item IDs, or the root's group IDs.
//
// A trailing odd byte means the value is not a uint16 array, so the whole
// lookup reports not-found rather than silently returning a truncated list.
func (s *TLVList) Uint16SliceBE(tag uint16) ([]uint16, bool) {
	b, ok := s.Bytes(tag)
	if !ok || len(b)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:i+2]))
	}
	return out, true
}

// TLVRestBlock is a bare TLV list occupying the remainder of a payload — no
// count or length header precedes it.
type TLVRestBlock struct {
	TLVList
}

// TLVBlock is a TLV list prefixed with a uint16 element count.
type TLVBlock struct {
	TLVList `oscar:"count_prefix=uint16"`
}

// TLVLBlock is a TLV list prefixed with a uint16 byte-length.
type TLVLBlock struct {
	TLVList `oscar:"len_prefix=uint16"`
}
