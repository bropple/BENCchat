// Package wire implements the OSCAR wire format: FLAP framing, SNAC headers,
// TLVs, and a reflection-based (un)marshaler driven by `oscar:"..."` struct
// tags.
//
// The codec here is a focused port of open-oscar-server's wire package (MIT,
// mk6i). That server is the exact dialect BENCchat speaks, so matching its
// encoding byte-for-byte is the whole point — CLAUDE.md names its Go source as
// the source of truth. The ICQ/Kerberos decode "quirks" the server carries are
// intentionally omitted; BENCchat is an AIM/BUCP client and does not need them.
//
// Supported struct tags:
//
//	oscar:"len_prefix=uint8|uint16"    // length-prefixed slice/string/struct
//	oscar:"count_prefix=uint8|uint16"  // element-count-prefixed slice
//	oscar:"optional"                   // final pointer-to-struct field, may be absent
//	oscar:"nullterm"                   // null-terminated string
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var (
	ErrMarshalFailure     = errors.New("failed to marshal")
	ErrUnmarshalFailure   = errors.New("failed to unmarshal")
	errNonOptionalPointer = errors.New("pointer fields must reference structs and have an `optional` struct tag")
	errOptionalNonPointer = errors.New("optional fields must be pointers")
	errInvalidStructTag   = errors.New("invalid struct tag")
)

// MarshalBE marshals an OSCAR message in big-endian order (the default for
// AIM/BUCP). Little-endian (MarshalLE) exists only for ICQ payloads.
func MarshalBE(v any, w io.Writer) error {
	if err := marshal(reflect.TypeOf(v), reflect.ValueOf(v), "", w, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrMarshalFailure, err)
	}
	return nil
}

// MarshalLE marshals an OSCAR message in little-endian order (ICQ).
func MarshalLE(v any, w io.Writer) error {
	if err := marshal(reflect.TypeOf(v), reflect.ValueOf(v), "", w, binary.LittleEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrMarshalFailure, err)
	}
	return nil
}

func marshal(t reflect.Type, v reflect.Value, tag reflect.StructTag, w io.Writer, order binary.ByteOrder) error {
	if t == nil {
		return errors.New("attempting to marshal a nil value")
	}

	oscTag, err := parseOSCARTag(tag)
	if err != nil {
		return err
	}

	if oscTag.optional {
		if t.Kind() != reflect.Pointer {
			return fmt.Errorf("%w: got %v", errOptionalNonPointer, t.Kind())
		}
		if v.IsNil() {
			return nil
		}
		return marshalStruct(t.Elem(), v.Elem(), oscTag, w, order)
	} else if t.Kind() == reflect.Pointer {
		return errNonOptionalPointer
	}

	switch t.Kind() {
	case reflect.Array:
		return marshalArray(t, v, w, order)
	case reflect.Slice:
		return marshalSlice(t, v, oscTag, w, order)
	case reflect.String:
		return marshalString(oscTag, v, w, order)
	case reflect.Struct:
		return marshalStruct(t, v, oscTag, w, order)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return binary.Write(w, order, v.Interface())
	case reflect.Interface:
		return marshalInterface(v, w, oscTag, order)
	default:
		return fmt.Errorf("unsupported type %v", t.Kind())
	}
}

func marshalInterface(v reflect.Value, w io.Writer, tag oscarTag, order binary.ByteOrder) error {
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("interface underlying type must be a struct, got %v", elem.Kind())
	}
	return marshalStruct(elem.Type(), elem, tag, w, order)
}

func marshalArray(t reflect.Type, v reflect.Value, w io.Writer, order binary.ByteOrder) error {
	if t.Elem().Kind() == reflect.Struct {
		for j := 0; j < v.Len(); j++ {
			if err := marshalStruct(t.Elem(), v.Index(j), oscarTag{}, w, order); err != nil {
				return fmt.Errorf("marshalling %s: %w", t.Elem().Kind(), err)
			}
		}
		return nil
	}
	return binary.Write(w, order, v.Interface())
}

func marshalSlice(t reflect.Type, v reflect.Value, oscTag oscarTag, w io.Writer, order binary.ByteOrder) error {
	buf := &bytes.Buffer{}
	if t.Elem().Kind() == reflect.Struct {
		for j := 0; j < v.Len(); j++ {
			if err := marshalStruct(t.Elem(), v.Index(j), oscarTag{}, buf, order); err != nil {
				return err
			}
		}
	} else {
		if err := binary.Write(buf, order, v.Interface()); err != nil {
			return fmt.Errorf("marshalling %s", t.Elem().Kind())
		}
	}

	if oscTag.hasLenPrefix {
		if err := marshalUnsignedInt(oscTag.lenPrefix, buf.Len(), w, order); err != nil {
			return err
		}
	} else if oscTag.hasCountPrefix {
		if err := marshalUnsignedInt(oscTag.countPrefix, v.Len(), w, order); err != nil {
			return err
		}
	}
	if buf.Len() > 0 {
		_, err := w.Write(buf.Bytes())
		return err
	}
	return nil
}

func marshalString(oscTag oscarTag, v reflect.Value, w io.Writer, order binary.ByteOrder) error {
	str := v.String()
	if oscTag.nullTerminated && str != "" {
		str += "\x00"
	}
	if oscTag.hasLenPrefix {
		if err := marshalUnsignedInt(oscTag.lenPrefix, len(str), w, order); err != nil {
			return err
		}
	}
	if str == "" {
		return nil
	}
	return binary.Write(w, order, []byte(str))
}

func marshalStruct(t reflect.Type, v reflect.Value, oscTag oscarTag, w io.Writer, order binary.ByteOrder) error {
	marshalEachField := func(w io.Writer) error {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			value := v.Field(i)
			if field.Type.Kind() == reflect.Pointer {
				if i != t.NumField()-1 {
					return fmt.Errorf("pointer type found at non-final field %s", field.Name)
				}
				if field.Type.Elem().Kind() != reflect.Struct {
					return fmt.Errorf("field %s must point to a struct, got %v", field.Name, field.Type.Elem().Kind())
				}
			}
			if err := marshal(field.Type, value, field.Tag, w, order); err != nil {
				return err
			}
		}
		return nil
	}
	if oscTag.hasLenPrefix {
		buf := &bytes.Buffer{}
		if err := marshalEachField(buf); err != nil {
			return err
		}
		if err := marshalUnsignedInt(oscTag.lenPrefix, buf.Len(), w, order); err != nil {
			return err
		}
		if buf.Len() > 0 {
			_, err := w.Write(buf.Bytes())
			return err
		}
		return nil
	}
	return marshalEachField(w)
}

func marshalUnsignedInt(intType reflect.Kind, intVal int, w io.Writer, order binary.ByteOrder) error {
	switch intType {
	case reflect.Uint8:
		return binary.Write(w, order, uint8(intVal))
	case reflect.Uint16:
		return binary.Write(w, order, uint16(intVal))
	default:
		return fmt.Errorf("unsupported prefix type %s (allowed: uint8, uint16)", intType)
	}
}

// UnmarshalBE decodes an OSCAR message from big-endian bytes into v (a pointer).
func UnmarshalBE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

// UnmarshalLE decodes an OSCAR message from little-endian bytes into v (ICQ).
func UnmarshalLE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.LittleEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

func unmarshal(t reflect.Type, v reflect.Value, tag reflect.StructTag, r io.Reader, order binary.ByteOrder) error {
	oscTag, err := parseOSCARTag(tag)
	if err != nil {
		return fmt.Errorf("parsing tag: %w", err)
	}

	if oscTag.optional {
		v.Set(reflect.New(t.Elem()))
		err := unmarshalStruct(t.Elem(), v.Elem(), oscTag, r, order)
		if errors.Is(err, io.EOF) {
			// An optional final field with nothing left to read is legal.
			v.Set(reflect.Zero(t))
			err = nil
		}
		return err
	} else if v.Kind() == reflect.Pointer {
		return errNonOptionalPointer
	}

	switch v.Kind() {
	case reflect.Array:
		return unmarshalArray(v, r, order)
	case reflect.Slice:
		return unmarshalSlice(v, oscTag, r, order)
	case reflect.String:
		return unmarshalString(v, oscTag, r, order)
	case reflect.Struct:
		return unmarshalStruct(t, v, oscTag, r, order)
	case reflect.Uint8:
		var l uint8
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint16:
		var l uint16
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint32:
		var l uint32
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint64:
		var l uint64
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	default:
		return fmt.Errorf("unsupported type %v", t.Kind())
	}
}

func unmarshalArray(v reflect.Value, r io.Reader, order binary.ByteOrder) error {
	arrType := v.Type().Elem()
	for i := 0; i < v.Len(); i++ {
		elem := reflect.New(arrType).Elem()
		if err := unmarshal(arrType, elem, "", r, order); err != nil {
			return err
		}
		v.Index(i).Set(elem)
	}
	return nil
}

func unmarshalSlice(v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
	slice := reflect.New(v.Type()).Elem()
	elemType := v.Type().Elem()

	switch {
	case oscTag.hasLenPrefix:
		bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
		if err != nil {
			return err
		}
		b := make([]byte, bufLen)
		if bufLen > 0 {
			if _, err := io.ReadFull(r, b); err != nil {
				return err
			}
		}
		buf := bytes.NewBuffer(b)
		for buf.Len() > 0 {
			elem := reflect.New(elemType).Elem()
			if err := unmarshal(elemType, elem, "", buf, order); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	case oscTag.hasCountPrefix:
		count, err := unmarshalUnsignedInt(oscTag.countPrefix, r, order)
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			elem := reflect.New(elemType).Elem()
			if err := unmarshal(elemType, elem, "", r, order); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	default:
		// No prefix: consume until EOF.
		for {
			elem := reflect.New(elemType).Elem()
			if err := unmarshal(elemType, elem, "", r, order); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	}
	v.Set(slice)
	return nil
}

func unmarshalString(v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
	if !oscTag.hasLenPrefix {
		return fmt.Errorf("string field missing len_prefix tag")
	}
	bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
	if err != nil {
		return err
	}
	buf := make([]byte, bufLen)
	if bufLen > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if oscTag.nullTerminated {
			if nullPos := bytes.IndexByte(buf, 0x00); nullPos != -1 {
				buf = buf[0:nullPos]
			}
		}
	}
	v.SetString(string(buf))
	return nil
}

func unmarshalStruct(t reflect.Type, v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
	if oscTag.hasLenPrefix {
		bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
		if err != nil {
			return err
		}
		b := make([]byte, bufLen)
		if bufLen > 0 {
			if _, err := io.ReadFull(r, b); err != nil {
				return err
			}
		}
		r = bytes.NewBuffer(b)
	}
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		if field.Type.Kind() == reflect.Pointer {
			if i != v.NumField()-1 {
				return fmt.Errorf("pointer type found at non-final field %s", field.Name)
			}
			if field.Type.Elem().Kind() != reflect.Struct {
				return fmt.Errorf("%w: field %s must point to a struct, got %v", errNonOptionalPointer, field.Name, field.Type.Elem().Kind())
			}
		}
		if err := unmarshal(field.Type, value, field.Tag, r, order); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalUnsignedInt(intType reflect.Kind, r io.Reader, order binary.ByteOrder) (int, error) {
	switch intType {
	case reflect.Uint8:
		var l uint8
		if err := binary.Read(r, order, &l); err != nil {
			return 0, err
		}
		return int(l), nil
	case reflect.Uint16:
		var l uint16
		if err := binary.Read(r, order, &l); err != nil {
			return 0, err
		}
		return int(l), nil
	default:
		return 0, fmt.Errorf("unsupported prefix type %s (allowed: uint8, uint16)", intType)
	}
}

type oscarTag struct {
	hasCountPrefix bool
	countPrefix    reflect.Kind
	hasLenPrefix   bool
	lenPrefix      reflect.Kind
	optional       bool
	nullTerminated bool
}

func parseOSCARTag(tag reflect.StructTag) (oscarTag, error) {
	var oscTag oscarTag

	val, ok := tag.Lookup("oscar")
	if !ok {
		return oscTag, nil
	}

	for _, kv := range strings.Split(val, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		key := strings.TrimSpace(parts[0])
		if len(parts) == 2 {
			valPart := strings.TrimSpace(parts[1])
			kind, err := prefixKind(valPart)
			if err != nil {
				return oscTag, err
			}
			switch key {
			case "len_prefix":
				oscTag.hasLenPrefix = true
				oscTag.lenPrefix = kind
			case "count_prefix":
				oscTag.hasCountPrefix = true
				oscTag.countPrefix = kind
			default:
				return oscTag, fmt.Errorf("%w: unsupported struct tag %s", errInvalidStructTag, key)
			}
		} else {
			switch key {
			case "optional":
				oscTag.optional = true
			case "nullterm":
				oscTag.nullTerminated = true
			default:
				return oscTag, fmt.Errorf("%w: unsupported struct tag %s", errInvalidStructTag, key)
			}
		}
	}

	if oscTag.hasCountPrefix && oscTag.hasLenPrefix {
		return oscTag, fmt.Errorf("%w: field has both len_prefix and count_prefix", errInvalidStructTag)
	}
	return oscTag, nil
}

func prefixKind(valPart string) (reflect.Kind, error) {
	switch valPart {
	case "uint8":
		return reflect.Uint8, nil
	case "uint16":
		return reflect.Uint16, nil
	default:
		return reflect.Invalid, fmt.Errorf("%w: unsupported prefix type %s (allowed: uint8, uint16)", errInvalidStructTag, valPart)
	}
}
