package permissions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal, strict CBOR decoder (RFC 8949) for the little WebAuthn needs:
// the attestation object, the credential's COSE key and authenticator
// extensions. It runs in a root helper, so it is deliberately small instead
// of a general library: definite lengths only (CTAP2's canonical CBOR has no
// indefinite ones), no tags, no floats, bounded depth and sizes, duplicate
// map keys refused. Integers decode to int64, byte strings to []byte, text
// to string, arrays to []any and maps to map[any]any (keys int64 or string).

const cborMaxDepth = 8

var errCBOR = errors.New("malformed CBOR")

// cborDecodeFirst decodes the first CBOR item in b and returns it with the
// number of bytes it took.
func cborDecodeFirst(b []byte) (any, int, error) {
	d := cborDecoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// cborDecode decodes exactly one CBOR item filling b.
func cborDecode(b []byte) (any, error) {
	v, n, err := cborDecodeFirst(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errCBOR, len(b)-n)
	}
	return v, nil
}

type cborDecoder struct {
	b   []byte
	pos int
}

func (d *cborDecoder) remaining() int { return len(d.b) - d.pos }

// head reads an item's initial byte and argument.
func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if d.remaining() < 1 {
		return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	ib := d.b[d.pos]
	d.pos++
	major, ai := ib>>5, ib&0x1f
	var n int
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	default: // 28-30 reserved, 31 indefinite length
		return 0, 0, fmt.Errorf("%w: unsupported additional information %d", errCBOR, ai)
	}
	if d.remaining() < n {
		return 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	var buf [8]byte
	copy(buf[8-n:], d.b[d.pos:d.pos+n])
	d.pos += n
	return major, binary.BigEndian.Uint64(buf[:]), nil
}

func (d *cborDecoder) bytes(n uint64) ([]byte, error) {
	if n > uint64(d.remaining()) {
		return nil, fmt.Errorf("%w: truncated", errCBOR)
	}
	out := d.b[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

func (d *cborDecoder) value(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	if d.remaining() > 0 && d.b[d.pos]>>5 == 7 {
		// Only false, true and null, in their one-byte forms.
		ib := d.b[d.pos]
		d.pos++
		switch ib {
		case 0xf4:
			return false, nil
		case 0xf5:
			return true, nil
		case 0xf6:
			return nil, nil
		}
		return nil, fmt.Errorf("%w: unsupported simple value or float", errCBOR)
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil
	case 2:
		b, err := d.bytes(arg)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	case 3:
		b, err := d.bytes(arg)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4:
		if arg > uint64(d.remaining()) { // every item takes at least one byte
			return nil, fmt.Errorf("%w: truncated", errCBOR)
		}
		out := make([]any, 0, arg)
		for range arg {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > uint64(d.remaining())/2 {
			return nil, fmt.Errorf("%w: truncated", errCBOR)
		}
		out := make(map[any]any, arg)
		for range arg {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("%w: map keys must be integers or text", errCBOR)
			}
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("%w: duplicate map key %v", errCBOR, k)
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	default: // 6: tags
		return nil, fmt.Errorf("%w: tags are not supported", errCBOR)
	}
}
