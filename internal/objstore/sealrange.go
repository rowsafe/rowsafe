package objstore

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// SealedReader reads plaintext ranges of sealed objects (Seal) without
// downloading them whole: one small read for the header and size (kept
// for the next ranges of the same object), then only the segments the
// range touches.
type SealedReader struct {
	Store      *Store
	Passphrase string

	mu    sync.Mutex
	heads map[string]sealedHead
}

type sealedHead struct {
	header []byte
	size   int64
}

func (r *SealedReader) head(ctx context.Context, key string) (sealedHead, error) {
	r.mu.Lock()
	h, ok := r.heads[key]
	r.mu.Unlock()
	if ok {
		return h, nil
	}
	rc, size, err := r.Store.GetRange(ctx, key, 0, int64(SealHeaderSize))
	if err != nil {
		return sealedHead{}, err
	}
	defer rc.Close()
	b := make([]byte, SealHeaderSize)
	if _, err := io.ReadFull(rc, b); err != nil {
		return sealedHead{}, fmt.Errorf("%s is not a Rowsafe encrypted file: %w", key, err)
	}
	h = sealedHead{header: b, size: size}
	r.mu.Lock()
	if r.heads == nil || len(r.heads) >= 8192 {
		r.heads = map[string]sealedHead{}
	}
	r.heads[key] = h
	r.mu.Unlock()
	return h, nil
}

// PlainSize is the plaintext size of the sealed object at key.
func (r *SealedReader) PlainSize(ctx context.Context, key string) (int64, error) {
	h, err := r.head(ctx, key)
	if err != nil {
		return 0, err
	}
	return PlainSize(h.size)
}

// Range returns the plaintext bytes [off, off+n) of the sealed object at
// key. Reading past its end is an error.
func (r *SealedReader) Range(ctx context.Context, key string, off, n int64) (io.ReadCloser, error) {
	if n == 0 {
		return io.NopCloser(eofReader{}), nil
	}
	h, err := r.head(ctx, key)
	if err != nil {
		return nil, err
	}
	plain, err := PlainSize(h.size)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if off < 0 || n < 0 || off+n > plain {
		return nil, fmt.Errorf("%s: bytes %d-%d are past its end (%d bytes)", key, off, off+n, plain)
	}
	start, end, first, skip := SealedRange(h.size, off, n)
	rc, _, err := r.Store.GetRange(ctx, key, start, end-start)
	if err != nil {
		return nil, err
	}
	src, err := OpenAt(rc, r.Passphrase, h.header, h.size, first)
	if err != nil {
		rc.Close()
		return nil, err
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, src, skip); err != nil {
			rc.Close()
			return nil, err
		}
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(src, n), rc}, nil
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
