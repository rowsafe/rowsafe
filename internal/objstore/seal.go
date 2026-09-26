package objstore

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Sealed stream format (version 1), written by Seal and read by Open:
//
//	magic "RWSF1\n" | salt (16 bytes) | nonce prefix (7 bytes) | segments
//
// Each segment is up to 64 KiB of plaintext sealed with AES-256-GCM (16-byte
// tag). The nonce is the prefix, a 4-byte big-endian segment counter and a
// final flag (1 on the last segment only), so segments can't be reordered,
// dropped or truncated unnoticed. The key is HKDF-SHA256 of the master key
// with the salt; the master key is PBKDF2-HMAC-SHA256 of the passphrase
// (ROWSAFE_REPO_CIPHER_PASS, 600,000 iterations). Only the server knows the
// passphrase, so only it (or whoever holds a copy) can open what it sealed.

const (
	sealMagic   = "RWSF1\n"
	segmentSize = 64 << 10
	tagSize     = 16
	saltSize    = 16
	prefixSize  = 7
	kdfIter     = 600000
	kdfSalt     = "rowsafe objstore v1"
)

// ErrBadPassphrase is returned when a stream doesn't open with the
// passphrase: wrong passphrase, or the data was altered.
var ErrBadPassphrase = errors.New("can't decrypt: wrong encryption passphrase, or the file was altered")

var (
	masterMu    sync.Mutex
	masterCache = map[string][]byte{}
)

// masterKey stretches the passphrase once per process.
func masterKey(passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("no encryption passphrase (ROWSAFE_REPO_CIPHER_PASS)")
	}
	sum := sha256.Sum256([]byte(passphrase))
	id := string(sum[:])
	masterMu.Lock()
	defer masterMu.Unlock()
	if k, ok := masterCache[id]; ok {
		return k, nil
	}
	k, err := pbkdf2.Key(sha256.New, passphrase, []byte(kdfSalt), kdfIter, 32)
	if err != nil {
		return nil, err
	}
	masterCache[id] = k
	return k, nil
}

func segmentAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	mk, err := masterKey(passphrase)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, mk, salt, "rowsafe sealed stream", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func segmentNonce(prefix []byte, n uint32, last bool) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[prefixSize:], n)
	if last {
		nonce[11] = 1
	}
	return nonce
}

// sealWriter encrypts into w.
type sealWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	buf    []byte
	n      uint32
	closed bool
	err    error
}

// Seal returns a writer that encrypts everything written to it into w.
// Close it to write the final segment (it doesn't close w).
func Seal(w io.Writer, passphrase string) (io.WriteCloser, error) {
	head := make([]byte, len(sealMagic)+saltSize+prefixSize)
	copy(head, sealMagic)
	if _, err := rand.Read(head[len(sealMagic):]); err != nil {
		return nil, err
	}
	salt := head[len(sealMagic) : len(sealMagic)+saltSize]
	aead, err := segmentAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(head); err != nil {
		return nil, err
	}
	return &sealWriter{w: w, aead: aead, prefix: head[len(sealMagic)+saltSize:], buf: make([]byte, 0, segmentSize)}, nil
}

func (s *sealWriter) flush(last bool) error {
	if s.n == ^uint32(0) {
		return errors.New("sealed stream too long")
	}
	out := s.aead.Seal(nil, segmentNonce(s.prefix, s.n, last), s.buf, nil)
	s.n++
	s.buf = s.buf[:0]
	_, err := s.w.Write(out)
	return err
}

func (s *sealWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.closed {
		return 0, errors.New("write to a closed sealed stream")
	}
	written := 0
	for len(p) > 0 {
		// A full segment is only flushed once more data arrives, so the
		// last segment (flagged) is never empty unless the stream is.
		if len(s.buf) == segmentSize {
			if s.err = s.flush(false); s.err != nil {
				return written, s.err
			}
		}
		k := min(segmentSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:k]...)
		p = p[k:]
		written += k
	}
	return written, nil
}

func (s *sealWriter) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	s.err = s.flush(true)
	return s.err
}

// openReader decrypts a sealed stream.
type openReader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	prefix []byte
	seg    []byte // ciphertext buffer
	plain  []byte
	pos    int
	n      uint32
	done   bool
	err    error
}

// Open returns a reader of the plaintext of the sealed stream r. It fails
// with ErrBadPassphrase when a segment doesn't authenticate, and with
// io.ErrUnexpectedEOF when the stream was cut short.
func Open(r io.Reader, passphrase string) (io.Reader, error) {
	head := make([]byte, len(sealMagic)+saltSize+prefixSize)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("not a Rowsafe encrypted file (too short): %w", err)
	}
	if string(head[:len(sealMagic)]) != sealMagic {
		return nil, errors.New("not a Rowsafe encrypted file")
	}
	aead, err := segmentAEAD(passphrase, head[len(sealMagic):len(sealMagic)+saltSize])
	if err != nil {
		return nil, err
	}
	return &openReader{r: bufio.NewReaderSize(r, 256<<10), aead: aead, prefix: head[len(sealMagic)+saltSize:], seg: make([]byte, segmentSize+tagSize)}, nil
}

func (o *openReader) Read(p []byte) (int, error) {
	for o.pos == len(o.plain) {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		o.err = o.next()
	}
	n := copy(p, o.plain[o.pos:])
	o.pos += n
	return n, nil
}

// next reads and opens one segment. The segment followed by nothing is the
// last one.
func (o *openReader) next() error {
	n, err := io.ReadFull(o.r, o.seg)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	last := true
	if err == nil {
		_, perr := o.r.Peek(1)
		last = perr != nil
	}
	if n < tagSize {
		return io.ErrUnexpectedEOF
	}
	ct := o.seg[:n]
	plain, oerr := o.aead.Open(nil, segmentNonce(o.prefix, o.n, last), ct, nil)
	if oerr != nil {
		if last {
			// Cut exactly on a segment boundary: this is a middle segment
			// and the final one is missing.
			if _, e2 := o.aead.Open(nil, segmentNonce(o.prefix, o.n, false), ct, nil); e2 == nil {
				return io.ErrUnexpectedEOF
			}
		}
		return ErrBadPassphrase
	}
	o.n++
	o.plain, o.pos = plain, 0
	o.done = last
	return nil
}
