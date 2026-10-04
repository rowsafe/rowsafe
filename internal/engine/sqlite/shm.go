package sqlite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
)

// The wal-index header at the start of the -shm file (two copies of a
// 48-byte WalIndexHdr, in the host's byte order): it says how many WAL
// frames are committed (mxFrame) and the WAL's current salts. The agent
// reads it with a plain read, as SQLite's own readers do through mmap,
// and only trusts it when both copies agree and its checksum matches.
// Everything up to mxFrame is whole, committed transactions, so the
// agent never reads a transaction the app is still writing.

type shmHeader struct {
	Change   uint32
	PageSize int
	MaxFrame uint32  // committed frames in the WAL
	Salt     [8]byte // as in the WAL header (big-endian bytes)
	Cksum1   uint32  // cumulative checksum of frame MaxFrame
	Cksum2   uint32
}

var errShmUnreadable = errors.New("the -shm file isn't readable yet")

func readShmHeader(path string) (shmHeader, error) {
	f, err := os.Open(path + "-shm")
	if err != nil {
		return shmHeader{}, err
	}
	defer f.Close()
	b := make([]byte, 96)
	for range 8 {
		if _, err := f.ReadAt(b, 0); err != nil {
			return shmHeader{}, errShmUnreadable
		}
		if h, ok := parseShmHeader(b); ok {
			return h, nil
		}
	}
	return shmHeader{}, errShmUnreadable
}

func parseShmHeader(b []byte) (shmHeader, bool) {
	if len(b) < 96 || !bytes.Equal(b[:48], b[48:96]) {
		return shmHeader{}, false
	}
	ne := binary.NativeEndian
	if ne.Uint32(b[0:]) != walVersion || b[12] != 1 {
		return shmHeader{}, false
	}
	// aCksum (bytes 40..47) covers bytes 0..39, native byte order.
	s1, s2 := walChecksumNative(b[:40])
	if s1 != ne.Uint32(b[40:]) || s2 != ne.Uint32(b[44:]) {
		return shmHeader{}, false
	}
	h := shmHeader{Change: ne.Uint32(b[8:]), PageSize: int(ne.Uint16(b[14:])), MaxFrame: ne.Uint32(b[16:]),
		Cksum1: ne.Uint32(b[24:]), Cksum2: ne.Uint32(b[28:])}
	if h.PageSize == 1 {
		h.PageSize = 65536
	}
	copy(h.Salt[:], b[32:40])
	return h, true
}

// walChecksumNative is walChecksum over native-order words.
func walChecksumNative(b []byte) (uint32, uint32) {
	var x [4]byte
	binary.NativeEndian.PutUint32(x[:], 1)
	return walChecksum(x[0] == 0, b, 0, 0)
}
