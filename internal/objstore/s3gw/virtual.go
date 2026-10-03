package s3gw

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Virtual files: read-only files the gateway serves although no object in
// the bucket holds them as such. A ClickHouse restore to a moment reads a
// backup the agent assembles for that moment: its .backup file (made by
// the agent, Data) and the parts it lists, each file a range of an object
// already in the bucket (Pieces: a part the agent copied, or a file of an
// earlier backup). Config.Virtual maps ClickHouse's keys to them; they are
// listed with the real objects and can't be written or deleted.

// VirtualFile is one virtual file: Data, or the concatenation of Pieces.
type VirtualFile struct {
	Data   []byte
	Pieces []Piece
}

// Piece is the plaintext bytes [Off, Off+Len) of the sealed object stored
// at Stored (a key relative to the Store, as stored: for a file the gateway
// wrote, StoredKey's answer).
type Piece struct {
	Stored string `json:"stored"`
	Off    int64  `json:"off"`
	Len    int64  `json:"len"`
}

// Size is the file's size.
func (v VirtualFile) Size() int64 {
	if len(v.Pieces) == 0 {
		return int64(len(v.Data))
	}
	var n int64
	for _, p := range v.Pieces {
		n += p.Len
	}
	return n
}

// virtualTime is the Last-Modified of virtual files.
var virtualTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

func virtualETag(key string, size int64) string {
	sum := md5.Sum([]byte(fmt.Sprintf("virtual\x00%s\x00%d", key, size))) //nolint:gosec // an ETag
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (g *Gateway) virtual(key string) (VirtualFile, bool) {
	v, ok := g.cfg.Virtual[key]
	return v, ok
}

func (g *Gateway) serveVirtual(q *request, v VirtualFile) error {
	switch q.r.Method {
	case http.MethodHead:
		h := q.w.Header()
		h.Set("Content-Length", strconv.FormatInt(v.Size(), 10))
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Accept-Ranges", "bytes")
		h.Set("ETag", virtualETag(q.key, v.Size()))
		h.Set("Last-Modified", virtualTime.Format(http.TimeFormat))
		q.w.WriteHeader(http.StatusOK)
		return nil
	case http.MethodGet:
		return g.getVirtual(q, v)
	}
	return accessDenied("%s is part of a restore the agent assembled: it can only be read", q.key)
}

func (g *Gateway) getVirtual(q *request, v VirtualFile) error {
	ctx := q.r.Context()
	size := v.Size()
	first, n, ranged, err := parseRange(q.r.Header.Get("Range"))
	if err != nil {
		return err
	}
	if !ranged {
		first, n = 0, size
	} else if first, n, err = clampRange(first, n, size); err != nil {
		return err
	}
	// The start is read before answering, so a piece that doesn't open
	// fails with an answer ClickHouse doesn't retry.
	src := g.virtualReader(ctx, v, first, n)
	defer src.Close()
	pre := make([]byte, min(n, preDecrypt))
	if _, err := io.ReadFull(src, pre); err != nil {
		return damaged(q.key, err)
	}
	h := q.w.Header()
	h.Set("Content-Length", strconv.FormatInt(n, 10))
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", virtualETag(q.key, size))
	status := http.StatusOK
	if ranged {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, first+n-1, size))
		status = http.StatusPartialContent
	}
	q.w.WriteHeader(status)
	sent, err := q.w.Write(pre)
	if err == nil {
		var more int64
		more, err = io.CopyN(q.w, src, n-int64(len(pre)))
		sent += int(more)
	}
	g.bytesRead.Add(int64(sent))
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("reading %s: %w", q.key, err)
	}
	g.objectsRead.Add(1)
	if ranged {
		g.rangedReads.Add(1)
	}
	return nil
}

// virtualReader reads v's bytes [first, first+n).
func (g *Gateway) virtualReader(ctx context.Context, v VirtualFile, first, n int64) io.ReadCloser {
	if len(v.Pieces) == 0 {
		return io.NopCloser(bytes.NewReader(v.Data[first : first+n]))
	}
	pr, pw := io.Pipe()
	go func() {
		off := int64(0)
		end := first + n
		for _, p := range v.Pieces {
			ps, pe := off, off+p.Len
			off = pe
			if pe <= first || ps >= end {
				continue
			}
			from, to := max(ps, first), min(pe, end)
			rc, err := g.sealed.Range(ctx, p.Stored, p.Off+(from-ps), to-from)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			c := &countReader{r: rc}
			_, err = io.Copy(pw, c)
			rc.Close()
			g.storedRead.Add(c.n)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.Close()
	}()
	return pr
}

// SealedReader is the gateway's reader of sealed objects (for the agent's
// own reads through the same header cache).
func (g *Gateway) SealedReader() *objstore.SealedReader { return g.sealed }
