package s3gw

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // multipart ETags are MD5 by definition
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Multipart uploads. ClickHouse sends the parts of a large file in
// parallel; the bucket must end up with one sealed stream of them in order.
// Each part goes to a temporary file (AES-CTR with the gateway's in-memory
// key, so no plaintext touches the disk), and the upload's drainer feeds
// the parts, in order and as soon as they are contiguous, into one Seal
// writing into one Store.Put. Complete then only waits for the tail.

// maxWaiting is how many bytes of parts an upload may hold before answers
// to UploadPart wait for the drainer.
const maxWaiting = 128 << 20

var errAborted = errors.New("the upload was aborted")

type part struct {
	path string
	size int64
	etag string
	iv   []byte
}

type upload struct {
	g      *Gateway
	id     string
	key    string
	ctx    context.Context
	cancel context.CancelCauseFunc
	done   chan struct{} // the drainer is finished

	mu       sync.Mutex
	cond     *sync.Cond
	parts    map[int]*part  // received, not drained yet
	inflight *part          // being drained (part number next)
	drained  map[int]string // ETags of the drained parts
	next     int            // next part number to drain
	waiting  int64          // bytes held in parts and inflight
	final    int            // number of parts, once Complete arrived
	err      error          // the upload failed
	plain    int64
	stored   int64
	counted  bool
}

type initiateResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

func (g *Gateway) createUpload(q *request) error {
	if _, err := io.Copy(io.Discard, q.r.Body); err != nil {
		return err
	}
	ctx, cancel := context.WithCancelCause(g.ctx)
	u := &upload{g: g, id: randHex(16), key: q.key, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		parts: map[int]*part{}, drained: map[int]string{}, next: 1}
	u.cond = sync.NewCond(&u.mu)
	context.AfterFunc(ctx, u.wake)
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		cancel(errAborted)
		return errf(http.StatusServiceUnavailable, "ServiceUnavailable", "the backup gateway is stopping")
	}
	g.uploads[u.id] = u
	g.wg.Add(1)
	g.mu.Unlock()
	go u.drain()
	return writeXML(q.w, http.StatusOK, initiateResult{Bucket: Bucket, Key: q.key, UploadID: u.id})
}

func (u *upload) wake() {
	u.mu.Lock()
	u.cond.Broadcast()
	u.mu.Unlock()
}

func (g *Gateway) findUpload(id, key string) (*upload, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := g.uploads[id]
	if u == nil || u.key != key {
		return nil, errf(http.StatusNotFound, "NoSuchUpload", "the upload does not exist (aborted, or the gateway restarted)")
	}
	return u, nil
}

func (g *Gateway) uploadPart(q *request, id, number string) error {
	u, err := g.findUpload(id, q.key)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(number)
	if err != nil || n < 1 || n > 10000 {
		return errf(http.StatusBadRequest, "InvalidArgument", "part numbers go from 1 to 10000")
	}
	b, err := q.body()
	if err != nil {
		return err
	}
	p, err := g.writePart(b)
	if err != nil {
		return err
	}
	p.etag = b.etag()
	if err := u.add(n, p); err != nil {
		os.Remove(p.path)
		return err
	}
	if err := u.hold(q.r.Context(), n, p); err != nil {
		return err
	}
	q.w.Header().Set("ETag", p.etag)
	q.w.WriteHeader(http.StatusOK)
	return nil
}

// writePart stores a part's payload in a temporary file, encrypted.
func (g *Gateway) writePart(b io.Reader) (*part, error) {
	f, err := os.CreateTemp(g.tmp, "part-") // 0600
	if err != nil {
		return nil, err
	}
	p := &part{path: f.Name(), iv: randBytes(aes.BlockSize)}
	block, err := aes.NewCipher(g.tmpKey)
	if err != nil {
		f.Close()
		os.Remove(p.path)
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 256<<10)
	p.size, err = io.Copy(cipher.StreamWriter{S: cipher.NewCTR(block, p.iv), W: bw}, b)
	if err == nil {
		err = bw.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p.path)
		return nil, err
	}
	return p, nil
}

// readPart decrypts a part's file into w.
func (g *Gateway) readPart(p *part, w io.Writer) error {
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()
	block, err := aes.NewCipher(g.tmpKey)
	if err != nil {
		return err
	}
	n, err := io.Copy(w, cipher.StreamReader{S: cipher.NewCTR(block, p.iv), R: bufio.NewReaderSize(f, 256<<10)})
	if err == nil && n != p.size {
		err = fmt.Errorf("a buffered part has %d bytes instead of %d", n, p.size)
	}
	return err
}

// add registers part n. A part sent again (a retry) replaces the one
// waiting, or is a no-op when it was drained with the same content.
func (u *upload) add(n int, p *part) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return u.failure()
	}
	if u.ctx.Err() != nil {
		return errf(http.StatusNotFound, "NoSuchUpload", "the upload was aborted")
	}
	if u.final > 0 {
		return errf(http.StatusBadRequest, "InvalidRequest", "the upload is being completed")
	}
	etag, drained := u.drained[n]
	if u.inflight != nil && n == u.next {
		etag, drained = u.inflight.etag, true
	}
	if drained {
		if etag != p.etag {
			return errf(http.StatusBadRequest, "InvalidPart", "part %d was already stored with different content", n)
		}
		os.Remove(p.path)
		return nil
	}
	if old := u.parts[n]; old != nil {
		os.Remove(old.path)
		u.waiting -= old.size
	}
	u.parts[n] = p
	u.waiting += p.size
	u.cond.Broadcast()
	return nil
}

// hold waits, while the upload holds too much, until part n is drained.
func (u *upload) hold(ctx context.Context, n int, p *part) error {
	stop := context.AfterFunc(ctx, u.wake)
	defer stop()
	u.mu.Lock()
	defer u.mu.Unlock()
	for u.waiting > maxWaiting && u.parts[n] == p && u.err == nil && ctx.Err() == nil && u.ctx.Err() == nil {
		u.cond.Wait()
	}
	if u.err != nil {
		return u.failure()
	}
	return ctx.Err()
}

func (u *upload) failure() error {
	return fmt.Errorf("storing %s failed: %w", u.key, u.err)
}

// drain feeds the parts, in order, into one sealed upload to the bucket.
func (u *upload) drain() {
	defer u.g.wg.Done()
	defer close(u.done)
	pr, pw := io.Pipe()
	putDone := make(chan struct{})
	var (
		stored int64
		putErr error
	)
	go func() {
		defer close(putDone)
		stored, putErr = u.g.cfg.Store.Put(u.ctx, u.key, pr)
		pr.CloseWithError(cmpErr(putErr, errors.New("the storage stopped reading")))
	}()
	u.g.heads.forget(u.key)
	err := u.feed(pw)
	pw.CloseWithError(err) // nil: EOF, the upload completes; else it is abandoned
	<-putDone
	u.g.heads.forget(u.key)
	if err == nil {
		err = putErr
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil && u.err == nil {
		u.err = err
		if !errors.Is(err, errAborted) && !errors.Is(err, context.Canceled) {
			u.g.log.Error("backup gateway: storing a file failed", "key", u.key, "error", err)
		}
	}
	u.stored = stored
	for n, p := range u.parts {
		os.Remove(p.path)
		delete(u.parts, n)
	}
	u.waiting = 0
	u.cond.Broadcast()
}

func (u *upload) feed(pw io.Writer) error {
	sw, err := objstore.Seal(pw, u.g.cfg.Passphrase)
	if err != nil {
		return err
	}
	for {
		u.mu.Lock()
		for u.err == nil && u.ctx.Err() == nil && u.parts[u.next] == nil && (u.final == 0 || u.next <= u.final) {
			u.cond.Wait()
		}
		switch {
		case u.err != nil:
			err := u.err
			u.mu.Unlock()
			return err
		case u.ctx.Err() != nil:
			u.mu.Unlock()
			return context.Cause(u.ctx)
		case u.final > 0 && u.next > u.final:
			u.mu.Unlock()
			return sw.Close()
		}
		n, p := u.next, u.parts[u.next]
		delete(u.parts, n)
		u.inflight = p
		u.mu.Unlock()

		err := u.g.readPart(p, sw)
		os.Remove(p.path)

		u.mu.Lock()
		u.inflight = nil
		u.waiting -= p.size
		if err == nil {
			u.drained[n] = p.etag
			u.plain += p.size
			u.next++
		}
		u.cond.Broadcast()
		u.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

type completeRequest struct {
	Parts []struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

type completeResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

func (g *Gateway) completeUpload(q *request, id string) error {
	u, err := g.findUpload(id, q.key)
	if err != nil {
		return err
	}
	b, err := q.body()
	if err != nil {
		return err
	}
	data, err := readSmall(b, 4<<20)
	if err != nil {
		var se *s3Error
		if errors.As(err, &se) {
			return se
		}
		return errf(http.StatusBadRequest, "MalformedXML", "the part list is too large or unreadable")
	}
	var req completeRequest
	if err := xml.Unmarshal(data, &req); err != nil || len(req.Parts) == 0 {
		return errf(http.StatusBadRequest, "MalformedXML", "the part list is not valid")
	}
	etags := md5.New() //nolint:gosec // see the import
	u.mu.Lock()
	for i, p := range req.Parts {
		if p.PartNumber != i+1 {
			u.mu.Unlock()
			return errf(http.StatusBadRequest, "InvalidPartOrder", "the backup gateway needs parts numbered 1, 2, 3... (got %d in position %d)", p.PartNumber, i+1)
		}
		have, ok := u.drained[p.PartNumber]
		if u.inflight != nil && p.PartNumber == u.next {
			have, ok = u.inflight.etag, true
		} else if w := u.parts[p.PartNumber]; w != nil {
			have, ok = w.etag, true
		}
		if u.final == 0 && (!ok || strings.Trim(have, `"`) != strings.Trim(p.ETag, `"`)) {
			u.mu.Unlock()
			return errf(http.StatusBadRequest, "InvalidPart", "part %d is missing or has another ETag", p.PartNumber)
		}
		sum, _ := hex.DecodeString(strings.Trim(have, `"`))
		etags.Write(sum)
	}
	switch {
	case u.final == 0:
		// Parts sent but not listed are dropped, as S3 does.
		for n, p := range u.parts {
			if n > len(req.Parts) {
				os.Remove(p.path)
				u.waiting -= p.size
				delete(u.parts, n)
			}
		}
		u.final = len(req.Parts)
		u.cond.Broadcast()
	case u.final != len(req.Parts):
		u.mu.Unlock()
		return errf(http.StatusBadRequest, "InvalidPart", "the upload is already being completed with %d parts", u.final)
	}
	u.mu.Unlock()

	select {
	case <-u.done:
	case <-q.r.Context().Done():
		return q.r.Context().Err()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return u.failure()
	}
	if !u.counted {
		u.counted = true
		g.objectsWritten.Add(1)
		g.multipart.Add(1)
		g.bytesWritten.Add(u.plain)
		g.storedWritten.Add(u.stored)
	}
	etag := `"` + hex.EncodeToString(etags.Sum(nil)) + "-" + strconv.Itoa(len(req.Parts)) + `"`
	return writeXML(q.w, http.StatusOK, completeResult{Location: g.Endpoint(q.key), Bucket: Bucket, Key: q.key, ETag: etag})
}

func (g *Gateway) abortUpload(q *request, id string) error {
	u, err := g.findUpload(id, q.key)
	if err != nil {
		return err
	}
	u.cancel(errAborted)
	select {
	case <-u.done:
	case <-q.r.Context().Done():
		return q.r.Context().Err()
	}
	g.mu.Lock()
	delete(g.uploads, id)
	g.mu.Unlock()
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}
