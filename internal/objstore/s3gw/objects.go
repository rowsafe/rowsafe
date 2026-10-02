package s3gw

import (
	"context"
	"crypto/md5" //nolint:gosec // ETags only
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// seal stores what src yields, sealed, at key. Nothing is stored unless src
// reads to EOF; received is called once it has.
func (g *Gateway) seal(ctx context.Context, key string, src io.Reader, received func()) (plain, stored int64, err error) {
	g.heads.forget(key)
	defer g.heads.forget(key)
	pr, pw := io.Pipe()
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := g.cfg.Store.Put(ctx, g.stored(key), pr)
		// Unblocks the writer when the storage gave up early.
		pr.CloseWithError(cmpErr(err, errors.New("the storage stopped reading")))
		done <- result{n, err}
	}()
	sw, err := objstore.Seal(pw, g.cfg.Passphrase)
	if err == nil {
		plain, err = io.Copy(sw, src)
		if err == nil {
			if received != nil {
				received()
			}
			err = sw.Close()
		}
	}
	pw.CloseWithError(err) // nil: EOF, the object is complete
	res := <-done
	if err != nil {
		return plain, 0, err
	}
	if res.err != nil {
		return plain, 0, res.err
	}
	return plain, res.n, nil
}

func cmpErr(err, otherwise error) error {
	if err != nil {
		return err
	}
	return otherwise
}

// pendingPut is a PutObject being stored. ClickHouse stops waiting for an
// answer after a few seconds on its first attempt and sends the object
// again; once the whole body has arrived the upload goes on without it, and
// the retry (same key, same Content-MD5) waits for that upload instead of
// storing the object a second time.
type pendingPut struct {
	md5      string
	received atomic.Bool // the whole body arrived
	done     chan struct{}
	err      error
	etag     string
}

func (g *Gateway) putObject(q *request) error {
	b, err := q.body()
	if err != nil {
		return err
	}
	cm := q.r.Header.Get("Content-MD5")
	g.mu.Lock()
	if p := g.puts[q.key]; p != nil && cm != "" && p.md5 == cm && p.received.Load() {
		g.mu.Unlock()
		if _, err := io.Copy(io.Discard, b); err != nil {
			return err
		}
		select {
		case <-p.done:
		case <-q.r.Context().Done():
			return q.r.Context().Err()
		}
		if p.err != nil {
			return p.err
		}
		q.w.Header().Set("ETag", p.etag)
		q.w.WriteHeader(http.StatusOK)
		return nil
	}
	p := &pendingPut{md5: cm, done: make(chan struct{})}
	g.puts[q.key] = p
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.puts[q.key] == p {
			delete(g.puts, q.key)
		}
		g.mu.Unlock()
		close(p.done)
	}()
	// The gateway's context, not the request's: see pendingPut.
	plain, stored, err := g.seal(g.ctx, q.key, b, func() { p.received.Store(true) })
	if err != nil {
		p.err = err
		return err
	}
	p.etag = b.etag()
	g.objectsWritten.Add(1)
	g.bytesWritten.Add(plain)
	g.storedWritten.Add(stored)
	q.w.Header().Set("ETag", p.etag)
	q.w.WriteHeader(http.StatusOK)
	return nil
}

// objectETag is a stable ETag for a stored object (S3 clients want one;
// ClickHouse doesn't compare it with the PutObject one).
func objectETag(key string, size int64, mtime time.Time) string {
	sum := md5.Sum([]byte(fmt.Sprintf("%s\x00%d\x00%d", key, size, mtime.UnixNano()))) //nolint:gosec // an ETag
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (g *Gateway) headObject(q *request) error {
	o, err := g.cfg.Store.Head(q.r.Context(), g.stored(q.key))
	if err != nil {
		return err
	}
	plain, err := objstore.PlainSize(o.Size)
	if err != nil {
		return fmt.Errorf("%s: %w", q.key, err)
	}
	h := q.w.Header()
	h.Set("Content-Length", strconv.FormatInt(plain, 10))
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", objectETag(q.key, o.Size, o.LastModified))
	if !o.LastModified.IsZero() {
		h.Set("Last-Modified", o.LastModified.UTC().Format(http.TimeFormat))
	}
	q.w.WriteHeader(http.StatusOK)
	return nil
}

// parseRange reads a single "bytes=" range; ok is false when there is
// none (or one the gateway serves whole, as S3 does: several ranges).
// first < 0 is a suffix of n bytes; n < 0 is "to the end".
func parseRange(h string) (first, n int64, ok bool, err error) {
	spec, found := strings.CutPrefix(h, "bytes=")
	if h == "" || !found || strings.Contains(spec, ",") {
		return 0, 0, false, nil
	}
	a, b, found := strings.Cut(spec, "-")
	if !found {
		return 0, 0, false, nil
	}
	bad := errf(http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "the range %q is not valid", h)
	switch {
	case a == "":
		s, err := strconv.ParseInt(b, 10, 64)
		if err != nil || s <= 0 {
			return 0, 0, false, bad
		}
		return -1, s, true, nil
	case b == "":
		f, err := strconv.ParseInt(a, 10, 64)
		if err != nil || f < 0 {
			return 0, 0, false, bad
		}
		return f, -1, true, nil
	}
	f, err1 := strconv.ParseInt(a, 10, 64)
	l, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil || f < 0 || l < f {
		return 0, 0, false, bad
	}
	return f, l - f + 1, true, nil
}

// header returns key's sealed header and stored size, from the cache or
// with a small ranged read.
func (g *Gateway) header(ctx context.Context, key string) (headEntry, error) {
	e, gen, ok := g.heads.get(key)
	if ok {
		return e, nil
	}
	rc, size, err := g.cfg.Store.GetRange(ctx, g.stored(key), 0, int64(objstore.SealHeaderSize))
	if err != nil {
		return headEntry{}, err
	}
	defer rc.Close()
	h := make([]byte, objstore.SealHeaderSize)
	if _, err := io.ReadFull(rc, h); err != nil {
		return headEntry{}, fmt.Errorf("%s is not a Rowsafe encrypted file: %w", key, err)
	}
	g.storedRead.Add(int64(len(h)))
	e = headEntry{header: h, size: size}
	g.heads.put(key, e, gen)
	return e, nil
}

func (g *Gateway) getObject(q *request) error {
	ctx := q.r.Context()
	first, n, ranged, err := parseRange(q.r.Header.Get("Range"))
	if err != nil {
		return err
	}
	var (
		rc     io.ReadCloser
		head   headEntry
		plain  int64
		seg    int64
		skip   int64
		cached bool
	)
	if !ranged {
		var size int64
		rc, size, err = g.cfg.Store.GetRange(ctx, g.stored(q.key), 0, -1)
		if err != nil {
			return err
		}
		defer rc.Close()
		if plain, err = objstore.PlainSize(size); err != nil {
			return fmt.Errorf("%s: %w", q.key, err)
		}
		head.size = size
		first, n = 0, plain
	} else {
		var gen uint64
		head, gen, cached = g.heads.get(q.key)
		if !cached && (first < 0 || first >= objstore.SealSegmentSize) {
			// The range starts past the first segment: the header (and
			// the size, for a suffix) first.
			if head, err = g.header(ctx, q.key); err != nil {
				return err
			}
			cached = true
		}
		if cached {
			if plain, err = objstore.PlainSize(head.size); err != nil {
				return fmt.Errorf("%s: %w", q.key, err)
			}
			if first, n, err = clampRange(first, n, plain); err != nil {
				return err
			}
			s, e, sg, sk := objstore.SealedRange(head.size, first, n)
			rc, _, err = g.cfg.Store.GetRange(ctx, g.stored(q.key), s, e-s)
			if err != nil {
				return err
			}
			defer rc.Close()
			seg, skip = sg, sk
		} else {
			// Starts in the first segment: one read from the beginning,
			// header included. Without the size, ask for as much as the
			// range would need of a large enough object.
			want := int64(-1)
			if n > 0 {
				want = int64(objstore.SealHeaderSize) + ((first+n-1)/objstore.SealSegmentSize+1)*(objstore.SealSegmentSize+16)
			}
			var size int64
			rc, size, err = g.cfg.Store.GetRange(ctx, g.stored(q.key), 0, want)
			if err != nil {
				return err
			}
			defer rc.Close()
			h := make([]byte, objstore.SealHeaderSize)
			if _, err := io.ReadFull(rc, h); err != nil {
				return damaged(q.key, fmt.Errorf("%s is not a Rowsafe encrypted file: %w", q.key, err))
			}
			g.storedRead.Add(int64(len(h)))
			head = headEntry{header: h, size: size}
			g.heads.put(q.key, head, gen)
			if plain, err = objstore.PlainSize(size); err != nil {
				return fmt.Errorf("%s: %w", q.key, err)
			}
			if first, n, err = clampRange(first, n, plain); err != nil {
				return err
			}
			seg, skip = 0, first
		}
	}
	var src io.Reader
	counted := &countReader{r: rc}
	if !ranged {
		src, err = objstore.Open(counted, g.cfg.Passphrase)
	} else {
		src, err = objstore.OpenAt(counted, g.cfg.Passphrase, head.header, head.size, seg)
	}
	if err != nil {
		return damaged(q.key, err)
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, src, skip); err != nil {
			return damaged(q.key, err)
		}
	}
	// The start is decrypted before answering, so a file that doesn't open
	// fails with an answer ClickHouse doesn't retry (damaged). Past it, a
	// failure cuts the connection; ClickHouse reads again from there and
	// gets that answer.
	pre := make([]byte, min(n, preDecrypt))
	if _, err := io.ReadFull(src, pre); err != nil {
		return damaged(q.key, err)
	}
	h := q.w.Header()
	h.Set("Content-Length", strconv.FormatInt(n, 10))
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Accept-Ranges", "bytes")
	status := http.StatusOK
	if ranged {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, first+n-1, plain))
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
	g.storedRead.Add(counted.n)
	if err != nil {
		if ctx.Err() != nil {
			return nil // ClickHouse went away
		}
		// Headers are out: fail cuts the connection.
		return fmt.Errorf("decrypting %s: %w", q.key, err)
	}
	g.objectsRead.Add(1)
	if ranged {
		g.rangedReads.Add(1)
	}
	return nil
}

// preDecrypt is how much of an answer is decrypted before it starts.
const preDecrypt = 4 << 20

// damaged turns a decryption failure into an answer ClickHouse doesn't
// retry (403: retrying can't help), in plain words it shows in its error;
// other errors (the storage, the network) stay retryable.
func damaged(key string, err error) error {
	if errors.Is(err, objstore.ErrBadPassphrase) || errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(err.Error(), "not a Rowsafe encrypted file") {
		return errf(http.StatusForbidden, "AccessDenied", "the backup file %s can't be decrypted: wrong encryption passphrase, or the file was altered", key)
	}
	return fmt.Errorf("decrypting %s: %w", key, err)
}

// clampRange fits a parsed range to an object of plain bytes.
func clampRange(first, n, plain int64) (int64, int64, error) {
	if first < 0 { // suffix
		n = min(n, plain)
		first = plain - n
	}
	if first >= plain {
		return 0, 0, errf(http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "the range starts past the end of the object (%d bytes)", plain)
	}
	if n < 0 || first+n > plain {
		n = plain - first
	}
	return first, n, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (g *Gateway) deleteObject(q *request) error {
	g.heads.forget(q.key)
	if err := g.cfg.Store.Delete(q.r.Context(), g.stored(q.key)); err != nil {
		return err
	}
	g.deleted.Add(1)
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

type deleteRequest struct {
	Quiet   bool `xml:"Quiet"`
	Objects []struct {
		Key string `xml:"Key"`
	} `xml:"Object"`
}

type deleteResult struct {
	XMLName xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedObject `xml:"Deleted"`
	Errors  []deleteError   `xml:"Error"`
}

type deletedObject struct {
	Key string `xml:"Key"`
}

type deleteError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (g *Gateway) deleteObjects(q *request) error {
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
		return errf(http.StatusBadRequest, "MalformedXML", "the delete request is too large or unreadable")
	}
	var req deleteRequest
	if err := xml.Unmarshal(data, &req); err != nil || len(req.Objects) == 0 || len(req.Objects) > 1000 {
		return errf(http.StatusBadRequest, "MalformedXML", "the delete request is not valid")
	}
	var (
		mu  sync.Mutex
		res deleteResult
		wg  sync.WaitGroup
		sem = make(chan struct{}, 8)
	)
	for _, o := range req.Objects {
		key := o.Key
		if err := g.checkKey(key); err != nil {
			se := err.(*s3Error)
			res.Errors = append(res.Errors, deleteError{Key: key, Code: se.code, Message: se.message})
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			g.heads.forget(key)
			err := g.cfg.Store.Delete(q.r.Context(), g.stored(key))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors = append(res.Errors, deleteError{Key: key, Code: "InternalError", Message: err.Error()})
				return
			}
			g.deleted.Add(1)
			if !req.Quiet {
				res.Deleted = append(res.Deleted, deletedObject{Key: key})
			}
		}()
	}
	wg.Wait()
	for _, e := range res.Errors {
		g.errs.Add(1)
		g.lastErr.Store("delete " + e.Key + ": " + e.Message)
		g.log.Warn("backup gateway: delete failed", "key", e.Key, "error", e.Message)
	}
	return writeXML(q.w, http.StatusOK, res)
}

type copyResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// copyObject copies the stored (sealed) bytes: same passphrase, so they
// open the same under the new key.
func (g *Gateway) copyObject(q *request) error {
	src := q.r.Header.Get("x-amz-copy-source")
	if i := strings.Index(src, "?"); i >= 0 {
		return errf(http.StatusNotImplemented, "NotImplemented", "copying a version is not supported")
	}
	if s, err := url.PathUnescape(src); err == nil {
		src = s
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(src, "/"), "/")
	if bucket != Bucket {
		return errf(http.StatusNotFound, "NoSuchBucket", "the bucket %q does not exist", bucket)
	}
	if err := g.checkKey(key); err != nil {
		return err
	}
	if q.r.Header.Get("x-amz-copy-source-range") != "" {
		return errf(http.StatusNotImplemented, "NotImplemented", "copying a range is not supported")
	}
	if _, err := io.Copy(io.Discard, q.r.Body); err != nil {
		return err
	}
	ctx := q.r.Context()
	rc, size, err := g.cfg.Store.GetRange(ctx, g.stored(key), 0, -1)
	if err != nil {
		return err
	}
	defer rc.Close()
	plain, err := objstore.PlainSize(size)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	g.heads.forget(q.key)
	stored, err := g.cfg.Store.Put(ctx, g.stored(q.key), rc)
	g.heads.forget(q.key)
	if err != nil {
		return err
	}
	if stored != size {
		return fmt.Errorf("copying %s: read %d bytes of %d", key, stored, size)
	}
	g.storedRead.Add(stored)
	g.objectsWritten.Add(1)
	g.bytesWritten.Add(plain)
	g.storedWritten.Add(stored)
	now := time.Now().UTC()
	return writeXML(q.w, http.StatusOK, copyResult{ETag: objectETag(q.key, stored, now), LastModified: now.Format("2006-01-02T15:04:05.000Z")})
}

type listContents struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type listResult struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	MaxKeys               int            `xml:"MaxKeys"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	Marker                *string        `xml:"Marker"`
	NextMarker            string         `xml:"NextMarker,omitempty"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	KeyCount              *int           `xml:"KeyCount"`
	Contents              []listContents `xml:"Contents"`
	CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
}

// list answers ListObjects (V1) and ListObjectsV2 with plaintext sizes,
// only showing keys under the gateway's prefixes.
func (g *Gateway) list(q *request, query url.Values) error {
	v2 := query.Get("list-type") == "2"
	prefix, delim := query.Get("prefix"), query.Get("delimiter")
	maxKeys := 1000
	if s := query.Get("max-keys"); s != "" {
		m, err := strconv.Atoi(s)
		if err != nil || m < 0 {
			return errf(http.StatusBadRequest, "InvalidArgument", "invalid max-keys")
		}
		maxKeys = min(m, 1000)
	}
	after := query.Get("marker")
	token := query.Get("continuation-token")
	if v2 {
		after = query.Get("start-after")
		if token != "" {
			t, err := hex.DecodeString(token)
			if err != nil {
				return errf(http.StatusBadRequest, "InvalidArgument", "invalid continuation token")
			}
			after = string(t)
		}
	}
	if delim != "" && strings.HasPrefix(after, prefix) && strings.HasSuffix(after, delim) {
		// Resuming after a common prefix: skip all of it.
		after += "\xff"
	}
	// What to list in the bucket: the folder (see names.go) the prefix is
	// in, when it is inside the gateway's prefixes, else the folders of
	// those it covers. Names are decrypted, then filtered, sorted and
	// paginated as plaintext keys.
	var roots []string
	if g.allowed(prefix) {
		roots = []string{g.folderOf(prefix)}
	} else {
		for _, p := range g.cfg.Prefixes {
			if strings.HasPrefix(p, prefix) {
				roots = append(roots, p[:strings.LastIndexByte(p, '/')+1])
			}
		}
		if len(roots) == 0 {
			return accessDenied("the prefix %q is outside the folders this gateway serves", prefix)
		}
	}
	type entry struct {
		key string // ClickHouse's
		obj objstore.Object
	}
	var objs []entry
	listed := map[string]bool{}
	for _, root := range roots {
		if listed[root] {
			continue
		}
		listed[root] = true
		o, err := g.cfg.Store.List(q.r.Context(), root)
		if err != nil {
			return err
		}
		for _, ob := range o {
			if k, ok := g.plainKey(root, ob.Key); ok && g.folderOf(k) == root {
				objs = append(objs, entry{k, ob})
			}
		}
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].key < objs[j].key })
	enc := func(s string) string { return s }
	if query.Get("encoding-type") == "url" {
		enc = func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "%2F", "/") }
	}
	res := listResult{Name: Bucket, Prefix: enc(prefix), Delimiter: enc(delim), MaxKeys: maxKeys, EncodingType: query.Get("encoding-type")}
	seen := map[string]bool{}
	count := 0
	last := ""
	for i, e := range objs {
		key, o := e.key, e.obj
		if (i > 0 && key == objs[i-1].key) || !strings.HasPrefix(key, prefix) || key <= after || !g.allowed(key) {
			continue
		}
		entry := key
		if delim != "" {
			if j := strings.Index(key[len(prefix):], delim); j >= 0 {
				entry = key[:len(prefix)+j+len(delim)]
				if seen[entry] || entry <= after {
					continue
				}
			}
		}
		if count == maxKeys {
			res.IsTruncated = true
			break
		}
		count++
		last = entry
		if entry != key {
			seen[entry] = true
			res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: enc(entry)})
			// Skip the rest of this common prefix.
			after = entry + "\xff"
			continue
		}
		plain, err := objstore.PlainSize(o.Size)
		if err != nil {
			g.log.Warn("backup gateway: an object in the backup folder is not a Rowsafe encrypted file", "key", o.Key, "size", o.Size)
			continue
		}
		res.Contents = append(res.Contents, listContents{Key: enc(key), LastModified: o.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
			ETag: objectETag(key, o.Size, o.LastModified), Size: plain, StorageClass: "STANDARD"})
	}
	if v2 {
		res.KeyCount = &count
		res.ContinuationToken = token
		res.StartAfter = enc(query.Get("start-after"))
		if res.IsTruncated {
			res.NextContinuationToken = hex.EncodeToString([]byte(last))
		}
	} else {
		marker := enc(query.Get("marker"))
		res.Marker = &marker
		if res.IsTruncated {
			res.NextMarker = enc(last)
		}
	}
	return writeXML(q.w, http.StatusOK, res)
}
