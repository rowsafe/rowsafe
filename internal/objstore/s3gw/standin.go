// Package s3gw: TEMPORARY stand-in for the encrypting S3 gateway built on
// branch feat/clickhouse-gateway, with the same API, so the ClickHouse
// engine can be developed and tested before it lands. Delete this file when
// the real package is merged.
package s3gw

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Config configures a gateway.
type Config struct {
	Store      *objstore.Store
	Passphrase string
	Listen     string
	PublicURL  string
	Prefixes   []string
	ReadOnly   bool
	Log        *slog.Logger
}

// Stats counts what went through the gateway.
type Stats struct {
	BytesIn, BytesOut int64
}

// Gateway is a running gateway.
type Gateway struct {
	cfg     Config
	ln      net.Listener
	srv     *http.Server
	base    string
	key     string
	secret  string
	tmp     string
	mu      sync.Mutex
	uploads map[string]map[int]string
	in, out atomic.Int64
}

const bucket = "rowsafe"

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start starts a gateway.
func Start(ctx context.Context, cfg Config) (*Gateway, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "s3gw-")
	if err != nil {
		ln.Close()
		return nil, err
	}
	g := &Gateway{cfg: cfg, ln: ln, key: "rs" + rnd(8), secret: rnd(20), tmp: tmp, uploads: map[string]map[int]string{}}
	g.base = strings.TrimRight(cfg.PublicURL, "/")
	if g.base == "" {
		g.base = "http://" + ln.Addr().String()
	}
	g.srv = &http.Server{Handler: http.HandlerFunc(g.handle)}
	go func() { _ = g.srv.Serve(ln) }()
	go func() { <-ctx.Done(); g.Close() }()
	return g, nil
}

func (g *Gateway) Endpoint(key string) string { return g.base + "/" + bucket + "/" + key }
func (g *Gateway) AccessKeyID() string        { return g.key }
func (g *Gateway) SecretAccessKey() string    { return g.secret }
func (g *Gateway) Stats() Stats               { return Stats{BytesIn: g.in.Load(), BytesOut: g.out.Load()} }

func (g *Gateway) Close() error {
	err := g.srv.Close()
	os.RemoveAll(g.tmp)
	return err
}

func (g *Gateway) allowed(key string) bool {
	if len(g.cfg.Prefixes) == 0 {
		return true
	}
	for _, p := range g.cfg.Prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func s3err(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func plainSize(sealed int64) int64 {
	const head, seg, tag = 29, 64 << 10, 16
	n := (sealed - head + seg + tag - 1) / (seg + tag)
	if n < 1 {
		n = 1
	}
	return sealed - head - tag*n
}

func (g *Gateway) size(ctx context.Context, key string) (int64, bool, error) {
	objs, err := g.cfg.Store.List(ctx, key)
	if err != nil {
		return 0, false, err
	}
	for _, o := range objs {
		if o.Key == key {
			return plainSize(o.Size), true, nil
		}
	}
	return 0, false, nil
}

func (g *Gateway) body(r *http.Request) io.Reader {
	if strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") || strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
		return &chunked{r: bufio.NewReader(r.Body)}
	}
	return r.Body
}

// chunked decodes aws-chunked bodies.
type chunked struct {
	r    *bufio.Reader
	left int64
	done bool
}

func (c *chunked) Read(p []byte) (int, error) {
	for c.left == 0 {
		if c.done {
			return 0, io.EOF
		}
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sz, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(sz, 16, 64)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			c.done = true
			return 0, io.EOF
		}
		c.left = n
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left == 0 {
		_, _ = c.r.ReadString('\n')
	}
	return n, err
}

func (g *Gateway) put(ctx context.Context, key string, src io.Reader) error {
	pr, pw := io.Pipe()
	go func() {
		w, err := objstore.Seal(pw, g.cfg.Passphrase)
		if err == nil {
			var n int64
			n, err = io.Copy(w, src)
			g.in.Add(n)
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		pw.CloseWithError(err)
	}()
	_, err := g.cfg.Store.Put(ctx, key, pr)
	pr.CloseWithError(errors.New("stopped"))
	return err
}

func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/")
	b, key, _ := strings.Cut(path, "/")
	if b != bucket {
		s3err(w, 404, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	if key == "" && r.Method == http.MethodGet {
		g.list(w, r)
		return
	}
	if r.Method == http.MethodPost && q.Has("delete") {
		var req struct {
			Objects []struct {
				Key string `xml:"Key"`
			} `xml:"Object"`
		}
		_ = xml.NewDecoder(g.body(r)).Decode(&req)
		var out strings.Builder
		out.WriteString(`<?xml version="1.0" encoding="UTF-8"?><DeleteResult>`)
		for _, o := range req.Objects {
			if !g.allowed(o.Key) || g.cfg.ReadOnly {
				continue
			}
			_ = g.cfg.Store.Delete(ctx, o.Key)
			fmt.Fprintf(&out, "<Deleted><Key>%s</Key></Deleted>", xmlEsc(o.Key))
		}
		out.WriteString("</DeleteResult>")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, out.String())
		return
	}
	if !g.allowed(key) {
		g.cfg.Log.Warn("s3gw stand-in: refused", "method", r.Method, "key", key, "url", r.URL.String(), "prefixes", g.cfg.Prefixes)
		s3err(w, 403, "AccessDenied")
		return
	}
	write := r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete
	if write && g.cfg.ReadOnly {
		g.cfg.Log.Warn("s3gw stand-in: read-only", "method", r.Method, "key", key)
		s3err(w, 403, "AccessDenied")
		return
	}
	switch {
	case r.Method == http.MethodHead:
		n, ok, err := g.size(ctx, key)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("ETag", `"`+rnd(8)+`"`)
		w.WriteHeader(200)
	case r.Method == http.MethodGet:
		g.get(w, r, key)
	case r.Method == http.MethodPost && q.Has("uploads"):
		id := rnd(12)
		g.mu.Lock()
		g.uploads[id] = map[int]string{}
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, bucket, xmlEsc(key), id)
	case r.Method == http.MethodPut && q.Has("uploadId"):
		id := q.Get("uploadId")
		num, _ := strconv.Atoi(q.Get("partNumber"))
		g.mu.Lock()
		parts, ok := g.uploads[id]
		g.mu.Unlock()
		if !ok {
			s3err(w, 404, "NoSuchUpload")
			return
		}
		f, err := os.CreateTemp(g.tmp, "part-")
		if err != nil {
			s3err(w, 500, "InternalError")
			return
		}
		_, err = io.Copy(f, g.body(r))
		f.Close()
		if err != nil {
			s3err(w, 500, "InternalError")
			return
		}
		g.mu.Lock()
		parts[num] = f.Name()
		g.mu.Unlock()
		w.Header().Set("ETag", `"`+rnd(8)+`"`)
		w.WriteHeader(200)
	case r.Method == http.MethodPost && q.Has("uploadId"):
		id := q.Get("uploadId")
		g.mu.Lock()
		parts := g.uploads[id]
		delete(g.uploads, id)
		g.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		var nums []int
		for n := range parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var readers []io.Reader
		var files []*os.File
		for _, n := range nums {
			f, err := os.Open(parts[n])
			if err != nil {
				s3err(w, 500, "InternalError")
				return
			}
			files = append(files, f)
			readers = append(readers, f)
		}
		err := g.put(ctx, key, io.MultiReader(readers...))
		for _, f := range files {
			f.Close()
			os.Remove(f.Name())
		}
		if err != nil {
			s3err(w, 500, "InternalError")
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>"%s"</ETag></CompleteMultipartUploadResult>`, bucket, xmlEsc(key), rnd(8))
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		g.mu.Lock()
		for _, f := range g.uploads[q.Get("uploadId")] {
			os.Remove(f)
		}
		delete(g.uploads, q.Get("uploadId"))
		g.mu.Unlock()
		w.WriteHeader(204)
	case r.Method == http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			s3err(w, 501, "NotImplemented")
			return
		}
		if err := g.put(ctx, key, g.body(r)); err != nil {
			s3err(w, 500, "InternalError")
			return
		}
		w.Header().Set("ETag", `"`+rnd(8)+`"`)
		w.WriteHeader(200)
	case r.Method == http.MethodDelete:
		_ = g.cfg.Store.Delete(ctx, key)
		w.WriteHeader(204)
	default:
		s3err(w, 501, "NotImplemented")
	}
}

func (g *Gateway) get(w http.ResponseWriter, r *http.Request, key string) {
	ctx := r.Context()
	size, ok, err := g.size(ctx, key)
	if err != nil {
		s3err(w, 500, "InternalError")
		return
	}
	if !ok {
		s3err(w, 404, "NoSuchKey")
		return
	}
	rc, err := g.cfg.Store.Get(ctx, key)
	if err != nil {
		s3err(w, 500, "InternalError")
		return
	}
	defer rc.Close()
	pr, err := objstore.Open(rc, g.cfg.Passphrase)
	if err != nil {
		s3err(w, 500, "InternalError")
		return
	}
	start, end := int64(0), size-1
	status := 200
	if rg := r.Header.Get("Range"); strings.HasPrefix(rg, "bytes=") {
		a, b, _ := strings.Cut(strings.TrimPrefix(rg, "bytes="), "-")
		if a != "" {
			start, _ = strconv.ParseInt(a, 10, 64)
		}
		if b != "" {
			end, _ = strconv.ParseInt(b, 10, 64)
		}
		end = min(end, size-1)
		status = 206
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	}
	if _, err := io.CopyN(io.Discard, pr, start); err != nil && size > 0 {
		s3err(w, 500, "InternalError")
		return
	}
	n := max(end-start+1, 0)
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.Header().Set("ETag", `"`+rnd(8)+`"`)
	w.WriteHeader(status)
	m, _ := io.CopyN(w, pr, n)
	g.out.Add(m)
}

func (g *Gateway) list(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	objs, err := g.cfg.Store.List(r.Context(), prefix)
	if err != nil {
		s3err(w, 500, "InternalError")
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>%s</Name><Prefix>%s</Prefix><IsTruncated>false</IsTruncated><KeyCount>%d</KeyCount>`, bucket, xmlEsc(prefix), len(objs))
	for _, o := range objs {
		if !g.allowed(o.Key) {
			continue
		}
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><ETag>\"x\"</ETag><LastModified>%s</LastModified></Contents>", xmlEsc(o.Key), plainSize(o.Size), o.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	b.WriteString("</ListBucketResult>")
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, b.String())
}

func xmlEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var _ = filepath.Join
