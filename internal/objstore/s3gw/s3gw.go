// Package s3gw is the encrypting S3 gateway behind ClickHouse backups.
//
// ClickHouse backs up with its own BACKUP ... TO S3(url, key, secret) and
// restores with RESTORE ... FROM S3(...). For one task, the agent starts a
// Gateway and points ClickHouse at it: a short-lived S3-compatible HTTP
// server with random credentials of its own. Every object ClickHouse writes
// is sealed (objstore.Seal, with the passphrase only the server knows) and
// stored at the same key in the database's folder of the customer's bucket;
// every read is decrypted on the way back. ClickHouse never sees the bucket's
// credentials or the passphrase, and the bucket only ever holds ciphertext.
//
// How it works:
//
//   - Every request must carry an AWS Signature Version 4 (header form) made
//     with the gateway's credentials; signed, unsigned and aws-chunked
//     payloads are checked as S3 checks them. Keys must start with one of
//     Config.Prefixes and can't leave the Store's folder.
//   - Names in the bucket say when, never what (names.go). ClickHouse's
//     keys name databases and tables (backup/<label>/data/<db>/<table>/...),
//     so each object is stored under its folder (the Config.Prefixes entry
//     it falls in, e.g. backup/<label>/, in clear: labels are times) and
//     one opaque name, the rest of the key encrypted deterministically
//     (synthetic IV: HMAC nonce, AES-GCM, keys derived from the passphrase).
//     Listings decrypt the names and filter, sort and paginate ClickHouse's
//     keys; objects whose names don't decrypt (the agent's own files) are
//     not shown.
//   - Sizes ClickHouse sees are plaintext sizes. Sealed segments have a fixed
//     size, so the plaintext size follows from the stored size
//     (objstore.PlainSize) and nothing is stored next to an object.
//   - A file that doesn't decrypt (wrong passphrase, altered) is answered
//     403 AccessDenied, "the backup file <key> can't be decrypted: ...":
//     ClickHouse doesn't retry it, so a restore of a damaged backup fails
//     at once, in plain words.
//   - A ranged GET fetches and decrypts only the segments the range touches
//     (objstore.SealedRange, Store.GetRange, objstore.OpenAt).
//   - A PutObject streams through Seal into the bucket. ClickHouse gives up
//     on a first attempt after a few seconds and sends the object again, so
//     an upload whose body has fully arrived finishes without the client,
//     and the retry waits for it rather than storing the object twice.
//   - A multipart upload has to become one sealed stream, so each part is
//     kept in a private temporary directory, encrypted with a key that only
//     lives in memory, until the parts before it have arrived; a drainer
//     feeds the parts in order into one Seal and one upload to the bucket as
//     they become contiguous, so CompleteMultipartUpload only waits for the
//     tail. Answers to UploadPart are held back while too much is waiting to
//     be drained, which keeps that tail (and the temporary files) short.
//   - Close, or the end of the context given to Start, stops everything:
//     requests in flight are cut, unfinished uploads are abandoned (nothing
//     half-written becomes visible in the bucket), the temporary directory is
//     removed, and Close returns once every handler has.
package s3gw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Bucket is the bucket name ClickHouse sees (path style). The real bucket
// and folder are the Store's.
const Bucket = "rowsafe"

// Config is what a Gateway serves.
type Config struct {
	Store      *objstore.Store // the database's folder in the bucket; keys are relative to it
	Passphrase string          // seals every object
	Listen     string          // "" = "127.0.0.1:0"; Docker: ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN e.g. "0.0.0.0:9010"
	// PublicURL is the base URL ClickHouse uses; "" = "http://" + the
	// listening address. Without a port, the listening port is added
	// (e.g. "http://host.docker.internal" with Listen "0.0.0.0:0").
	PublicURL string
	Prefixes  []string // keys ClickHouse may touch must start with one of these (e.g. "backup/"); none: any key in the Store
	ReadOnly  bool     // restores: refuse PUT/POST/DELETE
	// TempDir holds multipart parts until they are stored (encrypted with
	// a key that only lives in memory); "" = os.TempDir().
	TempDir string
	Log     *slog.Logger
	// Virtual are read-only files served at these keys (virtual.go); the
	// keys must be inside Prefixes.
	Virtual map[string]VirtualFile
}

// Stats counts what went through a gateway.
type Stats struct {
	Requests       int64
	ObjectsWritten int64 // objects stored (PutObject, completed multipart uploads, copies)
	Multipart      int64 // of them, multipart uploads
	BytesWritten   int64 // plaintext received from ClickHouse
	StoredWritten  int64 // sealed bytes stored in the bucket
	ObjectsRead    int64 // GetObject answers
	RangedReads    int64 // of them, ranges
	BytesRead      int64 // plaintext sent to ClickHouse
	StoredRead     int64 // sealed bytes fetched from the bucket
	Deleted        int64
	Errors         int64  // requests answered with an error (refused ones included)
	LastError      string // the last of them, for logs and task notes
}

// Gateway is a running gateway.
type Gateway struct {
	cfg    Config
	log    *slog.Logger
	ln     net.Listener
	srv    *http.Server
	ctx    context.Context
	cancel context.CancelFunc
	public string // base URL, no trailing slash
	keyID  string
	secret string
	tmp    string // private directory for multipart parts
	tmpKey []byte // encrypts the parts there

	mu      sync.Mutex
	closing bool
	uploads map[string]*upload
	puts    map[string]*pendingPut
	wg      sync.WaitGroup // handlers and drainers
	served  chan error

	heads  headCache
	names  *names
	sealed *objstore.SealedReader

	requests, objectsWritten, bytesWritten, storedWritten atomic.Int64
	objectsRead, bytesRead, storedRead, deleted, errs     atomic.Int64
	multipart, rangedReads                                atomic.Int64
	lastErr                                               atomic.Value // string

	closeOnce sync.Once
	closeErr  error
}

// Start listens and serves until Close or the end of ctx.
func Start(ctx context.Context, cfg Config) (*Gateway, error) {
	if cfg.Store == nil {
		return nil, errors.New("the backup gateway needs a storage folder")
	}
	if cfg.Passphrase == "" {
		return nil, errors.New("no encryption passphrase (ROWSAFE_REPO_CIPHER_PASS)")
	}
	for _, p := range cfg.Prefixes {
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return nil, fmt.Errorf("backup gateway: invalid key prefix %q", p)
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if cfg.TempDir == "" {
		cfg.TempDir = os.TempDir()
	}
	tmp, err := os.MkdirTemp(cfg.TempDir, "rowsafe-s3gw-")
	if err != nil {
		return nil, fmt.Errorf("backup gateway: temporary folder: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("backup gateway: can't listen on %s: %w", cfg.Listen, err)
	}
	public, err := publicURL(cfg.PublicURL, ln.Addr().(*net.TCPAddr))
	if err != nil {
		ln.Close()
		os.RemoveAll(tmp)
		return nil, err
	}
	nm, err := newNames(cfg.Passphrase)
	if err != nil {
		ln.Close()
		os.RemoveAll(tmp)
		return nil, err
	}
	gctx, cancel := context.WithCancel(ctx)
	g := &Gateway{
		cfg: cfg, log: cfg.Log, ln: ln, ctx: gctx, cancel: cancel, public: public,
		keyID: "RS" + strings.ToUpper(randHex(9)), secret: randHex(20), tmp: tmp, tmpKey: randBytes(32),
		uploads: map[string]*upload{}, puts: map[string]*pendingPut{}, served: make(chan error, 1),
	}
	g.heads.m = map[string]headEntry{}
	g.names = nm
	g.sealed = &objstore.SealedReader{Store: cfg.Store, Passphrase: cfg.Passphrase}
	g.srv = &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return gctx },
		ErrorLog:          slog.NewLogLogger(cfg.Log.Handler(), slog.LevelDebug),
	}
	go func() { g.served <- g.srv.Serve(ln) }()
	// The end of ctx stops the gateway as Close does.
	context.AfterFunc(gctx, func() { g.srv.Close() })
	g.log.Debug("backup gateway listening", "address", ln.Addr().String(), "url", public)
	return g, nil
}

func publicURL(pub string, addr *net.TCPAddr) (string, error) {
	port := strconv.Itoa(addr.Port)
	if pub == "" {
		return "http://" + net.JoinHostPort(addr.IP.String(), port), nil
	}
	u, err := url.Parse(strings.TrimRight(pub, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("backup gateway: invalid public URL %q", pub)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	return u.String(), nil
}

// Endpoint is the S3 URL for ClickHouse of key (relative to the Store), in
// path style: <PublicURL>/<Bucket>/<key>.
func (g *Gateway) Endpoint(key string) string {
	return g.public + "/" + Bucket + "/" + encodePath(strings.TrimLeft(key, "/"))
}

// AccessKeyID is the gateway's access key (random per gateway).
func (g *Gateway) AccessKeyID() string { return g.keyID }

// SecretAccessKey is the gateway's secret key (random per gateway).
func (g *Gateway) SecretAccessKey() string { return g.secret }

// Addr is the listening address.
func (g *Gateway) Addr() string { return g.ln.Addr().String() }

// Stats returns the counters so far.
func (g *Gateway) Stats() Stats {
	s := Stats{
		Requests: g.requests.Load(), ObjectsWritten: g.objectsWritten.Load(), BytesWritten: g.bytesWritten.Load(),
		StoredWritten: g.storedWritten.Load(), ObjectsRead: g.objectsRead.Load(), BytesRead: g.bytesRead.Load(),
		StoredRead: g.storedRead.Load(), Deleted: g.deleted.Load(), Errors: g.errs.Load(),
		Multipart: g.multipart.Load(), RangedReads: g.rangedReads.Load(),
	}
	s.LastError, _ = g.lastErr.Load().(string)
	return s
}

// Close stops the gateway: requests in flight are cut, unfinished multipart
// uploads are abandoned, and it returns once every handler has.
func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closing = true
		g.mu.Unlock()
		g.cancel()
		g.srv.Close()
		g.wg.Wait()
		if err := <-g.served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.closeErr = err
		}
		if err := os.RemoveAll(g.tmp); err != nil && g.closeErr == nil {
			g.closeErr = err
		}
	})
	return g.closeErr
}

// enter registers a handler, unless the gateway is closing.
func (g *Gateway) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return false
	}
	g.wg.Add(1)
	return true
}

// s3Error is an S3 error answer.
type s3Error struct {
	status  int
	code    string
	message string
}

func (e *s3Error) Error() string { return e.code + ": " + e.message }

func errf(status int, code, format string, args ...any) *s3Error {
	return &s3Error{status: status, code: code, message: fmt.Sprintf(format, args...)}
}

func accessDenied(format string, args ...any) *s3Error {
	return errf(http.StatusForbidden, "AccessDenied", format, args...)
}

// statusWriter remembers whether the answer has started.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// request is one request being served.
type request struct {
	w     *statusWriter
	r     *http.Request
	key   string // "" for bucket requests
	id    string
	sig   *signature
	start time.Time
}

func (g *Gateway) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if !g.enter() {
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer g.wg.Done()
	g.requests.Add(1)
	q := &request{w: &statusWriter{ResponseWriter: rw}, r: r, id: strings.ToUpper(randHex(8)), start: time.Now()}
	q.w.Header().Set("x-amz-request-id", q.id)
	q.w.Header().Set("Server", "Rowsafe")
	err := g.serve(q)
	if err != nil {
		g.fail(q, err)
	}
	g.log.Debug("backup gateway request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery,
		"range", r.Header.Get("Range"), "status", q.w.status, "duration", time.Since(q.start).Round(time.Millisecond))
}

func (g *Gateway) serve(q *request) error {
	r := q.r
	sig, err := g.authenticate(r)
	if err != nil {
		return err
	}
	q.sig = sig
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	if bucket != Bucket {
		return errf(http.StatusNotFound, "NoSuchBucket", "the bucket %q does not exist", bucket)
	}
	query := r.URL.Query()
	write := r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete
	if write && g.cfg.ReadOnly {
		return accessDenied("this gateway only reads (a restore)")
	}
	if key == "" {
		switch {
		case r.Method == http.MethodHead:
			q.w.WriteHeader(http.StatusOK)
			return nil
		case r.Method == http.MethodGet && query.Has("location"):
			return writeXML(q.w, http.StatusOK, locationConstraint{})
		case r.Method == http.MethodGet && !hasAny(query, "uploads", "versions", "acl", "policy", "lifecycle", "versioning"):
			return g.list(q, query)
		case r.Method == http.MethodPost && query.Has("delete"):
			return g.deleteObjects(q)
		}
		return errf(http.StatusNotImplemented, "NotImplemented", "%s on the bucket is not supported by the backup gateway", r.Method)
	}
	if err := g.checkKey(key); err != nil {
		return err
	}
	if v, ok := g.virtual(key); ok {
		q.key = key
		return g.serveVirtual(q, v)
	}
	if write {
		if err := g.checkStoredLen(key); err != nil {
			return err
		}
	}
	q.key = key
	uploadID := query.Get("uploadId")
	switch r.Method {
	case http.MethodHead:
		return g.headObject(q)
	case http.MethodGet:
		if uploadID != "" || hasAny(query, "acl", "tagging", "attributes", "torrent") {
			break
		}
		return g.getObject(q)
	case http.MethodPut:
		switch {
		case uploadID != "" && r.Header.Get("x-amz-copy-source") == "":
			return g.uploadPart(q, uploadID, query.Get("partNumber"))
		case uploadID != "":
			// UploadPartCopy: ClickHouse only copies server side between
			// S3 disks, never from a backup.
		case r.Header.Get("x-amz-copy-source") != "":
			return g.copyObject(q)
		case hasAny(query, "acl", "tagging"):
		default:
			return g.putObject(q)
		}
	case http.MethodPost:
		switch {
		case query.Has("uploads"):
			return g.createUpload(q)
		case uploadID != "":
			return g.completeUpload(q, uploadID)
		}
	case http.MethodDelete:
		if uploadID != "" {
			return g.abortUpload(q, uploadID)
		}
		return g.deleteObject(q)
	}
	return errf(http.StatusNotImplemented, "NotImplemented", "%s %s is not supported by the backup gateway", r.Method, r.URL.RawQuery)
}

func hasAny(q url.Values, names ...string) bool {
	for _, n := range names {
		if q.Has(n) {
			return true
		}
	}
	return false
}

// checkKey keeps ClickHouse inside its prefixes of the Store's folder.
func (g *Gateway) checkKey(key string) error {
	if len(key) > 1024 {
		return errf(http.StatusBadRequest, "KeyTooLongError", "the key is longer than 1024 bytes")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return accessDenied("invalid key %q", key)
		}
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] == 0x7f || key[i] == '\\' {
			return accessDenied("invalid key %q", key)
		}
	}
	if !g.allowed(key) {
		return accessDenied("the key %q is outside the folders this gateway serves", key)
	}
	return nil
}

// maxStoredKey is S3's limit on a key.
const maxStoredKey = 1024

// checkStoredLen refuses, before anything is sent, a key whose stored name
// (encrypted, which makes it longer, under the bucket's folder) is over S3's
// limit: the bucket would refuse it on every retry.
func (g *Gateway) checkStoredLen(key string) error {
	if n := len(g.cfg.Store.FullKey(g.stored(key))); n > maxStoredKey {
		if len(key) > 120 {
			key = key[:60] + "..." + key[len(key)-40:]
		}
		return errf(http.StatusBadRequest, "KeyTooLongError", "the file name %q is too long to store: encrypted and in your "+
			"bucket's folder it would be %d bytes, over the 1,024 bytes S3 allows (shorter database or table names, or a shorter "+
			"bucket path, fix it)", key, n)
	}
	return nil
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

// fail answers with err (an *s3Error, or an internal error), unless the
// answer has started, and logs it.
func (g *Gateway) fail(q *request, err error) {
	var se *s3Error
	switch {
	case errors.As(err, &se):
	case errors.Is(err, objstore.ErrNotFound):
		se = errf(http.StatusNotFound, "NoSuchKey", "the key %q does not exist", q.key)
	case g.ctx.Err() != nil:
		se = errf(http.StatusServiceUnavailable, "ServiceUnavailable", "the backup gateway is stopping")
	case q.r.Context().Err() != nil:
		// ClickHouse gave up waiting (it retries): not an error of ours.
		g.log.Debug("backup gateway: the client closed the connection", "method", q.r.Method, "path", q.r.URL.Path,
			"query", q.r.URL.RawQuery, "after", time.Since(q.start).Round(time.Millisecond))
		return
	default:
		se = errf(http.StatusInternalServerError, "InternalError", "%v", err)
	}
	expected := se.code == "NoSuchKey" && (q.r.Method == http.MethodHead || q.r.Method == http.MethodGet) ||
		se.code == "NoSuchUpload" && q.r.Method == http.MethodDelete
	if !expected {
		g.errs.Add(1)
		msg := fmt.Sprintf("%s %s: %s", q.r.Method, q.r.URL.Path, se.Error())
		g.lastErr.Store(msg)
		level := slog.LevelWarn
		if se.status >= 500 {
			level = slog.LevelError
		}
		g.log.Log(q.r.Context(), level, "backup gateway: "+se.message, "method", q.r.Method, "path", q.r.URL.Path,
			"query", q.r.URL.RawQuery, "code", se.code, "status", se.status)
	}
	if q.w.status != 0 {
		// The answer has started: cut the connection so the client sees
		// a failure rather than a short or corrupted object.
		panic(http.ErrAbortHandler)
	}
	if q.r.Method == http.MethodHead {
		q.w.WriteHeader(se.status)
		return
	}
	_ = writeXML(q.w, se.status, errorDoc{Code: se.code, Message: se.message, Key: q.key, RequestID: q.id})
}

type errorDoc struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Key       string   `xml:"Key,omitempty"`
	RequestID string   `xml:"RequestId"`
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
}

func writeXML(w http.ResponseWriter, status int, v any) error {
	b, err := xml.Marshal(v)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(xml.Header)+len(b)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(b)
	return nil
}

// encodePath percent-encodes every byte except unreserved characters and
// '/', as SigV4 wants.
func encodePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' || unreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func encodeComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if unreserved(s[i]) {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }

// headCache keeps the headers and stored sizes of objects recently read,
// so a ranged read past the first segment takes one request to the bucket.
type headCache struct {
	mu  sync.Mutex
	m   map[string]headEntry
	gen uint64 // bumped by every write, so a read can't cache a stale entry
}

type headEntry struct {
	header []byte
	size   int64
}

func (c *headCache) get(key string) (headEntry, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	return e, c.gen, ok
}

func (c *headCache) put(key string, e headEntry, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if len(c.m) >= 4096 {
		clear(c.m)
	}
	c.m[key] = e
}

func (c *headCache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.m, key)
}
