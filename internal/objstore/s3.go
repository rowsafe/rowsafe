// Package objstore is a small S3 client (AWS Signature Version 4, path or
// virtual-host style, multipart uploads) for engines whose backups Rowsafe
// writes itself rather than through pgBackRest. Together with Seal/Open it
// keeps the promise PostgreSQL's pgBackRest keeps: everything is encrypted on
// the server, with the passphrase that never leaves it, before it is sent.
package objstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// Store is an S3-compatible bucket, under a path prefix.
type Store struct {
	endpoint string // host[:port]
	bucket   string
	region   string
	key      string
	secret   string
	hostPath bool   // virtual-host style
	prefix   string // "" or "a/b" (no leading or trailing slash)
	http     *http.Client
	scheme   string // "" is https
	now      func() time.Time
	// PartSize is the first multipart part size (tests shrink it; at least
	// 5 MiB against real S3).
	PartSize int
}

// Object is one listed object.
type Object struct {
	Key          string // relative to the store's prefix
	Size         int64
	LastModified time.Time
}

// ErrNotFound is returned by Get for a missing key.
var ErrNotFound = errors.New("object not found")

// New returns a Store for repo, rooted at repo.PathPrefix plus sub (e.g.
// the stanza). It validates nothing beyond what it needs to build requests.
func New(repo pgbackrest.Repo, sub string) (*Store, error) {
	if repo.Endpoint == "" || repo.Bucket == "" || repo.Key == "" || repo.KeySecret == "" {
		return nil, errors.New("backup storage is not configured")
	}
	// "http://" is only for local test servers; everything real is https.
	scheme := ""
	if strings.HasPrefix(repo.Endpoint, "http://") {
		scheme = "http"
	}
	endpoint := strings.TrimPrefix(strings.TrimPrefix(repo.Endpoint, "https://"), "http://")
	endpoint = strings.TrimRight(endpoint, "/")
	if repo.Port != 0 && repo.Port != 443 {
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			endpoint = h
		}
		endpoint = net.JoinHostPort(endpoint, strconv.Itoa(repo.Port))
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if repo.CAFile != "" {
		pem, err := os.ReadFile(repo.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading the storage CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", repo.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	if repo.SkipTLSVerify {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // only for throwaway test repositories (ROWSAFE_REPO_S3_VERIFY_TLS=false)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	tr.ResponseHeaderTimeout = 2 * time.Minute
	region := repo.Region
	if region == "" {
		region = "auto"
	}
	prefix := strings.Trim(strings.Trim(repo.PathPrefix, "/")+"/"+strings.Trim(sub, "/"), "/")
	return &Store{
		endpoint: endpoint, bucket: repo.Bucket, region: region, key: repo.Key, secret: repo.KeySecret,
		hostPath: repo.URIStyle == "host", prefix: prefix,
		http: &http.Client{Transport: tr}, scheme: scheme, now: time.Now, PartSize: 16 << 20,
	}, nil
}

// SetHTTPClient replaces the HTTP client (tests).
func (s *Store) SetHTTPClient(c *http.Client) { s.http = c }

// SetScheme is for tests against a plain-HTTP server: "http" or "https".
func (s *Store) SetScheme(scheme string) { s.scheme = scheme }

func (s *Store) fullKey(key string) string {
	key = strings.TrimLeft(key, "/")
	if s.prefix == "" {
		return key
	}
	return s.prefix + "/" + key
}

func (s *Store) url(fullKey string, q url.Values) *url.URL {
	scheme := "https"
	if s.scheme != "" {
		scheme = s.scheme
	}
	u := &url.URL{Scheme: scheme}
	if s.hostPath {
		u.Host = s.bucket + "." + s.endpoint
		u.Path = "/" + fullKey
	} else {
		u.Host = s.endpoint
		u.Path = "/" + s.bucket
		if fullKey != "" {
			u.Path += "/" + fullKey
		}
	}
	u.RawPath = encodePath(u.Path)
	if q != nil {
		u.RawQuery = canonicalQuery(q)
	}
	return u
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

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
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

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, encodeComponent(k)+"="+encodeComponent(v))
		}
	}
	return strings.Join(parts, "&")
}

var emptySHA256 = hex.EncodeToString(sha256.New().Sum(nil))

// sign adds SigV4 headers to req; payloadHash is the hex SHA-256 of the body.
func (s *Store) sign(req *http.Request, payloadHash string) {
	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	host := req.URL.Host
	req.Host = host

	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "content-md5" {
			names = append(names, lk)
		}
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		v := host
		if n != "host" {
			v = strings.TrimSpace(req.Header.Get(n))
		}
		ch.WriteString(n + ":" + v + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, ch.String(), signed, payloadHash}, "\n")
	scope := date + "/" + s.region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	k := hmacSHA256([]byte("AWS4"+s.secret), date)
	k = hmacSHA256(k, s.region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.key+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// S3Error is an error answer from the storage.
type S3Error struct {
	Status  int
	Code    string
	Message string
	Op      string
}

func (e *S3Error) Error() string {
	msg := e.Code
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("storage %s: HTTP %d %s", e.Op, e.Status, msg)
}

func readS3Error(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var x struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(body, &x)
	return &S3Error{Status: resp.StatusCode, Code: x.Code, Message: x.Message, Op: op}
}

func retryable(err error) bool {
	var se *S3Error
	if errors.As(err, &se) {
		return se.Status >= 500 || se.Status == http.StatusTooManyRequests
	}
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// do sends a request with a fully buffered body (nil for none), retrying
// transient failures. The caller closes the response body.
func (s *Store) do(ctx context.Context, op, method string, u *url.URL, body []byte, header http.Header, want ...int) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			}
		}
		var rd io.Reader
		hash := emptySHA256
		if body != nil {
			rd = bytes.NewReader(body)
			sum := sha256.Sum256(body)
			hash = hex.EncodeToString(sum[:])
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return nil, err
		}
		req.URL = u
		for k, vs := range header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if body != nil {
			req.ContentLength = int64(len(body))
		}
		s.sign(req, hash)
		resp, err := s.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("storage %s: %w", op, err)
			if ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}
		for _, w := range want {
			if resp.StatusCode == w {
				return resp, nil
			}
		}
		lastErr = readS3Error(op, resp)
		resp.Body.Close()
		if !retryable(lastErr) {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// PutBytes stores a small object.
func (s *Store) PutBytes(ctx context.Context, key string, data []byte) error {
	resp, err := s.do(ctx, "upload "+key, http.MethodPut, s.url(s.fullKey(key), nil), data, nil, http.StatusOK)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Put streams r into key, as one request when it is small and as a
// multipart upload otherwise. It returns the bytes stored.
func (s *Store) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	partSize := max(s.PartSize, 1<<10)
	first := make([]byte, partSize)
	n, err := io.ReadFull(r, first)
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		return int64(n), s.PutBytes(ctx, key, first[:n])
	case err != nil:
		return 0, err
	}
	full := s.fullKey(key)
	resp, err := s.do(ctx, "start upload "+key, http.MethodPost, s.url(full, url.Values{"uploads": {""}}), []byte{}, nil, http.StatusOK)
	if err != nil {
		return 0, err
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&init)
	resp.Body.Close()
	if err != nil || init.UploadID == "" {
		return 0, fmt.Errorf("storage start upload %s: no upload id (%v)", key, err)
	}
	abort := func() {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if resp, err := s.do(actx, "abort upload", http.MethodDelete, s.url(full, url.Values{"uploadId": {init.UploadID}}), nil, nil,
			http.StatusNoContent, http.StatusOK); err == nil {
			resp.Body.Close()
		}
	}
	type part struct {
		XMLName    xml.Name `xml:"Part"`
		PartNumber int      `xml:"PartNumber"`
		ETag       string   `xml:"ETag"`
	}
	var parts []part
	var total int64
	buf := first[:n]
	for num := 1; ; num++ {
		q := url.Values{"partNumber": {strconv.Itoa(num)}, "uploadId": {init.UploadID}}
		resp, err := s.do(ctx, fmt.Sprintf("upload part %d of %s", num, key), http.MethodPut, s.url(full, q), buf, nil, http.StatusOK)
		if err != nil {
			abort()
			return total, err
		}
		etag := resp.Header.Get("ETag")
		resp.Body.Close()
		parts = append(parts, part{PartNumber: num, ETag: etag})
		total += int64(len(buf))
		if num == 10000 {
			abort()
			return total, errors.New("storage: object too large (10,000 parts)")
		}
		// Parts grow so a huge dump still fits in S3's 10,000 parts.
		size := partSize
		for i := 1000; i <= num && size < 512<<20; i += 1000 {
			size *= 2
		}
		if cap(first) < size {
			first = make([]byte, size)
		}
		buf = first[:size]
		m, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			abort()
			return total, err
		}
		buf = buf[:m]
		if err == io.ErrUnexpectedEOF && m == 0 {
			break
		}
	}
	var cmu bytes.Buffer
	cmu.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		b, _ := xml.Marshal(p)
		cmu.Write(b)
	}
	cmu.WriteString("</CompleteMultipartUpload>")
	resp, err = s.do(ctx, "finish upload "+key, http.MethodPost, s.url(full, url.Values{"uploadId": {init.UploadID}}), cmu.Bytes(),
		http.Header{"Content-Type": {"application/xml"}}, http.StatusOK)
	if err != nil {
		abort()
		return total, err
	}
	// S3 can answer 200 with an error document.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if bytes.Contains(body, []byte("<Error>")) {
		abort()
		var x struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		_ = xml.Unmarshal(body, &x)
		return total, &S3Error{Status: 200, Code: x.Code, Message: x.Message, Op: "finish upload " + key}
	}
	return total, nil
}

// Get opens key for reading. The caller closes it.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.do(ctx, "download "+key, http.MethodGet, s.url(s.fullKey(key), nil), nil, nil, http.StatusOK)
	if err != nil {
		var se *S3Error
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return resp.Body, nil
}

// GetBytes reads a whole (small) object.
func (s *Store) GetBytes(ctx context.Context, key string) ([]byte, error) {
	rc, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 64<<20))
}

// Delete removes key (a missing key is not an error).
func (s *Store) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, "delete "+key, http.MethodDelete, s.url(s.fullKey(key), nil), nil, nil,
		http.StatusNoContent, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// List returns every object under prefix (relative to the store), in key
// order.
func (s *Store) List(ctx context.Context, prefix string) ([]Object, error) {
	full := s.fullKey(prefix)
	var out []Object
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {full}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, "list "+prefix, http.MethodGet, s.url("", q), nil, nil, http.StatusOK)
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct {
				Key          string `xml:"Key"`
				Size         int64  `xml:"Size"`
				LastModified string `xml:"LastModified"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("storage list %s: %w", prefix, err)
		}
		strip := ""
		if s.prefix != "" {
			strip = s.prefix + "/"
		}
		for _, c := range res.Contents {
			t, _ := time.Parse(time.RFC3339Nano, c.LastModified)
			out = append(out, Object{Key: strings.TrimPrefix(c.Key, strip), Size: c.Size, LastModified: t})
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		token = res.NextContinuationToken
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
