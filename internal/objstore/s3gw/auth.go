package s3gw

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Content-MD5 and ETags are MD5 by definition, not for security
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWS Signature Version 4, as S3 checks it, for the header form only
// (ClickHouse never presigns): the Authorization header signs the method,
// path, query, the headers it lists and the payload's SHA-256, which is
// either in x-amz-content-sha256, UNSIGNED-PAYLOAD, or aws-chunked
// (STREAMING-*) with a signature per chunk.

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	maxSkew      = 15 * time.Minute
	emptySHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signature is a verified request signature, which aws-chunked payloads
// chain from.
type signature struct {
	key     []byte // signing key
	amzDate string
	scope   string
	value   string
}

func (g *Gateway) authenticate(r *http.Request) (*signature, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		if r.URL.Query().Has("X-Amz-Signature") {
			return nil, accessDenied("presigned URLs are not accepted by the backup gateway")
		}
		return nil, accessDenied("anonymous requests are not accepted by the backup gateway")
	}
	alg, rest, _ := strings.Cut(auth, " ")
	if alg != sigAlgorithm {
		return nil, errf(http.StatusBadRequest, "InvalidRequest", "unsupported authorization %q (only AWS Signature Version 4)", alg)
	}
	fields := map[string]string{}
	for _, f := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(f), "=")
		fields[k] = v
	}
	cred := strings.Split(fields["Credential"], "/")
	signedHeaders := fields["SignedHeaders"]
	given := fields["Signature"]
	if len(cred) != 5 || signedHeaders == "" || given == "" {
		return nil, errf(http.StatusBadRequest, "AuthorizationHeaderMalformed", "the authorization header is malformed")
	}
	if !subtleEq(cred[0], g.keyID) {
		return nil, errf(http.StatusForbidden, "InvalidAccessKeyId", "unknown access key")
	}
	date, region, service := cred[1], cred[2], cred[3]
	if service != "s3" || cred[4] != "aws4_request" {
		return nil, errf(http.StatusBadRequest, "AuthorizationHeaderMalformed", "the credential scope is not for S3")
	}
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return nil, accessDenied("the request has no x-amz-date")
	}
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil || !strings.HasPrefix(amzDate, date) {
		return nil, accessDenied("invalid x-amz-date %q", amzDate)
	}
	if d := time.Since(t); d > maxSkew || d < -maxSkew {
		return nil, errf(http.StatusForbidden, "RequestTimeTooSkewed", "the request time is %s away from the gateway's clock", d.Round(time.Second))
	}
	payload := r.Header.Get("x-amz-content-sha256")
	if payload == "" {
		return nil, errf(http.StatusBadRequest, "InvalidRequest", "the request has no x-amz-content-sha256")
	}
	names := strings.Split(signedHeaders, ";")
	if !sort.StringsAreSorted(names) || !contains(names, "host") {
		return nil, errf(http.StatusBadRequest, "AuthorizationHeaderMalformed", "invalid signed headers")
	}
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + headerValue(r, n) + "\n")
	}
	scope := date + "/" + region + "/s3/aws4_request"
	k := hmacSHA256([]byte("AWS4"+g.secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	query := canonicalQuery(r.URL.RawQuery)
	// The path as the client encoded it: SigV4's encoding of the decoded
	// path, or (some clients) the path as sent.
	paths := []string{encodePath(r.URL.Path)}
	if p := r.URL.EscapedPath(); p != paths[0] {
		paths = append(paths, p)
	}
	for _, p := range paths {
		creq := strings.Join([]string{r.Method, p, query, ch.String(), signedHeaders, payload}, "\n")
		sum := sha256.Sum256([]byte(creq))
		sts := sigAlgorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
		want := hex.EncodeToString(hmacSHA256(k, sts))
		if hmac.Equal([]byte(want), []byte(given)) {
			return &signature{key: k, amzDate: amzDate, scope: scope, value: want}, nil
		}
	}
	return nil, errf(http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match (wrong secret key?)")
}

func subtleEq(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// headerValue is a header's canonical value: values joined with commas,
// trimmed, inner spaces collapsed.
func headerValue(r *http.Request, name string) string {
	var vals []string
	switch name {
	case "host":
		vals = []string{r.Host}
	case "content-length":
		vals = r.Header.Values("Content-Length")
		if len(vals) == 0 && r.ContentLength >= 0 {
			vals = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
	case "transfer-encoding":
		vals = r.TransferEncoding
	default:
		vals = r.Header.Values(name)
	}
	for i, v := range vals {
		vals[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(vals, ",")
}

func canonicalQuery(raw string) string {
	type kv struct{ k, v string }
	var parts []kv
	for _, p := range strings.Split(raw, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			dk, dv = k, v
		}
		parts = append(parts, kv{encodeComponent(dk), encodeComponent(dv)})
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].k != parts[j].k {
			return parts[i].k < parts[j].k
		}
		return parts[i].v < parts[j].v
	})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// body is a request's payload, checked as it is read: the payload hash
// (or the chunk signatures), Content-MD5 and the length. It fails with an
// *s3Error when a check fails, at the latest at the end, so whatever the
// payload was going into must not be kept unless it reads to EOF.
type body struct {
	r      io.Reader
	md5    hash.Hash // of the payload, for the ETag and Content-MD5
	sha    hash.Hash // when x-amz-content-sha256 is a hash
	want   string    // that hash
	md5Arg []byte    // Content-MD5
	length int64     // expected payload length, -1 if unknown
	n      int64
	err    error
}

func (q *request) body() (*body, error) {
	r := q.r
	b := &body{md5: md5.New(), length: r.ContentLength} //nolint:gosec // see the import
	if cm := r.Header.Get("Content-MD5"); cm != "" {
		sum, err := base64.StdEncoding.DecodeString(cm)
		if err != nil || len(sum) != md5.Size {
			return nil, errf(http.StatusBadRequest, "InvalidDigest", "the Content-MD5 is not valid")
		}
		b.md5Arg = sum
	}
	payload := r.Header.Get("x-amz-content-sha256")
	switch payload {
	case "UNSIGNED-PAYLOAD":
		b.r = r.Body
	case "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
		dl, err := strconv.ParseInt(r.Header.Get("x-amz-decoded-content-length"), 10, 64)
		if err != nil || dl < 0 {
			return nil, errf(http.StatusLengthRequired, "MissingContentLength", "aws-chunked uploads need x-amz-decoded-content-length")
		}
		b.length = dl
		b.r = &chunkedReader{r: bufio.NewReaderSize(r.Body, 64<<10), sig: q.sig, prev: q.sig.value,
			signed: payload != "STREAMING-UNSIGNED-PAYLOAD-TRAILER", trailer: strings.HasSuffix(payload, "TRAILER"), h: sha256.New()}
	default:
		if len(payload) != 64 {
			return nil, errf(http.StatusBadRequest, "InvalidArgument", "unsupported x-amz-content-sha256 %q", payload)
		}
		b.r = r.Body
		b.sha = sha256.New()
		b.want = strings.ToLower(payload)
	}
	return b, nil
}

func (b *body) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.r.Read(p)
	if n > 0 {
		b.md5.Write(p[:n])
		if b.sha != nil {
			b.sha.Write(p[:n])
		}
		b.n += int64(n)
	}
	if err == io.EOF {
		err = b.finish()
	}
	if err != nil {
		b.err = err
	}
	return n, err
}

func (b *body) finish() error {
	if b.length >= 0 && b.n != b.length {
		return errf(http.StatusBadRequest, "IncompleteBody", "the payload has %d bytes, %d were announced", b.n, b.length)
	}
	if b.sha != nil && hex.EncodeToString(b.sha.Sum(nil)) != b.want {
		return errf(http.StatusBadRequest, "XAmzContentSHA256Mismatch", "the payload does not match its x-amz-content-sha256")
	}
	if b.md5Arg != nil && !bytes.Equal(b.md5.Sum(nil), b.md5Arg) {
		return errf(http.StatusBadRequest, "BadDigest", "the payload does not match its Content-MD5")
	}
	return io.EOF
}

// etag is the payload's ETag (its MD5, quoted), once read.
func (b *body) etag() string { return `"` + hex.EncodeToString(b.md5.Sum(nil)) + `"` }

var errChunk = errf(http.StatusBadRequest, "IncompleteBody", "the aws-chunked payload is malformed")

// chunkedReader decodes an aws-chunked payload:
//
//	hex-size[;chunk-signature=sig]\r\n data \r\n ... 0[;chunk-signature=sig]\r\n [trailers \r\n] \r\n
//
// checking each chunk's signature (chained from the request's) and the
// trailer's.
type chunkedReader struct {
	r       *bufio.Reader
	sig     *signature
	prev    string
	signed  bool
	trailer bool
	h       hash.Hash // of the current chunk
	left    int64     // bytes left in the current chunk
	chunkSg string    // the current chunk's signature
	inChunk bool
	done    bool
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.left == 0 {
		if c.done {
			return 0, io.EOF
		}
		if c.inChunk {
			if err := c.endChunk(); err != nil {
				return 0, err
			}
		}
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
	}
	n, err := c.r.Read(p[:min(int64(len(p)), c.left)])
	c.left -= int64(n)
	c.h.Write(p[:n])
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (c *chunkedReader) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return "", errChunk
		}
		return "", err
	}
	if len(line) > 4096 {
		return "", errChunk
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *chunkedReader) checkChunk() error {
	if !c.signed {
		return nil
	}
	sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.sig.amzDate + "\n" + c.sig.scope + "\n" + c.prev + "\n" + emptySHA256 + "\n" +
		hex.EncodeToString(c.h.Sum(nil))
	want := hex.EncodeToString(hmacSHA256(c.sig.key, sts))
	if !hmac.Equal([]byte(want), []byte(c.chunkSg)) {
		return errf(http.StatusForbidden, "SignatureDoesNotMatch", "a chunk signature does not match")
	}
	c.prev = want
	return nil
}

// endChunk checks the chunk just read and the CRLF after it.
func (c *chunkedReader) endChunk() error {
	if line, err := c.readLine(); err != nil || line != "" {
		return errChunk
	}
	c.inChunk = false
	return c.checkChunk()
}

func (c *chunkedReader) nextChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	size, ext, _ := strings.Cut(line, ";")
	n, err := strconv.ParseInt(size, 16, 64)
	if err != nil || n < 0 {
		return errChunk
	}
	c.chunkSg = ""
	if c.signed {
		sg, ok := strings.CutPrefix(ext, "chunk-signature=")
		if !ok {
			return errf(http.StatusForbidden, "SignatureDoesNotMatch", "a chunk has no signature")
		}
		c.chunkSg = sg
	}
	c.h.Reset()
	if n > 0 {
		c.left, c.inChunk = n, true
		return nil
	}
	// The final, empty chunk.
	if err := c.checkChunk(); err != nil {
		return err
	}
	if c.trailer {
		if err := c.readTrailer(); err != nil {
			return err
		}
	} else if line, err := c.readLine(); err != nil || line != "" {
		return errChunk
	}
	c.done = true
	return nil
}

// readTrailer reads the trailing headers (checksums the gateway doesn't
// need: every stored segment is authenticated) and checks the trailer
// signature of a signed payload.
func (c *chunkedReader) readTrailer() error {
	var trailers strings.Builder
	trailerSig := ""
	for {
		line, err := c.readLine()
		if err != nil {
			return err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return errChunk
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "x-amz-trailer-signature" {
			trailerSig = strings.TrimSpace(value)
			continue
		}
		trailers.WriteString(name + ":" + strings.TrimSpace(value) + "\n")
	}
	if !c.signed {
		return nil
	}
	sum := sha256.Sum256([]byte(trailers.String()))
	sts := "AWS4-HMAC-SHA256-TRAILER\n" + c.sig.amzDate + "\n" + c.sig.scope + "\n" + c.prev + "\n" + hex.EncodeToString(sum[:])
	want := hex.EncodeToString(hmacSHA256(c.sig.key, sts))
	if !hmac.Equal([]byte(want), []byte(trailerSig)) {
		return errf(http.StatusForbidden, "SignatureDoesNotMatch", "the trailer signature does not match")
	}
	return nil
}

// errBodyTooLarge guards bodies read whole (XML documents).
var errBodyTooLarge = errors.New("request body too large")

func readSmall(b io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(b, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBodyTooLarge
	}
	return data, nil
}
