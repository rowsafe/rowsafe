package s3gw

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // test ETags
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

const testPass = "gateway test passphrase 1234567"

// marker is plaintext that must never reach the bucket.
var marker = []byte("PLAINTEXT-MARKER-0123456789")

type env struct {
	t      *testing.T
	gw     *Gateway
	bucket *fakes3.Server
	store  *objstore.Store // the gateway's folder, directly
	client *objstore.Store // ClickHouse's view, through the gateway
	tmp    string
}

func newEnv(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	bucket := fakes3.New("bkt")
	t.Cleanup(bucket.Close)
	store, err := objstore.New(pgbackrest.Repo{Endpoint: "http://" + bucket.Host(), Bucket: "bkt", Key: "k", KeySecret: "s",
		PathPrefix: "/rowsafe", Region: "us-east-1"}, "db_1")
	if err != nil {
		t.Fatal(err)
	}
	store.PartSize = 64 << 10
	tmp := t.TempDir()
	cfg := Config{Store: store, Passphrase: testPass, Prefixes: []string{"backup/"}, TempDir: tmp,
		Log: slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	if mod != nil {
		mod(&cfg)
	}
	gw, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	client, err := objstore.New(pgbackrest.Repo{Endpoint: strings.TrimSuffix(gw.Endpoint(""), "/"+Bucket+"/"), Bucket: Bucket,
		Key: gw.AccessKeyID(), KeySecret: gw.SecretAccessKey()}, "")
	if err != nil {
		t.Fatal(err)
	}
	client.PartSize = 100 << 10
	return &env{t: t, gw: gw, bucket: bucket, store: store, client: client, tmp: tmp}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func payload(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	for i := 0; i+len(marker) <= n; i += 50000 {
		copy(b[i:], marker)
	}
	return b
}

// checkBucket asserts every stored object is sealed, opens to want[key],
// and shows no plaintext.
func (e *env) checkBucket(want map[string][]byte) {
	e.t.Helper()
	keys := e.bucket.Keys()
	if len(keys) != len(want) {
		e.t.Fatalf("bucket holds %d objects, want %d: %v", len(keys), len(want), keys)
	}
	for _, k := range keys {
		raw, _ := e.bucket.Object(k)
		stored := strings.TrimPrefix(k, "rowsafe/db_1/")
		// Names in the bucket: the folder in clear, the rest encrypted.
		rel, ok := e.gw.plainKey(stored[:strings.LastIndexByte(stored, '/')+1], stored)
		if !ok {
			e.t.Fatalf("%s isn't an encrypted name", k)
		}
		if e.gw.stored(rel) != stored {
			e.t.Fatalf("%s: the name doesn't map back (%s)", k, e.gw.stored(rel))
		}
		plain, ok := want[rel]
		if !ok {
			e.t.Fatalf("unexpected object %s (%s)", k, rel)
		}
		if bytes.Contains(raw, marker) {
			e.t.Fatalf("%s holds plaintext", k)
		}
		r, err := objstore.Open(bytes.NewReader(raw), testPass)
		if err != nil {
			e.t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			e.t.Fatalf("%s doesn't open to what was written (%d vs %d bytes, %v)", k, len(got), len(plain), err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	want := map[string][]byte{}
	sizes := []int{0, 1, 1000, objstore.SealSegmentSize, objstore.SealSegmentSize + 1, 300 << 10, 1<<20 + 3}
	for _, size := range sizes {
		key := fmt.Sprintf("backup/full/data_%d.bin", size)
		data := payload(size)
		// The client uses multipart above 100 KiB.
		if _, err := e.client.Put(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatalf("put %d: %v", size, err)
		}
		want[key] = data
	}
	e.checkBucket(want)

	for key, data := range want {
		o, err := e.client.Head(ctx, key)
		if err != nil || o.Size != int64(len(data)) {
			t.Fatalf("head %s: %+v %v", key, o, err)
		}
		got, err := e.client.GetBytes(ctx, key)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("get %s: %d bytes %v", key, len(got), err)
		}
		n := int64(len(data))
		ranges := [][2]int64{{0, 1}, {n - 1, 1}, {n / 3, n / 2}, {objstore.SealSegmentSize - 5, 10}, {objstore.SealSegmentSize + 7, -1}, {5, -1}}
		for _, rg := range ranges {
			off, l := rg[0], rg[1]
			if off < 0 || off >= n || l == 0 {
				continue
			}
			end := n
			if l > 0 {
				end = min(off+l, n)
			}
			rc, size, err := e.client.GetRange(ctx, key, off, l)
			if err != nil {
				t.Fatalf("range %s %v: %v", key, rg, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || size != n || !bytes.Equal(got, data[off:end]) {
				t.Fatalf("range %s %v: %d bytes, size %d, %v", key, rg, len(got), size, err)
			}
		}
	}

	objs, err := e.client.List(ctx, "backup/full/")
	if err != nil || len(objs) != len(sizes) {
		t.Fatalf("list: %v %v", objs, err)
	}
	for _, o := range objs {
		if o.Size != int64(len(want[o.Key])) {
			t.Fatalf("list %s: size %d, want %d", o.Key, o.Size, len(want[o.Key]))
		}
	}
	if _, err := e.client.Head(ctx, "backup/none"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("head of a missing key: %v", err)
	}
	if _, err := e.client.Get(ctx, "backup/none"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("get of a missing key: %v", err)
	}
	for key := range want {
		if err := e.client.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	e.checkBucket(nil)
	st := e.gw.Stats()
	if st.ObjectsWritten != int64(len(sizes)) || st.Deleted != int64(len(sizes)) || st.BytesRead == 0 || st.StoredWritten <= st.BytesWritten {
		t.Fatalf("stats: %+v", st)
	}
	if st.Errors != 0 {
		t.Fatalf("errors: %+v", st)
	}
	if entries, _ := os.ReadDir(e.gw.tmp); len(entries) != 0 {
		t.Fatalf("temporary parts left: %d", len(entries))
	}
}

// signer signs raw requests like an S3 client.
type signer struct {
	key, secret string
	now         time.Time
}

func (s signer) signingKey(date string) []byte {
	k := hmacSHA256([]byte("AWS4"+s.secret), date)
	k = hmacSHA256(k, "us-east-1")
	k = hmacSHA256(k, "s3")
	return hmacSHA256(k, "aws4_request")
}

// sign signs req with payloadHash; it returns the signature.
func (s signer) sign(req *http.Request, payloadHash string) string {
	now := s.now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	names := []string{"host"}
	for k := range req.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		v := req.URL.Host
		if n != "host" {
			v = strings.TrimSpace(req.Header.Get(n))
		}
		ch.WriteString(n + ":" + v + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, encodePath(req.URL.Path), canonicalQuery(req.URL.RawQuery), ch.String(), signed, payloadHash}, "\n")
	sum := sha256.Sum256([]byte(creq))
	scope := date + "/us-east-1/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	sig := hex.EncodeToString(hmacSHA256(s.signingKey(date), sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.key+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
	return sig
}

func (e *env) signer() signer { return signer{key: e.gw.AccessKeyID(), secret: e.gw.SecretAccessKey()} }

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// do sends a signed request; query is raw ("uploads", "partNumber=1&uploadId=x").
func (e *env) do(s signer, method, key, query string, body []byte, header http.Header) (*http.Response, []byte) {
	e.t.Helper()
	u := e.gw.Endpoint(key)
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	if req.Header.Get("x-amz-content-sha256") == "" {
		s.sign(req, sha(body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func expectError(t *testing.T, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status || !bytes.Contains(body, []byte("<Code>"+code+"</Code>")) {
		t.Fatalf("want %d %s, got %d %s", status, code, resp.StatusCode, body)
	}
}

func TestAuthAndKeys(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	data := []byte("hello " + string(marker))

	// Anonymous, wrong key, wrong secret, old date.
	req, _ := http.NewRequest(http.MethodGet, e.gw.Endpoint("backup/x"), nil)
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	expectError(t, resp, b, 403, "AccessDenied")
	resp, b = e.do(signer{key: "nope", secret: s.secret}, http.MethodPut, "backup/x", "", data, nil)
	expectError(t, resp, b, 403, "InvalidAccessKeyId")
	resp, b = e.do(signer{key: s.key, secret: "wrong"}, http.MethodPut, "backup/x", "", data, nil)
	expectError(t, resp, b, 403, "SignatureDoesNotMatch")
	resp, b = e.do(signer{key: s.key, secret: s.secret, now: time.Now().Add(-time.Hour)}, http.MethodPut, "backup/x", "", data, nil)
	expectError(t, resp, b, 403, "RequestTimeTooSkewed")

	// A signed payload that doesn't match its hash stores nothing.
	req, _ = http.NewRequest(http.MethodPut, e.gw.Endpoint("backup/x"), bytes.NewReader(data))
	s.sign(req, sha([]byte("something else")))
	resp, _ = http.DefaultClient.Do(req)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	expectError(t, resp, b, 400, "XAmzContentSHA256Mismatch")
	// A wrong Content-MD5 too.
	resp, b = e.do(s, http.MethodPut, "backup/x", "", data, http.Header{"Content-Md5": {base64.StdEncoding.EncodeToString(make([]byte, 16))}})
	expectError(t, resp, b, 400, "BadDigest")
	e.checkBucket(nil)

	// Keys outside the prefixes, or escaping the folder.
	for _, key := range []string{"other/x", "backup/../x", "backup//x", "backup/./x", "backupx"} {
		resp, b = e.do(s, http.MethodPut, key, "", data, nil)
		expectError(t, resp, b, 403, "AccessDenied")
	}
	resp, b = e.do(s, http.MethodGet, "", "list-type=2&prefix=other/", nil, nil)
	expectError(t, resp, b, 403, "AccessDenied")
	// Another bucket.
	req, _ = http.NewRequest(http.MethodGet, strings.Replace(e.gw.Endpoint("backup/x"), "/"+Bucket+"/", "/bkt/", 1), nil)
	s.sign(req, emptySHA256)
	resp, _ = http.DefaultClient.Do(req)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	expectError(t, resp, b, 404, "NoSuchBucket")

	// Unsigned payloads, and Content-MD5, are accepted.
	md := md5.Sum(data) //nolint:gosec // test
	resp, b = e.do(s, http.MethodPut, "backup/ok", "", data, http.Header{"Content-Md5": {base64.StdEncoding.EncodeToString(md[:])}})
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != `"`+hex.EncodeToString(md[:])+`"` {
		t.Fatalf("put: %d %s %s", resp.StatusCode, resp.Header.Get("ETag"), b)
	}
	req, _ = http.NewRequest(http.MethodPut, e.gw.Endpoint("backup/unsigned"), bytes.NewReader(data))
	s.sign(req, "UNSIGNED-PAYLOAD")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unsigned payload: %d", resp.StatusCode)
	}
	// Listing from the bucket's root only shows the prefixes.
	if err := e.store.PutBytes(context.Background(), "elsewhere", []byte("not ClickHouse's")); err != nil {
		t.Fatal(err)
	}
	resp, b = e.do(s, http.MethodGet, "", "list-type=2", nil, nil)
	if resp.StatusCode != 200 || bytes.Contains(b, []byte("elsewhere")) || !bytes.Contains(b, []byte("<Key>backup/ok</Key>")) {
		t.Fatalf("list root: %d %s", resp.StatusCode, b)
	}
	if e.gw.Stats().Errors == 0 || e.gw.Stats().LastError == "" {
		t.Fatal("refusals are not counted")
	}
}

func TestReadOnly(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ReadOnly = true })
	s := e.signer()
	if _, err := e.store.Put(context.Background(), "backup/x", bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPost} {
		resp, b := e.do(s, m, "backup/x", "", []byte("x"), nil)
		expectError(t, resp, b, 403, "AccessDenied")
	}
}

// chunked encodes body as an aws-chunked payload, signed from seed (empty:
// unsigned, with a trailer).
func chunked(s signer, req *http.Request, body []byte, chunk int, signed bool) []byte {
	var out bytes.Buffer
	now := time.Now().UTC()
	s.now = now
	amzDate := now.Format("20060102T150405Z")
	scope := now.Format("20060102") + "/us-east-1/s3/aws4_request"
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprint(len(body)))
	req.Header.Set("Content-Encoding", "aws-chunked")
	mode := "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	if signed {
		mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	}
	prev := s.sign(req, mode)
	key := s.signingKey(now.Format("20060102"))
	for {
		n := min(chunk, len(body))
		data := body[:n]
		body = body[n:]
		if signed {
			sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + amzDate + "\n" + scope + "\n" + prev + "\n" + emptySHA256 + "\n" + sha(data)
			prev = hex.EncodeToString(hmacSHA256(key, sts))
			fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n", n, prev)
		} else {
			fmt.Fprintf(&out, "%x\r\n", n)
		}
		if n == 0 {
			break
		}
		out.Write(data)
		out.WriteString("\r\n")
	}
	if !signed {
		out.WriteString("x-amz-checksum-crc32:AAAAAA==\r\n")
	}
	out.WriteString("\r\n")
	return out.Bytes()
}

func TestChunkedPayloads(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	data := payload(200 << 10)
	for _, signed := range []bool{true, false} {
		key := fmt.Sprintf("backup/chunked-%v", signed)
		req, _ := http.NewRequest(http.MethodPut, e.gw.Endpoint(key), nil)
		raw := chunked(s, req, data, 64<<10, signed)
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("chunked (signed %v): %d %s", signed, resp.StatusCode, b)
		}
		got, err := e.client.GetBytes(context.Background(), key)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("chunked (signed %v) reads back wrong: %v", signed, err)
		}
	}
	// A tampered chunk is refused and nothing is stored.
	req, _ := http.NewRequest(http.MethodPut, e.gw.Endpoint("backup/tampered"), nil)
	raw := chunked(s, req, data, 64<<10, true)
	raw[len(raw)-200] ^= 1
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	expectError(t, resp, b, 403, "SignatureDoesNotMatch")
	if _, ok := e.bucket.Object("rowsafe/db_1/" + e.gw.stored("backup/tampered")); ok {
		t.Fatal("a tampered upload was stored")
	}
}

func xmlField(b []byte, name string) string {
	_, rest, ok := bytes.Cut(b, []byte("<"+name+">"))
	if !ok {
		return ""
	}
	v, _, _ := bytes.Cut(rest, []byte("</"+name+">"))
	return string(v)
}

func TestParallelMultipart(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	key := "backup/big.bin"
	const parts = 12
	partSize := 300<<10 + 17 // not a multiple of the segment size
	data := payload(parts*partSize - 1000)

	resp, b := e.do(s, http.MethodPost, key, "uploads", nil, nil)
	id := xmlField(b, "UploadId")
	if resp.StatusCode != 200 || id == "" {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	etags := make([]string, parts+1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	// Parts arrive in reverse order, in parallel, and part 5 twice.
	for _, n := range []int{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 5} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chunk := data[(n-1)*partSize : min(n*partSize, len(data))]
			resp, b := e.do(s, http.MethodPut, key, fmt.Sprintf("partNumber=%d&uploadId=%s", n, id), chunk, nil)
			if resp.StatusCode != 200 {
				t.Errorf("part %d: %d %s", n, resp.StatusCode, b)
			}
			mu.Lock()
			etags[n] = resp.Header.Get("ETag")
			mu.Unlock()
		}()
		if n == 5 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	wg.Wait()
	// A different part 3, once drained, is refused.
	e.gw.mu.Lock()
	u := e.gw.uploads[id]
	e.gw.mu.Unlock()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		u.mu.Lock()
		next := u.next
		u.mu.Unlock()
		if next > parts {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parts not drained (next %d)", next)
		}
	}
	resp, b = e.do(s, http.MethodPut, key, "partNumber=3&uploadId="+id, []byte("different"), nil)
	expectError(t, resp, b, 400, "InvalidPart")

	complete := func(list []int, tag func(int) string) (*http.Response, []byte) {
		var x strings.Builder
		x.WriteString("<CompleteMultipartUpload>")
		for _, n := range list {
			fmt.Fprintf(&x, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", n, tag(n))
		}
		x.WriteString("</CompleteMultipartUpload>")
		return e.do(s, http.MethodPost, key, "uploadId="+id, []byte(x.String()), nil)
	}
	all := make([]int, parts)
	for i := range all {
		all[i] = i + 1
	}
	resp, b = complete(all, func(n int) string { return `"0123"` })
	expectError(t, resp, b, 400, "InvalidPart")
	resp, b = complete([]int{2, 1}, func(n int) string { return etags[n] })
	expectError(t, resp, b, 400, "InvalidPartOrder")
	resp, b = complete(all, func(n int) string { return etags[n] })
	if resp.StatusCode != 200 || !strings.HasSuffix(xmlField(b, "ETag"), fmt.Sprintf("-%d&#34;", parts)) {
		t.Fatalf("complete: %d %s", resp.StatusCode, b)
	}
	// Completing again answers the same.
	resp, _ = complete(all, func(n int) string { return etags[n] })
	if resp.StatusCode != 200 {
		t.Fatalf("complete again: %d", resp.StatusCode)
	}
	e.checkBucket(map[string][]byte{key: data})
	got, err := e.client.GetBytes(context.Background(), key)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back: %v", err)
	}
	if entries, _ := os.ReadDir(e.gw.tmp); len(entries) != 0 {
		t.Fatalf("temporary parts left: %d", len(entries))
	}

	// An aborted upload stores nothing and leaves no part behind.
	resp, b = e.do(s, http.MethodPost, "backup/aborted", "uploads", nil, nil)
	id2 := xmlField(b, "UploadId")
	for _, n := range []int{1, 3} {
		resp, b = e.do(s, http.MethodPut, "backup/aborted", fmt.Sprintf("partNumber=%d&uploadId=%s", n, id2), data[:partSize], nil)
		if resp.StatusCode != 200 {
			t.Fatalf("part: %d %s", resp.StatusCode, b)
		}
	}
	resp, b = e.do(s, http.MethodDelete, "backup/aborted", "uploadId="+id2, nil, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("abort: %d %s", resp.StatusCode, b)
	}
	resp, b = e.do(s, http.MethodPut, "backup/aborted", "partNumber=2&uploadId="+id2, data[:10], nil)
	expectError(t, resp, b, 404, "NoSuchUpload")
	e.checkBucket(map[string][]byte{key: data})
	if entries, _ := os.ReadDir(e.gw.tmp); len(entries) != 0 {
		t.Fatalf("temporary parts left after abort: %d", len(entries))
	}
}

func TestPartsNeverInPlaintext(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	resp, b := e.do(s, http.MethodPost, "backup/p", "uploads", nil, nil)
	id := xmlField(b, "UploadId")
	// Part 2 waits on disk for part 1.
	if resp, b = e.do(s, http.MethodPut, "backup/p", "partNumber=2&uploadId="+id, payload(200<<10), nil); resp.StatusCode != 200 {
		t.Fatalf("part: %d %s", resp.StatusCode, b)
	}
	entries, _ := os.ReadDir(e.gw.tmp)
	if len(entries) != 1 {
		t.Fatalf("%d buffered parts", len(entries))
	}
	info, _ := entries[0].Info()
	raw, _ := os.ReadFile(e.gw.tmp + "/" + entries[0].Name())
	if bytes.Contains(raw, marker) || info.Mode().Perm() != 0o600 {
		t.Fatalf("a buffered part is readable (mode %v, plaintext %v)", info.Mode().Perm(), bytes.Contains(raw, marker))
	}
	if st, _ := os.Stat(e.gw.tmp); st.Mode().Perm() != 0o700 {
		t.Fatalf("the parts folder is %v", st.Mode().Perm())
	}
	// Closing abandons the upload: nothing stored, nothing left.
	tmp := e.gw.tmp
	if err := e.gw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("the parts folder survived Close")
	}
	e.checkBucket(nil)
}

func TestDeleteObjectsCopyAndListV1(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	ctx := context.Background()
	want := map[string][]byte{}
	for i := range 5 {
		key := fmt.Sprintf("backup/b1/dir%d/f", i%2) + fmt.Sprint(i)
		want[key] = payload(1000 * i)
		if _, err := e.client.Put(ctx, key, bytes.NewReader(want[key])); err != nil {
			t.Fatal(err)
		}
	}
	// ListObjects V1 the way ClickHouse checks a backup exists, and with
	// a delimiter and pages.
	resp, b := e.do(s, http.MethodGet, "", "max-keys=1&prefix="+url.QueryEscape("backup/b1/dir1/f1"), nil, nil)
	if resp.StatusCode != 200 || xmlField(b, "Key") != "backup/b1/dir1/f1" || xmlField(b, "Size") != "1000" {
		t.Fatalf("list v1: %s", b)
	}
	resp, b = e.do(s, http.MethodGet, "", "delimiter=%2F&max-keys=1&prefix=backup%2Fb1%2F", nil, nil)
	if xmlField(b, "Prefix") != "backup/b1/" || !bytes.Contains(b, []byte("<CommonPrefixes><Prefix>backup/b1/dir0/</Prefix></CommonPrefixes>")) ||
		xmlField(b, "IsTruncated") != "true" || xmlField(b, "NextMarker") != "backup/b1/dir0/" {
		t.Fatalf("list v1 delimiter: %s", b)
	}
	resp, b = e.do(s, http.MethodGet, "", "delimiter=%2F&marker=backup%2Fb1%2Fdir0%2F&prefix=backup%2Fb1%2F", nil, nil)
	if !bytes.Contains(b, []byte("<CommonPrefixes><Prefix>backup/b1/dir1/</Prefix></CommonPrefixes>")) || bytes.Contains(b, []byte("<Prefix>backup/b1/dir0/")) {
		t.Fatalf("list v1 second page: %s", b)
	}

	// CopyObject.
	resp, b = e.do(s, http.MethodPut, "backup/copy", "", nil, http.Header{"X-Amz-Copy-Source": {"/" + Bucket + "/backup/b1/dir0/f2"}})
	if resp.StatusCode != 200 {
		t.Fatalf("copy: %d %s", resp.StatusCode, b)
	}
	want["backup/copy"] = want["backup/b1/dir0/f2"]
	resp, b = e.do(s, http.MethodPut, "backup/copy2", "", nil, http.Header{"X-Amz-Copy-Source": {"/" + Bucket + "/other/x"}})
	expectError(t, resp, b, 403, "AccessDenied")
	e.checkBucket(want)

	// DeleteObjects, with a key outside the prefixes.
	body := []byte("<Delete><Object><Key>backup/b1/dir0/f0</Key></Object><Object><Key>backup/b1/dir1/f1</Key></Object>" +
		"<Object><Key>other/x</Key></Object></Delete>")
	md := md5.Sum(body) //nolint:gosec // test
	resp, b = e.do(s, http.MethodPost, "", "delete", body, http.Header{"Content-Md5": {base64.StdEncoding.EncodeToString(md[:])}})
	if resp.StatusCode != 200 || strings.Count(string(b), "<Deleted>") != 2 || !bytes.Contains(b, []byte("<Key>other/x</Key><Code>AccessDenied</Code>")) {
		t.Fatalf("delete objects: %d %s", resp.StatusCode, b)
	}
	delete(want, "backup/b1/dir0/f0")
	delete(want, "backup/b1/dir1/f1")
	e.checkBucket(want)
}

func TestContextEndStopsGateway(t *testing.T) {
	bucket := fakes3.New("bkt")
	defer bucket.Close()
	store, _ := objstore.New(pgbackrest.Repo{Endpoint: "http://" + bucket.Host(), Bucket: "bkt", Key: "k", KeySecret: "s"}, "x")
	ctx, cancel := context.WithCancel(context.Background())
	gw, err := Start(ctx, Config{Store: store, Passphrase: testPass, TempDir: t.TempDir(), PublicURL: "http://gateway.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gw.Endpoint("backup/a b"), "http://gateway.test:") || !strings.HasSuffix(gw.Endpoint("backup/a b"), "/rowsafe/backup/a%20b") {
		t.Fatalf("endpoint: %s", gw.Endpoint("backup/a b"))
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := http.Get("http://" + gw.Addr() + "/")
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway still answers after its context ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRetriedPutJoinsUpload(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	var mu sync.Mutex
	puts := 0
	e.bucket.Fail = func(r *http.Request) int {
		if r.Method == http.MethodPut {
			mu.Lock()
			puts++
			mu.Unlock()
			time.Sleep(time.Second) // a slow bucket
		}
		return 0
	}
	data := payload(10 << 10)
	md := md5.Sum(data) //nolint:gosec // test
	put := func(timeout time.Duration) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPut, e.gw.Endpoint("backup/slow"), bytes.NewReader(data))
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(md[:]))
		s.sign(req, sha(data))
		return (&http.Client{Timeout: timeout}).Do(req)
	}
	// ClickHouse gives up on the first attempt, then sends it again.
	if _, err := put(200 * time.Millisecond); err == nil {
		t.Fatal("the first attempt should time out")
	}
	resp, err := put(10 * time.Second)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("retry: %v %v", resp, err)
	}
	resp.Body.Close()
	mu.Lock()
	n := puts
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the object was stored %d times", n)
	}
	e.bucket.Fail = nil
	e.checkBucket(map[string][]byte{"backup/slow": data})
}

// A client that disconnects mid-body leaves nothing at the key: net/http and
// the aws-chunked reader both end such a body with io.ErrUnexpectedEOF.
func TestCutPutStoresNothing(t *testing.T) {
	served := make(chan string, 10) // PUTs handled
	e := newEnv(t, func(c *Config) {
		c.Log = slog.New(slog.NewTextHandler(lineWriter(func(line string) {
			if strings.Contains(line, `msg="backup gateway request" method=PUT`) {
				served <- line
			}
		}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	s := e.signer()
	for _, size := range []int{10 << 10, 200 << 10} { // one request, multipart in the bucket
		for _, mode := range []string{"unsigned", "chunked"} {
			key := fmt.Sprintf("backup/cut-%s-%d", mode, size)
			data := payload(size)
			req, _ := http.NewRequest(http.MethodPut, e.gw.Endpoint(key), nil)
			raw := data
			if mode == "chunked" {
				raw = chunked(s, req, data, 16<<10, false)
			} else {
				s.sign(req, "UNSIGNED-PAYLOAD")
			}
			conn, err := net.Dial("tcp", req.URL.Host)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(conn, "PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", req.URL.RequestURI(), req.URL.Host, len(raw))
			req.Header.Write(conn)
			io.WriteString(conn, "\r\n")
			conn.Write(raw[:len(raw)*3/4])
			conn.Close()
			select {
			case <-served:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the gateway never noticed the cut body", key)
			}
			if _, ok := e.bucket.Object("rowsafe/db_1/" + e.gw.stored(key)); ok {
				t.Fatalf("%s: a truncated object was stored", key)
			}
		}
	}
	e.checkBucket(map[string][]byte{})
}

type lineWriter func(string)

func (w lineWriter) Write(p []byte) (int, error) {
	w(string(p))
	return len(p), nil
}

// A key whose encrypted name would be over S3's 1,024 bytes is refused
// up front, in plain words, and never sent to the bucket.
func TestKeyTooLongOnceStored(t *testing.T) {
	e := newEnv(t, nil)
	var mu sync.Mutex
	sent := 0
	e.bucket.Fail = func(r *http.Request) int {
		mu.Lock()
		sent++
		mu.Unlock()
		return 0
	}
	ctx := context.Background()
	ok := "backup/" + strings.Repeat("a", 500)
	if _, err := e.client.Put(ctx, ok, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("a 500-byte key: %v", err)
	}
	mu.Lock()
	sent = 0
	mu.Unlock()
	long := "backup/data/" + strings.Repeat("t", 760) + "/data.bin"
	if len(long) > 1024 {
		t.Fatal("the test key must fit S3 before encryption")
	}
	_, err := e.client.Put(ctx, long, bytes.NewReader(payload(300<<10)))
	var se *objstore.S3Error
	if !errors.As(err, &se) || se.Code != "KeyTooLongError" || !strings.Contains(err.Error(), "too long to store") {
		t.Fatalf("a key too long once encrypted: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sent != 0 {
		t.Fatalf("%d requests reached the bucket", sent)
	}
}
