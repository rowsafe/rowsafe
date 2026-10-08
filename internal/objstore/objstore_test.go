package objstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

const pass = "correct horse battery staple 42"

func sealBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := Seal(&buf, pass)
	if err != nil {
		t.Fatal(err)
	}
	// Odd write sizes cross segment boundaries.
	for p := plain; len(p) > 0; {
		k := min(len(p), 12345)
		if _, err := w.Write(p[:k]); err != nil {
			t.Fatal(err)
		}
		p = p[k:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openAll(sealed []byte, passphrase string) ([]byte, error) {
	r, err := Open(bytes.NewReader(sealed), passphrase)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestSealRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, segmentSize - 1, segmentSize, segmentSize + 1, 3*segmentSize + 777} {
		plain := make([]byte, size)
		rand.Read(plain)
		sealed := sealBytes(t, plain)
		if bytes.Contains(sealed, plain[:min(size, 64)]) && size >= 64 {
			t.Fatalf("size %d: plaintext visible in the sealed stream", size)
		}
		got, err := openAll(sealed, pass)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip differs", size)
		}
	}
}

func TestSealRejects(t *testing.T) {
	plain := bytes.Repeat([]byte("rowsafe "), 3*segmentSize/8+10)
	sealed := sealBytes(t, plain)

	if _, err := openAll(sealed, "another passphrase of some length"); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)/2] ^= 1
	if _, err := openAll(tampered, pass); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("tampered: %v", err)
	}
	head := len(sealMagic) + saltSize + prefixSize
	// Cut on a segment boundary: the final segment is missing.
	cut := sealed[:head+2*(segmentSize+tagSize)]
	if _, err := openAll(cut, pass); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cut on a boundary: %v", err)
	}
	// Cut inside a segment.
	if _, err := openAll(sealed[:len(sealed)-5], pass); err == nil {
		t.Error("cut inside a segment opened")
	}
	if _, err := openAll([]byte("hello world, not sealed at all"), pass); err == nil {
		t.Error("garbage opened")
	}
}

func testStore(t *testing.T) (*Store, *fakes3.Server) {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	st, err := New(pgbackrest.Repo{Endpoint: srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", PathPrefix: "/rowsafe", Region: "us-east-1"}, "stanza1")
	if err != nil {
		t.Fatal(err)
	}
	st.SetScheme("http")
	st.PartSize = 1 << 10
	return st, srv
}

func TestStorePutGetListDelete(t *testing.T) {
	ctx := context.Background()
	st, srv := testStore(t)
	small := []byte("small object")
	if n, err := st.Put(ctx, "a/small", bytes.NewReader(small)); err != nil || n != int64(len(small)) {
		t.Fatalf("put small: %d %v", n, err)
	}
	big := make([]byte, 5000) // five parts of 1 KiB
	rand.Read(big)
	if n, err := st.Put(ctx, "a/big", bytes.NewReader(big)); err != nil || n != int64(len(big)) {
		t.Fatalf("put big: %d %v", n, err)
	}
	exact := make([]byte, 1<<10) // exactly one part
	if _, err := st.Put(ctx, "b/exact", bytes.NewReader(exact)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := st.PutBytes(ctx, "c/"+string(rune('a'+i)), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := srv.Object("rowsafe/stanza1/a/big"); !bytes.Equal(got, big) {
		t.Fatal("multipart upload stored the wrong bytes")
	}
	got, err := st.GetBytes(ctx, "a/small")
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("get: %q %v", got, err)
	}
	if _, err := st.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	objs, err := st.List(ctx, "c/")
	if err != nil || len(objs) != 5 || objs[0].Key != "c/a" || objs[4].Key != "c/e" {
		t.Fatalf("list: %+v %v", objs, err)
	}
	all, _ := st.List(ctx, "")
	if len(all) != 8 {
		t.Fatalf("list all: %d", len(all))
	}
	if err := st.Delete(ctx, "a/small"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "a/small"); err != nil {
		t.Fatal("deleting twice:", err)
	}
	if _, err := st.Get(ctx, "a/small"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted object still there")
	}
}

// cutReader yields n bytes of data and then fails like a client that
// disconnected mid-body.
type cutReader struct {
	data []byte
	err  error
}

func (c *cutReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, c.err
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

func TestStorePutStoresNothingWhenTheSourceIsCut(t *testing.T) {
	ctx := context.Background()
	st, srv := testStore(t)
	for _, size := range []int{10, 1 << 10, 1500, 5000} { // small, exactly one part, multipart
		for _, cut := range []error{io.ErrUnexpectedEOF, errors.New("connection reset")} {
			key := fmt.Sprintf("cut/%d", size)
			_, err := st.Put(ctx, key, &cutReader{data: make([]byte, size), err: cut})
			if !errors.Is(err, cut) {
				t.Fatalf("size %d, %v: Put = %v", size, cut, err)
			}
			if _, ok := srv.Object("rowsafe/stanza1/" + key); ok {
				t.Fatalf("size %d, %v: a truncated object was stored", size, cut)
			}
		}
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Fatalf("stored: %v", keys)
	}
}

func TestStoreRetriesAndErrors(t *testing.T) {
	ctx := context.Background()
	st, srv := testStore(t)
	fails := 1
	srv.Fail = func(r *http.Request) int {
		if fails > 0 {
			fails--
			return http.StatusServiceUnavailable
		}
		return 0
	}
	if err := st.PutBytes(ctx, "x", []byte("y")); err != nil {
		t.Fatalf("a 503 is retried: %v", err)
	}
	srv.Fail = func(r *http.Request) int { return http.StatusForbidden }
	err := st.PutBytes(ctx, "x", []byte("y"))
	var se *S3Error
	if !errors.As(err, &se) || se.Status != 403 || !strings.Contains(err.Error(), "Injected") {
		t.Fatalf("403: %v", err)
	}
}

func TestSignature(t *testing.T) {
	// The AWS SigV4 test suite's get-vanilla example, adapted to S3.
	st := &Store{region: "us-east-1", key: "AKIDEXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		now: func() time.Time { return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC) }}
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.URL = &url.URL{Scheme: "https", Host: "example.amazonaws.com", Path: "/"}
	st.sign(req, emptySHA256)
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatalf("authorization: %s", auth)
	}
	// Signing is deterministic.
	req2, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req2.URL = &url.URL{Scheme: "https", Host: "example.amazonaws.com", Path: "/"}
	st.sign(req2, emptySHA256)
	if req2.Header.Get("Authorization") != auth {
		t.Fatal("signature not deterministic")
	}
	if encodePath("/b/a key+x") != "/b/a%20key%2Bx" {
		t.Fatal(encodePath("/b/a key+x"))
	}
}

// TestSignatureSessionToken: temporary credentials (Rowsafe Storage) send
// and sign their session token.
func TestSignatureSessionToken(t *testing.T) {
	st, err := New(pgbackrest.Repo{Endpoint: "acct.r2.cloudflarestorage.com", Bucket: "b", Key: "AKID", KeySecret: "secret",
		Token: "session-token", PathPrefix: "/orgs/org_1"}, "shop")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://acct.r2.cloudflarestorage.com/b/orgs/org_1/shop/x", nil)
	st.sign(req, emptySHA256)
	if req.Header.Get("x-amz-security-token") != "session-token" ||
		!strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,") {
		t.Fatalf("token: %q, authorization: %s", req.Header.Get("x-amz-security-token"), req.Header.Get("Authorization"))
	}
	if st.FullKey("x") != "orgs/org_1/shop/x" {
		t.Fatal(st.FullKey("x"))
	}
}

func TestSealedRanges(t *testing.T) {
	for _, size := range []int{0, 1, 100, segmentSize - 1, segmentSize, segmentSize + 1, 2 * segmentSize, 3*segmentSize + 777} {
		plain := make([]byte, size)
		rand.Read(plain)
		sealed := sealBytes(t, plain)
		if got := SealedSize(int64(size)); got != int64(len(sealed)) {
			t.Fatalf("size %d: SealedSize %d, stored %d", size, got, len(sealed))
		}
		if got, err := PlainSize(int64(len(sealed))); err != nil || got != int64(size) {
			t.Fatalf("size %d: PlainSize %d %v", size, got, err)
		}
		ranges := [][2]int{{0, size}, {0, 1}, {size - 1, 1}, {size / 2, size / 3}, {segmentSize - 3, 10}, {segmentSize, segmentSize}}
		for _, rg := range ranges {
			off, n := rg[0], rg[1]
			if off < 0 || n <= 0 || off+n > size {
				continue
			}
			start, end, first, skip := SealedRange(int64(len(sealed)), int64(off), int64(n))
			r, err := OpenAt(bytes.NewReader(sealed[start:end]), pass, sealed[:SealHeaderSize], int64(len(sealed)), first)
			if err != nil {
				t.Fatalf("size %d range %v: %v", size, rg, err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("size %d range %v: %v", size, rg, err)
			}
			if int64(len(got)) < skip+int64(n) || !bytes.Equal(got[skip:skip+int64(n)], plain[off:off+n]) {
				t.Fatalf("size %d range %v: wrong bytes", size, rg)
			}
		}
	}
	for _, bad := range []int64{0, 44, int64(SealHeaderSize) + segmentSize + tagSize + tagSize} {
		if _, err := PlainSize(bad); err == nil {
			t.Errorf("PlainSize(%d) accepted", bad)
		}
	}
	// A range of a tampered object, and one cut inside a segment.
	plain := make([]byte, 3*segmentSize)
	sealed := sealBytes(t, plain)
	start, end, first, _ := SealedRange(int64(len(sealed)), segmentSize, 10)
	tampered := bytes.Clone(sealed[start:end])
	tampered[5] ^= 1
	r, _ := OpenAt(bytes.NewReader(tampered), pass, sealed[:SealHeaderSize], int64(len(sealed)), first)
	if _, err := io.ReadAll(r); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("tampered range: %v", err)
	}
	r, _ = OpenAt(bytes.NewReader(sealed[start:end-3]), pass, sealed[:SealHeaderSize], int64(len(sealed)), first)
	if _, err := io.ReadAll(r); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cut range: %v", err)
	}
	// The middle segment can't pass for the last one (a truncated object).
	r, _ = OpenAt(bytes.NewReader(sealed[start:end]), pass, sealed[:SealHeaderSize], int64(len(sealed))-segmentSize-tagSize, first)
	if _, err := io.ReadAll(r); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("middle segment as the last: %v", err)
	}
}

func TestStoreHeadAndRange(t *testing.T) {
	ctx := context.Background()
	st, _ := testStore(t)
	data := []byte("0123456789abcdef")
	if err := st.PutBytes(ctx, "r/obj", data); err != nil {
		t.Fatal(err)
	}
	o, err := st.Head(ctx, "r/obj")
	if err != nil || o.Size != int64(len(data)) {
		t.Fatalf("head: %+v %v", o, err)
	}
	if _, err := st.Head(ctx, "r/none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("head missing: %v", err)
	}
	for _, c := range []struct {
		off, n int64
		want   string
	}{{0, -1, string(data)}, {3, 4, "3456"}, {10, -1, "abcdef"}, {15, 1, "f"}} {
		rc, size, err := st.GetRange(ctx, "r/obj", c.off, c.n)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if string(got) != c.want || size != int64(len(data)) {
			t.Fatalf("range %d+%d: %q size %d", c.off, c.n, got, size)
		}
	}
	if _, _, err := st.GetRange(ctx, "r/none", 0, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("range missing: %v", err)
	}
}
