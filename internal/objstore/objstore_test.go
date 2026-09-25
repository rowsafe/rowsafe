package objstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
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
