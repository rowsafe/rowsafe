package mysql

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// The bucket. Everything of one database lives under
// <ROWSAFE_REPO_PATH_PREFIX>/<engine>/<database name>/:
//
//	repository.json.age                       marker: engine, database, created
//	backups/<label>/data.xbs.zst.age          the backup stream (xbstream)
//	backups/<label>/manifest.json.age         written last: the backup is complete
//	binlogs/<file>~<created>/<from>-<to>.zst.age  binary log bytes [from, to)
//	marks/<name>.json.age                     Marks (binary log position and time)
//
// Every object is compressed (zstd) and then encrypted on this server with
// age, using the repository passphrase (ROWSAFE_REPO_CIPHER_PASS) through
// scrypt: the bucket only ever sees ciphertext, and the passphrase never
// leaves the server, like pgBackRest's repository encryption for
// PostgreSQL. Object names hold no data: binary log file names, byte
// offsets, backup labels and Mark names.

// scryptWorkFactor is the scrypt cost of each object's key (2^15: about 32
// MiB and a few tens of milliseconds; the passphrase is long and random, so
// the cost only has to stop cheap guessing of weak passphrases).
const scryptWorkFactor = 15

// objStore is one database's part of the bucket.
type objStore struct {
	mc       *minio.Client
	bucket   string
	prefix   string // "rowsafe/mysql/shop/"
	pass     string
	partSize uint64
}

// openStore connects to the bucket for one database.
func openStore(repo pgbackrest.Repo, engine, stanza string, partSizeMB int) (*objStore, error) {
	if err := repo.Validate(); err != nil {
		return nil, err
	}
	if !stanzaRE.MatchString(stanza) {
		return nil, fmt.Errorf("invalid database name %q", stanza)
	}
	endpoint := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(repo.Endpoint, "https://"), "http://"), "/")
	if repo.Port != 0 {
		host := endpoint
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			host = h
		}
		endpoint = net.JoinHostPort(host, strconv.Itoa(repo.Port))
	}
	tr, err := minio.DefaultTransport(true)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: repo.SkipTLSVerify} //nolint:gosec // test repositories only
	if repo.CAFile != "" {
		pem, err := os.ReadFile(repo.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ROWSAFE_REPO_S3_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ROWSAFE_REPO_S3_CA_FILE: no certificates in %s", repo.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	tr.TLSClientConfig = tlsConf
	lookup := minio.BucketLookupPath
	if repo.URIStyle == "host" {
		lookup = minio.BucketLookupDNS
	}
	region := repo.Region
	if region == "" {
		region = "us-east-1"
	}
	mc, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(repo.Key, repo.KeySecret, ""),
		Secure:       true,
		Region:       region,
		BucketLookup: lookup,
		Transport:    tr,
	})
	if err != nil {
		return nil, fmt.Errorf("storage endpoint %s: %w", endpoint, err)
	}
	prefix := strings.Trim(repo.PathPrefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &objStore{
		mc: mc, bucket: repo.Bucket, prefix: prefix + engine + "/" + stanza + "/", pass: repo.CipherPass,
		partSize: uint64(max(partSizeMB, 16)) << 20,
	}, nil
}

// location is the database's place in the bucket, for messages.
func (s *objStore) location() string { return "s3://" + s.bucket + "/" + s.prefix }

// encryptTo compresses and encrypts what is written to the returned writer
// into dst. Close it to flush.
func (s *objStore) encryptTo(dst io.Writer) (io.WriteCloser, error) {
	rcp, err := age.NewScryptRecipient(s.pass)
	if err != nil {
		return nil, err
	}
	rcp.SetWorkFactor(scryptWorkFactor)
	enc, err := age.Encrypt(dst, rcp)
	if err != nil {
		return nil, err
	}
	zw, err := zstd.NewWriter(enc, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(2))
	if err != nil {
		return nil, err
	}
	return &stackWriter{Writer: zw, closers: []io.Closer{zw, enc}}, nil
}

type stackWriter struct {
	io.Writer
	closers []io.Closer
}

func (w *stackWriter) Close() error {
	var errs []error
	for _, c := range w.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// countingReader counts what was read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// put stores src under key, compressed and encrypted, streaming it (no
// local copy). A read error from src aborts the upload: nothing is stored.
// It returns the plain bytes read and the bytes stored.
func (s *objStore) put(ctx context.Context, key string, src io.Reader) (plain, stored int64, err error) {
	pr, pw := io.Pipe()
	cr := &countingReader{r: src}
	done := make(chan error, 1)
	go func() {
		w, err := s.encryptTo(pw)
		if err == nil {
			_, err = io.Copy(w, cr)
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		pw.CloseWithError(err) // nil: EOF, the upload completes
		done <- err
	}()
	info, err := s.mc.PutObject(ctx, s.bucket, s.prefix+key, pr, -1, minio.PutObjectOptions{
		PartSize: s.partSize, ContentType: "application/octet-stream",
	})
	pr.CloseWithError(errors.Join(err, errors.New("upload stopped")))
	if werr := <-done; werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return cr.n, 0, fmt.Errorf("uploading %s: %w", key, err)
	}
	return cr.n, info.Size, nil
}

// putBytes stores a small object.
func (s *objStore) putBytes(ctx context.Context, key string, data []byte) error {
	var buf bytes.Buffer
	w, err := s.encryptTo(&buf)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = s.mc.PutObject(ctx, s.bucket, s.prefix+key, &buf, int64(buf.Len()), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("uploading %s: %w", key, err)
	}
	return nil
}

func (s *objStore) putJSON(ctx context.Context, key string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.putBytes(ctx, key, data)
}

// errNotFound: no such object.
var errNotFound = errors.New("not found in the bucket")

// errWrongPassphrase: the object was encrypted with another passphrase.
var errWrongPassphrase = errors.New("the backups here were encrypted with a different passphrase than ROWSAFE_REPO_CIPHER_PASS")

// get opens key for reading, decrypted and decompressed.
func (s *objStore) get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := s.mc.GetObject(ctx, s.bucket, s.prefix+key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", key, err)
	}
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		if resp := minio.ToErrorResponse(err); resp.Code == minio.NoSuchKey || resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s: %w", key, errNotFound)
		}
		return nil, fmt.Errorf("downloading %s: %w", key, err)
	}
	id, err := age.NewScryptIdentity(s.pass)
	if err != nil {
		obj.Close()
		return nil, err
	}
	id.SetMaxWorkFactor(22)
	ar, err := age.Decrypt(obj, id)
	if err != nil {
		obj.Close()
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, fmt.Errorf("%s: %w", key, errWrongPassphrase)
		}
		return nil, fmt.Errorf("downloading %s: %w", key, err)
	}
	zr, err := zstd.NewReader(ar, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
	if err != nil {
		obj.Close()
		return nil, err
	}
	return &stackReader{Reader: zr, close: func() error { zr.Close(); return obj.Close() }}, nil
}

type stackReader struct {
	io.Reader
	close func() error
}

func (r *stackReader) Close() error { return r.close() }

// getBytes reads a small object (at most 64 MiB).
func (s *objStore) getBytes(ctx context.Context, key string) ([]byte, error) {
	r, err := s.get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", key, err)
	}
	return b, nil
}

func (s *objStore) getJSON(ctx context.Context, key string, v any) error {
	b, err := s.getBytes(ctx, key)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("reading %s: %w", key, err)
	}
	return nil
}

// objInfo is one listed object (Key relative to the database's prefix).
type objInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// list returns the objects under prefix (relative), sorted by key.
func (s *objStore) list(ctx context.Context, prefix string) ([]objInfo, error) {
	var out []objInfo
	for o := range s.mc.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: s.prefix + prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, fmt.Errorf("listing %s: %w", s.location()+prefix, o.Err)
		}
		out = append(out, objInfo{Key: strings.TrimPrefix(o.Key, s.prefix), Size: o.Size, LastModified: o.LastModified})
	}
	return out, nil
}

// remove deletes objects (relative keys).
func (s *objStore) remove(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	ch := make(chan minio.ObjectInfo, len(keys))
	for _, k := range keys {
		ch <- minio.ObjectInfo{Key: s.prefix + k}
	}
	close(ch)
	for e := range s.mc.RemoveObjects(ctx, s.bucket, ch, minio.RemoveObjectsOptions{}) {
		if e.Err != nil {
			return fmt.Errorf("deleting %s: %w", strings.TrimPrefix(e.ObjectName, s.prefix), e.Err)
		}
	}
	return nil
}

// repoMarker is repository.json.age: it proves the passphrase can read
// what is already there before anything new is written.
type repoMarker struct {
	Engine    string    `json:"engine"`
	Database  string    `json:"database"`
	CreatedAt time.Time `json:"created_at"`
}

const markerKey = "repository.json.age"

// ensureMarker writes the marker, or checks an existing one decrypts.
func (s *objStore) ensureMarker(ctx context.Context, engine, database string) (created bool, err error) {
	var m repoMarker
	err = s.getJSON(ctx, markerKey, &m)
	switch {
	case err == nil:
		if m.Engine != engine {
			return false, fmt.Errorf("%s holds %s backups of another database; pick another name or bucket path", s.location(), m.Engine)
		}
		return false, nil
	case errors.Is(err, errNotFound):
		return true, s.putJSON(ctx, markerKey, repoMarker{Engine: engine, Database: database, CreatedAt: time.Now().UTC()})
	}
	return false, err
}

// joinKey joins key parts.
func joinKey(parts ...string) string { return path.Join(parts...) }
