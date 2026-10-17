package pgbackrest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Small objects of Rowsafe's own next to a stanza's backups (e.g. a standby
// pair's record, protocol.PrimaryRecordPath), in the stanza's folder of the
// repository: <path prefix>/<folder>/<rel>. S3 and posix repositories only.

// ErrNoObject: the object doesn't exist.
var ErrNoObject = errors.New("no such object")

// GetObject reads a small object (at most 1 MiB) of stanza's folder.
func (r Repo) GetObject(ctx context.Context, stanza, rel string) ([]byte, error) {
	if r.Posix() {
		b, err := os.ReadFile(r.posixObject(stanza, rel))
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoObject
		}
		return b, err
	}
	mc, err := r.objectClient()
	if err != nil {
		return nil, err
	}
	obj, err := mc.GetObject(ctx, r.Bucket, r.objectKey(stanza, rel), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	b, err := io.ReadAll(io.LimitReader(obj, 1<<20))
	if err != nil {
		if resp := minio.ToErrorResponse(err); resp.Code == minio.NoSuchKey || resp.StatusCode == http.StatusNotFound {
			return nil, ErrNoObject
		}
		return nil, err
	}
	return b, nil
}

// PutObject writes a small object of stanza's folder.
func (r Repo) PutObject(ctx context.Context, stanza, rel string, data []byte) error {
	if r.Posix() {
		p := r.posixObject(stanza, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, data, 0o640); err != nil {
			return err
		}
		return os.Rename(tmp, p)
	}
	mc, err := r.objectClient()
	if err != nil {
		return err
	}
	_, err = mc.PutObject(ctx, r.Bucket, r.objectKey(stanza, rel), bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/json"})
	return err
}

func (r Repo) posixObject(stanza, rel string) string {
	return filepath.Join(r.Path, r.folder(stanza), filepath.FromSlash(rel))
}

// objectKey is rel's key in the bucket.
func (r Repo) objectKey(stanza, rel string) string {
	return strings.TrimPrefix(path.Join(strings.Trim(r.PathPrefix, "/"), r.folder(stanza), rel), "/")
}

// objectClient connects to the S3 repository the way pgBackRest does
// (endpoint, port, path or host style, the CA bundle, TLS always).
func (r Repo) objectClient() (*minio.Client, error) {
	if r.SFTP() || (r.Type != "" && r.Type != "s3") {
		return nil, errors.New("this needs the backups in a bucket (S3-compatible storage)")
	}
	if r.Endpoint == "" || r.Bucket == "" {
		return nil, errors.New("the repository's bucket isn't configured")
	}
	endpoint := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(r.Endpoint, "https://"), "http://"), "/")
	if r.Port != 0 {
		host := endpoint
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			host = h
		}
		endpoint = net.JoinHostPort(host, strconv.Itoa(r.Port))
	}
	tr, err := minio.DefaultTransport(true)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: r.SkipTLSVerify} //nolint:gosec // test repositories only
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, fmt.Errorf("the repository's CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", r.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	tr.TLSClientConfig = tlsConf
	lookup := minio.BucketLookupPath
	if r.URIStyle == "host" {
		lookup = minio.BucketLookupDNS
	}
	region := r.Region
	if region == "" {
		region = "us-east-1"
	}
	return minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(r.Key, r.KeySecret, r.Token),
		Secure: true, Region: region, BucketLookup: lookup, Transport: tr,
	})
}
