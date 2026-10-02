//go:build clickhouse_integration

// Integration test against a real ClickHouse server, which must reach this
// process over the network (run it with scripts/test-clickhouse-gateway.sh,
// which uses the official clickhouse/clickhouse-server images):
//
//	ROWSAFE_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
//	ROWSAFE_TEST_CLICKHOUSE_GATEWAY_HOST=host.docker.internal \
//	go test -tags clickhouse_integration -run TestClickHouse ./internal/objstore/s3gw/
//
// ROWSAFE_TEST_CLICKHOUSE_USER/_PASSWORD log in (default: default, no
// password); ROWSAFE_TEST_CLICKHOUSE_ROWS sizes the data (default 3,000,000
// rows, a few hundred MB uncompressed).
package s3gw

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

const chMarker = "ROWSAFE-PLAINTEXT-MARKER"

type clickhouse struct {
	t          *testing.T
	url        string
	user, pass string
}

func (c *clickhouse) query(q string) string {
	c.t.Helper()
	return c.queryWith(q, "")
}

// queryWith runs q with session settings (URL parameters: ClickHouse 24.8
// refuses s3_* settings in a BACKUP's SETTINGS clause).
func (c *clickhouse) queryWith(q, settings string) string {
	c.t.Helper()
	out, err := c.try(q, settings)
	if err != nil {
		c.t.Fatalf("%s\n%v", q, err)
	}
	return out
}

func (c *clickhouse) try(q, settings string) (string, error) {
	u := c.url
	if settings != "" {
		u += map[bool]string{true: "&", false: "?"}[strings.Contains(u, "?")] + settings
	}
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(q))
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.pass)
	resp, err := (&http.Client{Timeout: 20 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return strings.TrimSpace(string(b)), nil
}

func gatewayFor(t *testing.T, store *objstore.Store, readOnly bool) *Gateway {
	t.Helper()
	host := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_GATEWAY_HOST")
	level := slog.LevelInfo
	if os.Getenv("ROWSAFE_TEST_GATEWAY_DEBUG") != "" {
		level = slog.LevelDebug
	}
	cfg := Config{Store: store, Passphrase: testPass, Prefixes: []string{"backup/"}, ReadOnly: readOnly, TempDir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: level}))}
	if host != "" && host != "127.0.0.1" && host != "localhost" {
		cfg.Listen = "0.0.0.0:0"
		cfg.PublicURL = "http://" + host
	}
	gw, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	return gw
}

func (g *Gateway) s3(key string) string {
	return fmt.Sprintf("S3('%s', '%s', '%s')", g.Endpoint(key), g.AccessKeyID(), g.SecretAccessKey())
}

func TestClickHouseBackupRestore(t *testing.T) {
	url := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_URL is not set")
	}
	ch := &clickhouse{t: t, url: url, user: cmp(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_USER"), "default"), pass: os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PASSWORD")}
	rows := 3_000_000
	if s := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ROWS"); s != "" {
		rows, _ = strconv.Atoi(s)
	}
	t.Logf("ClickHouse %s, %d rows", ch.query("SELECT version()"), rows)

	bucket := fakes3.New("bkt")
	t.Cleanup(bucket.Close)
	if d, _ := time.ParseDuration(os.Getenv("ROWSAFE_TEST_BUCKET_DELAY")); d > 0 {
		// A slow bucket: the last request of every multipart upload and
		// every large single upload take d, so the gateway answers
		// ClickHouse late.
		bucket.Fail = func(r *http.Request) int {
			if r.Method == http.MethodPost && r.URL.Query().Has("uploadId") || r.Method == http.MethodPut && r.ContentLength > 1<<20 && !r.URL.Query().Has("uploadId") {
				time.Sleep(d)
			}
			return 0
		}
	}
	store, err := objstore.New(pgbackrest.Repo{Endpoint: "http://" + bucket.Host(), Bucket: "bkt", Key: "k", KeySecret: "s",
		PathPrefix: "/rowsafe", Region: "us-east-1"}, "db_ch")
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{
		"DROP DATABASE IF EXISTS gw_src SYNC", "DROP DATABASE IF EXISTS gw_dst SYNC",
		"CREATE DATABASE gw_src",
		"CREATE TABLE gw_src.events (id UInt64, ts DateTime, user LowCardinality(String), payload String, value Float64) ENGINE = MergeTree ORDER BY id",
		"CREATE TABLE gw_src.users (id UInt64, name String, ver UInt32) ENGINE = ReplacingMergeTree(ver) ORDER BY id",
		"CREATE TABLE gw_src.notes (n UInt32, text String) ENGINE = Log",
		"CREATE MATERIALIZED VIEW gw_src.per_user ENGINE = SummingMergeTree ORDER BY user AS SELECT user, count() AS c, sum(value) AS s FROM gw_src.events GROUP BY user",
	} {
		ch.query(q)
	}
	insert := func(from, n int) {
		ch.query(fmt.Sprintf(`INSERT INTO gw_src.events SELECT number, toDateTime('2026-01-01 00:00:00') + number, concat('user', toString(number %% 97)),
			concat('%s ', toString(number), ' ', randomPrintableASCII(64)), number / 7 FROM numbers(%d, %d)`, chMarker, from, n))
		ch.query(fmt.Sprintf("INSERT INTO gw_src.users SELECT number %% 50000, concat('%s name ', toString(number)), number FROM numbers(%d, %d)", chMarker, from, n/10))
		ch.query(fmt.Sprintf("INSERT INTO gw_src.notes SELECT number, concat('%s note ', toString(number)) FROM numbers(%d, 1000)", chMarker, from))
	}
	insert(0, rows)

	// Small parts force multipart uploads of many files; the defaults
	// (32 MiB single uploads) are exercised by the big columns anyway.
	s3Settings := "s3_max_single_part_upload_size=8388608&s3_min_upload_part_size=5242880"
	full := gatewayFor(t, store, false)
	start := time.Now()
	out := ch.queryWith(fmt.Sprintf("BACKUP DATABASE gw_src TO %s", full.s3("backup/full")), s3Settings)
	st := full.Stats()
	t.Logf("full backup in %s: %s; %+v", time.Since(start).Round(time.Millisecond), out, st)
	if !strings.Contains(out, "BACKUP_CREATED") || st.Multipart == 0 || st.Errors != 0 {
		t.Fatalf("full backup: %s %+v", out, st)
	}
	full.Close()

	// More data, then a differential backup on top of the full one.
	insert(rows, rows/10)
	ch.query("OPTIMIZE TABLE gw_src.users FINAL")
	incr := gatewayFor(t, store, false)
	start = time.Now()
	out = ch.queryWith(fmt.Sprintf("BACKUP DATABASE gw_src TO %s SETTINGS base_backup = %s", incr.s3("backup/incr"), incr.s3("backup/full")), s3Settings)
	st = incr.Stats()
	t.Logf("incremental backup in %s: %s; %+v", time.Since(start).Round(time.Millisecond), out, st)
	if !strings.Contains(out, "BACKUP_CREATED") || st.Errors != 0 {
		t.Fatalf("incremental backup: %s %+v", out, st)
	}
	incr.Close()

	// Restore from the incremental through a read-only gateway (another
	// port and other credentials than at backup time).
	ro := gatewayFor(t, store, true)
	start = time.Now()
	out = ch.query(fmt.Sprintf("RESTORE DATABASE gw_src AS gw_dst FROM %s SETTINGS base_backup = %s", ro.s3("backup/incr"), ro.s3("backup/full")))
	st = ro.Stats()
	t.Logf("restore in %s: %s; %+v", time.Since(start).Round(time.Millisecond), out, st)
	if !strings.Contains(out, "RESTORED") || st.Errors != 0 || st.ObjectsRead == 0 {
		t.Fatalf("restore: %s %+v", out, st)
	}

	for _, tbl := range []string{"events", "users", "notes", "per_user"} {
		q := "SELECT count(), sum(cityHash64(*)) FROM %s.%s"
		if tbl == "users" || tbl == "per_user" {
			q = "SELECT count(), sum(cityHash64(*)) FROM %s.%s FINAL"
		}
		a, b := ch.query(fmt.Sprintf(q, "gw_src", tbl)), ch.query(fmt.Sprintf(q, "gw_dst", tbl))
		t.Logf("%s: %s / %s", tbl, a, b)
		if a != b || strings.HasPrefix(a, "0\t") {
			t.Fatalf("%s differs after the restore: %s vs %s", tbl, a, b)
		}
	}
	if engine := ch.query("SELECT engine FROM system.tables WHERE database = 'gw_dst' AND name = 'per_user'"); engine != "MaterializedView" {
		t.Fatalf("the materialized view came back as %q", engine)
	}

	// The bucket holds only ciphertext that opens with the passphrase.
	var total int64
	keys := bucket.Keys()
	for _, k := range keys {
		raw, _ := bucket.Object(k)
		total += int64(len(raw))
		if bytes.Contains(raw, []byte(chMarker)) || bytes.Contains(raw, []byte("gw_src")) {
			t.Fatalf("%s holds plaintext", k)
		}
		r, err := objstore.Open(bytes.NewReader(raw), testPass)
		if err == nil {
			_, err = io.Copy(io.Discard, r)
		}
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	t.Logf("bucket: %d objects, %d MB, no plaintext", len(keys), total>>20)
	ch.query("DROP DATABASE gw_dst SYNC")
	ch.query("DROP DATABASE gw_src SYNC")
}

func cmp(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
