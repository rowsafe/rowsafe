//go:build opensearch_integration

// Integration test against a real OpenSearch, with its program installed
// (Proof and copies start their own). Run it with scripts/test-opensearch.sh,
// which runs it inside the official opensearchproject/opensearch image set
// up like the installer's --install-opensearch (security plugin on, no demo
// users, TLS on the REST port, Rowsafe's snapshot folder in path.repo):
//
//	ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD=... go test -tags opensearch_integration ./internal/engine/opensearch/
package opensearch

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type testLog struct {
	t  *testing.T
	mu sync.Mutex
}

func (l *testLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.t.Logf(format, args...)
}

func (l *testLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s output:\n%s", label, out)
	}
}

func run[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	task := &protocol.Task{ID: "task_" + strconv.FormatInt(time.Now().UnixNano(), 36), Type: typ, Database: &db, Params: raw}
	res, err := e.Run(context.Background(), env, task, &testLog{t: t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func mustRun[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) *T {
	t.Helper()
	r, err := run[T](t, e, env, db, typ, params)
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return r
}

// admin is a client signed in as the server's administrator.
func admin(t *testing.T) *client {
	t.Helper()
	c, err := dial(context.Background(), 9200, Login{User: "admin", Password: os.Getenv("ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD")})
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	return c
}

func put(t *testing.T, c *client, path string, body any) {
	t.Helper()
	if err := c.do(context.Background(), http.MethodPut, path, body, nil); err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
}

func count(t *testing.T, c *client, index string) int64 {
	t.Helper()
	_ = c.do(context.Background(), http.MethodPost, "/"+index+"/_refresh", nil, nil)
	n, err := countOf(context.Background(), c, index)
	if err != nil {
		t.Fatalf("count %s: %v", index, err)
	}
	return n
}

func TestOpenSearch(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD") == "" {
		t.Skip("ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD not set")
	}
	if d := os.Getenv("ROWSAFE_TEST_TLS_DIR"); d != "" {
		tlsDir = d
	}
	dir := t.TempDir()
	s3 := fakes3.New("bkt")
	t.Cleanup(s3.Close)
	env := agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "opensearch"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes: os.Stderr,
	}
	e := &Engine{}
	db := protocol.DatabaseSpec{ID: "db_os", Name: "search", Stanza: "search", Port: 9200, RetentionFull: 2, Engine: protocol.EngineOpenSearch}

	// The installer's helpers.
	if st, err := ServerStatus(ctx, env, 9200); err != nil || st.Login != "missing" || st.Security != "on" || st.TLS != "on" {
		t.Fatalf("status before login: %+v %v", st, err)
	}
	if err := CreateLogin(ctx, env, 9200, "", ""); err != ErrNeedAdmin {
		t.Fatalf("no admin: %v", err)
	}
	if err := CreateLogin(ctx, env, 9200, "admin", "wrong"); err != ErrAdminRefused {
		t.Fatalf("wrong admin: %v", err)
	}
	if err := CreateLogin(ctx, env, 9200, "admin", os.Getenv("ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD")); err != nil {
		t.Fatalf("login: %v", err)
	}
	st, err := ServerStatus(ctx, env, 9200)
	if err != nil || st.Login != "ok" || st.Repo != "ok" || st.RestAPI != "ok" {
		t.Fatalf("status: %+v %v", st, err)
	}
	t.Logf("status: %+v", st)

	// Some data: an index and a data stream.
	a := admin(t)
	put(t, a, "/products", map[string]any{"settings": map[string]any{"number_of_replicas": 0}})
	var bulk bytes.Buffer
	for i := range 50 {
		fmt.Fprintf(&bulk, `{"index":{"_index":"products","_id":"p%d"}}`+"\n"+`{"name":"product %d","price":%d}`+"\n", i, i, i*10)
	}
	if _, _, err := a.raw(ctx, http.MethodPost, "/_bulk?refresh=true", &bulk, "application/x-ndjson"); err != nil {
		t.Fatal(err)
	}
	put(t, a, "/_index_template/logs", map[string]any{"index_patterns": []string{"logs-*"}, "data_stream": map[string]any{},
		"template": map[string]any{"settings": map[string]any{"number_of_replicas": 0}}})
	for i := range 5 {
		if err := a.do(ctx, http.MethodPost, "/logs-app/_doc?refresh=true", map[string]any{"@timestamp": time.Now().UTC().Format(time.RFC3339), "n": i}, nil); err != nil {
			t.Fatal(err)
		}
	}

	ad := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if ad.Applied || len(ad.Inspect.Databases) != 2 {
		t.Fatalf("plan: %+v", ad)
	}
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if ck := mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil); !ck.OK {
		t.Fatal("check")
	}
	full := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if !strings.HasSuffix(full.Label, "F") {
		t.Fatalf("full: %+v", full)
	}
	// Everything in the bucket is sealed; index names never appear in keys.
	repoKeys := 0
	for _, k := range s3.Keys() {
		obj, _ := s3.Object(k)
		if !bytes.HasPrefix(obj, []byte("RWSF1\n")) {
			t.Errorf("%s isn't sealed", k)
		}
		if strings.Contains(k, "products") {
			t.Errorf("an index name in a key: %s", k)
		}
		if strings.Contains(k, "/repo/") {
			repoKeys++
		}
	}
	if repoKeys < 5 {
		t.Fatalf("the repository's copy in the bucket has %d files", repoKeys)
	}

	// More documents, a Mark, then some deleted.
	for i := 50; i < 60; i++ {
		put(t, a, fmt.Sprintf("/products/_doc/p%d?refresh=true", i), map[string]any{"name": fmt.Sprintf("product %d", i)})
	}
	mk := mustRun[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-delete"})
	if !strings.HasSuffix(mk.LSN, "M") {
		t.Fatalf("mark: %+v", mk)
	}
	if err := a.do(ctx, http.MethodPost, "/products/_delete_by_query?refresh=true", map[string]any{"query": map[string]any{"range": map[string]any{"price": map[string]any{"lt": 100}}}}, nil); err != nil {
		t.Fatal(err)
	}
	put(t, a, "/products/_doc/p0?refresh=true", map[string]any{"name": "changed"})
	if n := count(t, a, "products"); n != 51 {
		t.Fatalf("after delete: %d", n)
	}
	diff := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff})
	if !strings.HasSuffix(diff.Label, "D") {
		t.Fatalf("diff: %+v", diff)
	}

	// Proof restores the newest snapshot from the bucket.
	dr := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if !dr.Passed || dr.BackupLabel != diff.Label {
		t.Fatalf("drill: %+v", dr)
	}

	// A copy at the Mark: compare, bring the deleted documents back.
	cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c1",
		Target: protocol.RewindTarget{Mark: "before-delete", BackupSet: mk.LSN}, Expires: time.Now().Add(time.Hour)})
	if cp.Port == 0 || len(cp.Databases) != 2 {
		t.Fatalf("copy: %+v", cp)
	}
	if states := e.RewindStates(env); len(states) != 1 || states[0].Status != protocol.RewindCopyReady {
		t.Fatalf("states: %+v", states)
	}
	cmp := mustRun[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"})
	var pd protocol.RewindTableDiff
	for _, x := range cmp.Tables {
		if x.DB == "products" {
			pd = x
		}
	}
	if pd.MissingInProduction != 9 || pd.Changed != 1 {
		t.Fatalf("compare: %+v", cmp.Tables)
	}
	rows := mustRun[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "c1",
		Tables: []protocol.RewindTable{{DB: "products", Table: "*"}}})
	if rows.Tables[0].Inserted != 9 || rows.Tables[0].Updated != 0 {
		t.Fatalf("rows: %+v", rows)
	}
	if n := count(t, a, "products"); n != 60 {
		t.Fatalf("after bringing back: %d", n)
	}
	mustRun[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "c1",
		Tables: []protocol.RewindTable{{DB: "products", Table: "*"}}, IncludeChanged: true})
	var p0 struct {
		Source map[string]any `json:"_source"`
	}
	_ = a.get(ctx, "/products/_doc/p0", &p0)
	if p0.Source["name"] != "product 0" {
		t.Fatalf("include changed: %+v", p0)
	}
	drop := mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"})
	if !drop.Removed {
		t.Fatal("drop")
	}

	// Rewind in place to the first full snapshot, then Undo.
	put(t, a, "/extra", map[string]any{"settings": map[string]any{"number_of_replicas": 0}})
	ip := mustRun[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace, protocol.RewindInPlaceParams{RewindID: "r1",
		Target: protocol.RewindTarget{BackupSet: full.Label}, KeepDays: 1})
	if ip.RolledBack || ip.KeptUntil == nil {
		t.Fatalf("in place: %+v", ip)
	}
	if n := count(t, a, "products"); n != 50 {
		t.Fatalf("after rewind: %d", n)
	}
	if err := a.get(ctx, "/extra", nil); statusOf(err) != http.StatusNotFound {
		t.Fatalf("an index made after the snapshot is still there: %v", err)
	}
	if n := count(t, a, "logs-app"); n != 5 {
		t.Fatalf("data stream after rewind: %d", n)
	}
	un := mustRun[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "r1"})
	if un.RolledBack {
		t.Fatalf("undo: %+v", un)
	}
	if n := count(t, a, "products"); n != 60 {
		t.Fatalf("after undo: %d", n)
	}
	cl := mustRun[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "r1"})
	if !cl.Removed || len(e.keptStates(env)) != 0 {
		t.Fatalf("cleanup: %+v", cl)
	}

	// Databases & users.
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub := protocol.EncodeSealKey(priv.PublicKey())
	ls := mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminList})
	if ls.Inventory == nil || ls.Inventory.ManageBlocked != "" || len(ls.Inventory.Users) < 2 {
		t.Fatalf("list: %+v", ls.Inventory)
	}
	cu, err := e.dbadmin(ctx, env, db, "task_reader", protocol.DBAdminParams{Action: protocol.DBAdminCreateUser,
		User: "reader", Access: protocol.DBAccessReadOnly, Databases: []string{"products"}, PublicKey: pub}, &testLog{t: t})
	if err != nil || cu.Secret == nil || cu.Connection == nil || cu.Connection.SSLMode != "require" {
		t.Fatalf("create user: %+v %v", cu, err)
	}
	plain, err := protocol.Open(priv, []byte("task_reader"), cu.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var secret protocol.DBSecret
	_ = json.Unmarshal(plain, &secret)
	if !strings.HasPrefix(secret.URL, "https://reader:") {
		t.Fatalf("url %q", secret.URL)
	}
	rc, err := dial(ctx, 9200, Login{User: "reader", Password: secret.Password})
	if err != nil {
		t.Fatalf("the new user signs in: %v", err)
	}
	if err := rc.get(ctx, "/products/_search?size=1", nil); err != nil {
		t.Fatalf("reader searches: %v", err)
	}
	if err := rc.do(ctx, http.MethodPut, "/products/_doc/x", map[string]any{"a": 1}, nil); statusOf(err) != http.StatusForbidden {
		t.Fatalf("reader writes: %v", err)
	}
	drop2 := mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "reader"})
	if strings.Contains(fmt.Sprint(drop2.Inventory.Users), "reader") {
		t.Fatal("drop user")
	}
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase,
		Database: "orders", CreateOwner: true, PublicKey: pub})
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase,
		Database: "orders", Confirm: "orders"})
	if _, err := run[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "admin"}); err == nil {
		t.Fatal("dropping admin")
	}

	// A fix: replicas a single node can't place.
	put(t, a, "/yellow", map[string]any{"settings": map[string]any{"number_of_replicas": 1}})
	mon, _ := e.Monitor(ctx, env, db)
	if mon.OpenSearch == nil || mon.OpenSearch.Status != "yellow" || len(mon.OpenSearch.UnassignedReplicaIndices) == 0 {
		t.Fatalf("monitor: %+v %+v", mon, mon.OpenSearch)
	}
	mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintOpenSearchReplicas})
	var h struct {
		Status string `json:"status"`
	}
	_ = a.get(ctx, "/_cluster/health?wait_for_status=green&timeout=30s", &h)
	if h.Status != "green" {
		t.Fatalf("after the fix: %s", h.Status)
	}
	mon, _ = e.Monitor(ctx, env, db)
	if mon.Error != "" || mon.OpenSearch.HeapMaxBytes == 0 || mon.OpenSearch.Snapshots == 0 || !mon.OpenSearch.SecurityPlugin || !mon.OpenSearch.TLS {
		t.Fatalf("monitor: %+v", mon.OpenSearch)
	}
	rep, err := e.SecurityReport(ctx, env, db)
	if err != nil || rep.EngineSecurity.AuthDisabled || !rep.SSL || len(rep.Roles) < 2 {
		t.Fatalf("security: %+v %v", rep, err)
	}

	// Retention keeps the newest 2 full snapshots and what follows.
	for range 2 {
		time.Sleep(1100 * time.Millisecond)
		mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	}
	c, _ := connectDB(ctx, env, db)
	snaps, _ := listSnapshots(ctx, c)
	for _, s := range snaps {
		if s.Snapshot == snapshotName(full.Label) || s.Snapshot == snapshotName(mk.LSN) {
			t.Errorf("retention kept %s", s.Snapshot)
		}
	}

	// A certificate from another issuer is loaded without a restart.
	if os.Getenv("ROWSAFE_TEST_TLS_DIR") != "" {
		tl, err := e.ServerTLS(ctx, env, db)
		if err != nil || tl.CertFile == "" {
			t.Fatalf("server tls: %+v %v", tl, err)
		}
		certPEM, keyPEM := otherIssuerCert(t)
		if err := os.WriteFile(tl.CertFile, certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tl.KeyFile, keyPEM, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := tl.Reload(ctx); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
}

// otherIssuerCert is a certificate for localhost from a CA other than the
// one in place (like Let's Encrypt's), its key as the agent writes it (EC).
func otherIssuerCert(t *testing.T) (certPEM, keyPEM []byte) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Test Issuer R1"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "db.example.test"}, DNSNames: []string{"db.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := x509.MarshalECPrivateKey(key)
	certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ec})
}
