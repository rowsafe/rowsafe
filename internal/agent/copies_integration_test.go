package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Integration tests against a real PostgreSQL (ROWSAFE_TEST_DATABASE_URL,
// e.g. postgres:///rowsafe_test?host=/tmp, as a superuser with trust or
// peer auth on the socket). Each test works in its own scratch database and
// stands in for a restored copy: the preview and masking code only needs a
// cluster it may change.

func testCluster(t *testing.T) (pginspect.Target, *pgx.Conn) {
	t.Helper()
	url := os.Getenv("ROWSAFE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ROWSAFE_TEST_DATABASE_URL not set")
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	tgt := pginspect.Target{SocketDir: cfg.Host, Port: int(cfg.Port), User: cfg.User, AppName: "rowsafe-test"}
	ctx := context.Background()
	conn, err := copyConnect(ctx, tgt, "postgres")
	if err != nil {
		t.Skipf("can't connect to the test cluster: %v", err)
	}
	var super bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil || !super {
		conn.Close(ctx)
		t.Skip("the test cluster user is not a superuser")
	}
	var user string
	_ = conn.QueryRow(ctx, `SELECT current_user`).Scan(&user)
	tgt.User = user
	t.Cleanup(func() { conn.Close(context.Background()) })
	return tgt, conn
}

// scratchDB creates a database dropped at the end of the test, and makes
// sure the Guard roles are dropped too.
func scratchDB(t *testing.T, conn *pgx.Conn, roles ...string) string {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("rowsafe_copies_test_%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dropping %s: %v", name, err)
		}
		for _, r := range append(roles, previewRole, copyOwnerRole) {
			if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+r); err != nil {
				t.Errorf("dropping role %s: %v", r, err)
			}
		}
	})
	return name
}

func execAll(t *testing.T, tgt pginspect.Target, db, sql string) {
	t.Helper()
	c, err := copyConnect(context.Background(), tgt, db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%v\n%s", err, sql)
	}
}

func testAgent(t *testing.T, pgUser string) *Agent {
	return &Agent{cfg: Config{StateDir: t.TempDir(), PGUser: pgUser}, log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))}
}

func runTestPreview(t *testing.T, a *Agent, super pginspect.Target, db, sql string) *protocol.PreviewResult {
	t.Helper()
	stmts, err := preview.Split(sql)
	if err != nil {
		t.Fatal(err)
	}
	res := &protocol.PreviewResult{PreviewID: "test", DB: db, Mode: preview.Mode(stmts)}
	runner := super
	runner.User = previewRole
	tl := &taskLog{}
	if err := a.runPreview(context.Background(), super, runner, db, stmts, res, time.Minute, tl); err != nil {
		t.Fatalf("runPreview: %v\n%s", err, tl.String())
	}
	var texts []string
	for _, s := range stmts {
		texts = append(texts, s.Text)
	}
	preview.Assess(res, texts)
	return res
}

func TestPreviewOnCopy(t *testing.T) {
	tgt, conn := testCluster(t)
	ctx := context.Background()
	db := scratchDB(t, conn)
	execAll(t, tgt, db, `
		CREATE TABLE users (id bigserial PRIMARY KEY, email text UNIQUE NOT NULL, phone text);
		CREATE TABLE orders (id bigserial PRIMARY KEY, user_id bigint REFERENCES users, total numeric NOT NULL, note text);
		INSERT INTO users (email, phone) SELECT 'user' || g || '@corp.example', '+1 555 01' || lpad(g::text, 4, '0') FROM generate_series(1, 2000) g;
		INSERT INTO orders (user_id, total) SELECT 1 + g % 2000, g * 1.5 FROM generate_series(1, 200000) g;
		ANALYZE;`)
	a := testAgent(t, tgt.User)
	if _, err := conn.Exec(ctx, "CREATE ROLE "+previewRole+" LOGIN"); err != nil {
		t.Fatal(err)
	}
	tl := &taskLog{}
	if err := prepareRoles(ctx, tgt, conn, []string{db}, previewRole, tl); err != nil {
		t.Fatalf("prepareRoles: %v", err)
	}

	t.Run("rewrite, index, update", func(t *testing.T) {
		res := runTestPreview(t, a, tgt, db, `
ALTER TABLE orders ADD COLUMN ref uuid DEFAULT gen_random_uuid();
CREATE INDEX orders_total ON orders (total);
UPDATE orders SET note = 'checked' WHERE id <= 150000;
CREATE TABLE things (id int);`)
		if res.Error != nil {
			t.Fatalf("error: %+v", res.Error)
		}
		s := res.Statements
		if len(s[0].Rewrites) != 1 || s[0].Rewrites[0].Name != "public.orders" || s[0].Rewrites[0].SizeBytes == 0 {
			t.Errorf("statement 1 rewrites: %+v", s[0].Rewrites)
		}
		if len(s[0].Locks) == 0 || s[0].Locks[0].Mode != "AccessExclusiveLock" || s[0].Locks[0].Relation != "public.orders" {
			t.Errorf("statement 1 locks: %+v", s[0].Locks)
		}
		if s[0].Locks[0].HeldMs < s[0].DurationMs {
			t.Errorf("in one transaction the lock lasts until COMMIT: held %d ms, statement %d ms", s[0].Locks[0].HeldMs, s[0].DurationMs)
		}
		if len(s[1].IndexBuilds) != 1 || s[1].IndexBuilds[0].Table != "public.orders" {
			t.Errorf("statement 2 index builds: %+v", s[1].IndexBuilds)
		}
		if s[2].Rows == nil || *s[2].Rows != 150000 {
			t.Errorf("statement 3 rows: %v", s[2].Rows)
		}
		if len(s[3].Locks) != 0 || len(s[3].Rewrites) != 0 {
			t.Errorf("a new table is harmless: %+v", s[3])
		}
		if res.Verdict == protocol.PreviewSafe || res.Verdict == protocol.PreviewFailed {
			t.Errorf("verdict %s: %s", res.Verdict, res.Summary)
		}
		found := map[string]bool{}
		for _, f := range res.Findings {
			found[f.Rule] = true
		}
		for _, r := range []string{"table_rewrite", "no_lock_timeout", "large_data_change"} {
			if !found[r] {
				t.Errorf("missing finding %s: %+v", r, res.Findings)
			}
		}
		t.Logf("%s\n%s", res.Summary, preview.Text(res))
	})

	t.Run("failure stops the run and hides data values", func(t *testing.T) {
		res := runTestPreview(t, a, tgt, db, `
ALTER TABLE users ADD COLUMN nickname text;
ALTER TABLE users ALTER COLUMN phone TYPE int USING phone::int;
DROP TABLE orders;`)
		if res.Error == nil || res.Error.Statement != 2 || res.Error.Line != 3 || res.Verdict != protocol.PreviewFailed {
			t.Fatalf("error %+v verdict %s", res.Error, res.Verdict)
		}
		if strings.Contains(res.Error.Message, "555") || !strings.Contains(res.Error.Message, "a value from your data") {
			t.Errorf("message not redacted: %q", res.Error.Message)
		}
		if res.Statements[2].Ran {
			t.Error("statement 3 ran after a failure")
		}
		// Nothing of a failed transaction stays on the copy.
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_database WHERE datname = $1`, db).Scan(&n); err != nil || n != 1 {
			t.Fatal(err)
		}
		c, _ := copyConnect(ctx, tgt, db)
		defer c.Close(ctx)
		if err := c.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'nickname'`).Scan(&n); err != nil || n != 0 {
			t.Errorf("the failed migration left nickname behind (%d, %v)", n, err)
		}
	})

	t.Run("never a superuser", func(t *testing.T) {
		res := runTestPreview(t, a, tgt, db, `COPY (SELECT 1) TO PROGRAM 'id';`)
		if res.Error == nil || res.Error.Code != "42501" {
			t.Fatalf("COPY TO PROGRAM ran as a superuser: %+v", res.Error)
		}
		res = runTestPreview(t, a, tgt, db, `RESET ROLE; SET ROLE `+tgt.User+`;`)
		if res.Error == nil {
			t.Fatal("the migration could become a superuser")
		}
	})

	t.Run("as written: CONCURRENTLY and explicit transactions", func(t *testing.T) {
		res := runTestPreview(t, a, tgt, db, `
SET lock_timeout = '5s';
CREATE INDEX CONCURRENTLY orders_user ON orders (user_id);
BEGIN;
ALTER TABLE orders ADD COLUMN flag boolean;
COMMIT;`)
		if res.Mode != protocol.PreviewAsWritten || res.Error != nil {
			t.Fatalf("mode %s error %+v", res.Mode, res.Error)
		}
		if len(res.Statements[1].IndexBuilds) != 1 {
			t.Errorf("concurrent index build not seen: %+v", res.Statements[1])
		}
		if l := res.Statements[3].Locks; len(l) == 0 || l[0].Mode != "AccessExclusiveLock" {
			t.Errorf("lock inside the explicit transaction not seen: %+v", l)
		}
		for _, f := range res.Findings {
			if f.Rule == "no_lock_timeout" || f.Rule == "create_index_blocks_writes" {
				t.Errorf("unexpected finding %+v", f)
			}
		}
	})

	t.Run("drop table", func(t *testing.T) {
		res := runTestPreview(t, a, tgt, db, `DROP TABLE orders;`)
		if len(res.Statements[0].Dropped) != 1 || res.Verdict != protocol.PreviewDangerous {
			t.Fatalf("%+v %s", res.Statements[0], res.Verdict)
		}
	})
}

func TestMaskCopy(t *testing.T) {
	tgt, conn := testCluster(t)
	ctx := context.Background()
	db := scratchDB(t, conn)
	execAll(t, tgt, db, `
		CREATE TABLE users (id bigserial PRIMARY KEY, email text UNIQUE NOT NULL, first_name text, phone text NOT NULL,
			password_digest text, signup_ip inet, notes text, plan text, birth_date date,
			email_lower text GENERATED ALWAYS AS (lower(email)) STORED);
		CREATE TABLE orders (id bigserial PRIMARY KEY, customer_email text, total numeric NOT NULL)
			PARTITION BY RANGE (id);
		CREATE TABLE orders_1 PARTITION OF orders FOR VALUES FROM (1) TO (1000000);
		INSERT INTO users (email, first_name, phone, password_digest, signup_ip, notes, plan, birth_date)
		SELECT 'user' || g || '@corp.example', 'Real' || g, '+44 20 7946 ' || lpad(g::text, 4, '0'),
		       '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW', ('203.0.113.' || (g % 250))::inet,
		       'Called about invoice ' || g, 'pro', '1980-01-01'::date + g
		FROM generate_series(1, 3000) g;
		INSERT INTO orders (customer_email, total) SELECT 'user' || (1 + g % 3000) || '@corp.example', g FROM generate_series(1, 9000) g;
		CREATE MATERIALIZED VIEW user_emails AS SELECT email FROM users;
		ANALYZE;`)
	a := testAgent(t, tgt.User)
	plan := protocol.MaskingPlan{Mode: protocol.MaskingRules, Rules: []protocol.MaskingRule{
		{DB: db, Table: "public.users", Column: "phone", Strategy: masking.Null},      // NOT NULL: skipped
		{DB: db, Table: "public.users", Column: "plan", Strategy: masking.Keep},       // kept
		{DB: db, Table: "public.orders", Column: "customer_email", Strategy: "email"}, // partition follows its parent
		{DB: db, Table: "public.users", Column: "notes", Strategy: masking.Noise},     // doesn't fit text: suggestion used
	}}
	tl := &taskLog{}
	report, err := a.maskCopy(ctx, tgt, []string{db}, plan, tl)
	if err != nil {
		t.Fatalf("%v\n%s", err, tl.String())
	}
	t.Log(tl.String())
	c, err := copyConnect(ctx, tgt, db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	one := func(q string, dest ...any) {
		t.Helper()
		if err := c.QueryRow(ctx, q).Scan(dest...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var n int
	one(`SELECT count(*) FROM users WHERE email LIKE '%@corp.example' OR first_name LIKE 'Real%' OR notes LIKE '%invoice%'
	     OR signup_ip << '203.0.113.0/24' OR password_digest LIKE '$2a$12$%'`, &n)
	if n != 0 {
		t.Errorf("%d users still have real values", n)
	}
	one(`SELECT count(DISTINCT email) FROM users`, &n)
	if n != 3000 {
		t.Errorf("emails not unique: %d distinct", n)
	}
	one(`SELECT count(*) FROM orders o JOIN users u ON u.email = o.customer_email`, &n)
	if n != 9000 {
		t.Errorf("masking is not consistent across tables: %d of 9000 orders still match their user", n)
	}
	var plan1, phone, lower, email string
	one(`SELECT plan, phone, email_lower, email FROM users ORDER BY id LIMIT 1`, &plan1, &phone, &lower, &email)
	if plan1 != "pro" || !strings.HasPrefix(phone, "+44 20 7946") || lower != strings.ToLower(email) {
		t.Errorf("plan %q phone %q email_lower %q email %q", plan1, phone, lower, email)
	}
	one(`SELECT count(*) FROM pg_stats WHERE tablename = 'users' AND attname = 'email' AND most_common_vals::text LIKE '%corp.example%'
	     OR (tablename = 'users' AND attname = 'email' AND histogram_bounds::text LIKE '%corp.example%')`, &n)
	if n != 0 {
		t.Error("pg_stats still shows real emails")
	}
	one(`SELECT count(*) FROM user_emails WHERE email LIKE '%@corp.example'`, &n)
	if n != 0 {
		t.Error("the materialized view still holds real emails")
	}
	if report.Tables != 2 || report.Strategies["email"] != 2 || report.Rows < 3000 {
		t.Errorf("report %+v", report)
	}
	skipped := strings.Join(report.Skipped, "\n")
	for _, want := range []string{"phone can't be emptied", "doesn't fit its type", "email_lower is computed"} {
		if !strings.Contains(skipped, want) {
			t.Errorf("skipped %q misses %q", skipped, want)
		}
	}
	// Deterministic: masking the same value again gives the same result.
	key, _ := a.maskKey()
	want, _ := masking.New(key).Value(masking.Email, "user1@corp.example", masking.Options{})
	one(`SELECT email FROM users WHERE id = 1`, &email)
	if email != want {
		t.Errorf("email %q, want %q", email, want)
	}
}
