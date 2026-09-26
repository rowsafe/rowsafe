package agent

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestValidateAdvisorMaintenance(t *testing.T) {
	ok := []protocol.MaintenanceParams{
		{Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"public.orders"}, Columns: []string{"customer_id"}},
		{Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{`"Odd"."T"`}, Columns: []string{"a", "B c"}},
		{Action: protocol.MaintDropInvalidIndex, DB: "shop", Index: "public.orders_x"},
		{Action: protocol.MaintSyncSequence, DB: "shop", Sequence: "public.items_id_seq"},
		{Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"public.orders"},
			Settings: map[string]string{"autovacuum_vacuum_scale_factor": "0", "autovacuum_vacuum_threshold": "50000"}},
	}
	for _, p := range ok {
		if err := validateMaintenance(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := map[string]protocol.MaintenanceParams{
		"no database":         {Action: protocol.MaintCreateIndex, Tables: []string{"t"}, Columns: []string{"a"}},
		"no table":            {Action: protocol.MaintCreateIndex, DB: "shop", Columns: []string{"a"}},
		"two tables":          {Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"a", "b"}, Columns: []string{"a"}},
		"no columns":          {Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"t"}},
		"empty column":        {Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"t"}, Columns: []string{""}},
		"long column":         {Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"t"}, Columns: []string{strings.Repeat("c", 64)}},
		"nul in column":       {Action: protocol.MaintCreateIndex, DB: "shop", Tables: []string{"t"}, Columns: []string{"a\x00b"}},
		"bad index":           {Action: protocol.MaintDropInvalidIndex, DB: "shop", Index: ""},
		"bad sequence":        {Action: protocol.MaintSyncSequence, DB: "shop", Sequence: ".x"},
		"no settings":         {Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"t"}},
		"unknown setting":     {Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"t"}, Settings: map[string]string{"fillfactor": "50"}},
		"sql in value":        {Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"t"}, Settings: map[string]string{"autovacuum_vacuum_threshold": "1); DROP TABLE t; --"}},
		"out of range":        {Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"t"}, Settings: map[string]string{"autovacuum_vacuum_scale_factor": "101"}},
		"fraction for an int": {Action: protocol.MaintSetTableStorageParams, DB: "shop", Tables: []string{"t"}, Settings: map[string]string{"autovacuum_vacuum_threshold": "1.5"}},
	}
	for name, p := range bad {
		if err := validateMaintenance(p); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

func TestIndexName(t *testing.T) {
	if got := indexName("orders", []string{"customer_id"}, 0); got != "orders_customer_id_idx" {
		t.Errorf("indexName = %q", got)
	}
	if got := indexName("orders", []string{"a", "b"}, 2); got != "orders_a_b_idx2" {
		t.Errorf("indexName = %q", got)
	}
	long := indexName(strings.Repeat("é", 40), []string{"x"}, 0)
	if len(long) > 63 || !strings.HasSuffix(long, "_idx") || !strings.HasPrefix(long, "é") {
		t.Errorf("long name %q (%d bytes)", long, len(long))
	}
}

func TestAdvisorMaintenanceAgainstPostgres(t *testing.T) {
	e := newFixEnv(t)
	e.exec(`CREATE TABLE customers (id serial PRIMARY KEY)`)
	e.exec(`INSERT INTO customers SELECT generate_series(1, 100)`)
	e.exec(`CREATE TABLE orders (id serial PRIMARY KEY, customer_id int REFERENCES customers, total int)`)
	e.exec(`INSERT INTO orders (customer_id, total) SELECT 1 + g % 100, g FROM generate_series(1, 5000) g`)

	t.Run("create index", func(t *testing.T) {
		res := e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
			Tables: []string{"public.orders"}, Columns: []string{"customer_id"}}, "Created the index orders_customer_id_idx on public.orders")
		if !e.exists("public.orders_customer_id_idx") || len(res.Details) != 2 {
			t.Fatalf("index missing or details %q", res.Details)
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
			Tables: []string{"public.orders"}, Columns: []string{"customer_id"}}, "already has an index on customer_id")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
			Tables: []string{"public.orders"}, Columns: []string{"nope"}}, `has no column "nope"`)
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
			Tables: []string{"public.orders_pkey"}, Columns: []string{"id"}}, "isn't a table")
		// An invalid index with the name Rowsafe would use (an earlier failed
		// build) is removed and built again.
		e.exec(`CREATE TABLE notes (v int, w int)`)
		e.exec(`INSERT INTO notes VALUES (1, 1), (1, 1)`)
		if _, err := e.conn.Exec(t.Context(), `CREATE UNIQUE INDEX CONCURRENTLY notes_v_idx ON notes (v)`); err == nil {
			t.Fatal("unique build over duplicates succeeded")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
			Tables: []string{"notes"}, Columns: []string{"v"}}, "Created the index notes_v_idx")
		var invalid int
		if err := e.conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_index WHERE indrelid = 'notes'::regclass AND NOT indisvalid`).Scan(&invalid); err != nil || invalid != 0 {
			t.Fatalf("%d invalid indexes left, %v", invalid, err)
		}
	})

	t.Run("drop invalid index", func(t *testing.T) {
		e.exec(`CREATE TABLE dupes (v int)`)
		e.exec(`INSERT INTO dupes VALUES (1), (1)`)
		if _, err := e.conn.Exec(t.Context(), `CREATE UNIQUE INDEX CONCURRENTLY dupes_v ON dupes (v)`); err == nil {
			t.Fatal("unique build over duplicates succeeded")
		}
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropInvalidIndex, DB: e.db, Index: "public.orders_pkey"},
			"is valid now")
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropInvalidIndex, DB: e.db, Index: "public.dupes_v"},
			"Removed the invalid index public.dupes_v")
		if e.exists("public.dupes_v") {
			t.Fatal("index still there")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropInvalidIndex, DB: e.db, Index: "public.dupes_v"},
			"already removed")
	})

	t.Run("sync sequence", func(t *testing.T) {
		e.exec(`CREATE TABLE items (id serial PRIMARY KEY, label text)`)
		e.exec(`INSERT INTO items (id, label) VALUES (1, 'a'), (2, 'b'), (50, 'c')`)
		if _, err := e.conn.Exec(t.Context(), `INSERT INTO items (label) VALUES ('d')`); err == nil {
			t.Fatal("insert with a stale sequence succeeded")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintSyncSequence, DB: e.db, Sequence: "public.items_id_seq"},
			"forward to 50")
		var id int
		if err := e.conn.QueryRow(t.Context(), `INSERT INTO items (label) VALUES ('e') RETURNING id`).Scan(&id); err != nil || id != 51 {
			t.Fatalf("insert after the fix: id %d, %v", id, err)
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintSyncSequence, DB: e.db, Sequence: "public.items_id_seq"},
			"already past")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintSyncSequence, DB: e.db, Sequence: "public.items"},
			"isn't a sequence")
		// A sequence named only in a DEFAULT (no OWNED BY) is found too.
		e.exec(`CREATE SEQUENCE loose_seq`)
		e.exec(`CREATE TABLE loose (id bigint PRIMARY KEY DEFAULT nextval('loose_seq'))`)
		e.exec(`INSERT INTO loose VALUES (7)`)
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintSyncSequence, DB: e.db, Sequence: "loose_seq"}, "forward to 7")
	})

	t.Run("set table storage params", func(t *testing.T) {
		res := e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintSetTableStorageParams, DB: e.db, Tables: []string{"public.orders"},
			Settings: map[string]string{"autovacuum_vacuum_scale_factor": "0", "autovacuum_vacuum_threshold": "50000"}},
			"autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 50000")
		var opts []string
		if err := e.conn.QueryRow(t.Context(), `SELECT reloptions FROM pg_class WHERE oid = 'orders'::regclass`).Scan(&opts); err != nil {
			t.Fatal(err)
		}
		if strings.Join(opts, ",") != "autovacuum_vacuum_scale_factor=0,autovacuum_vacuum_threshold=50000" {
			t.Fatalf("reloptions = %v", opts)
		}
		if len(res.Details) != 1 || !strings.Contains(res.Details[0], "RESET (autovacuum_vacuum_scale_factor, autovacuum_vacuum_threshold)") {
			t.Fatalf("details %q", res.Details)
		}
		res = e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintSetTableStorageParams, DB: e.db, Tables: []string{"public.orders"},
			Settings: map[string]string{"autovacuum_vacuum_threshold": "20000"}}, "autovacuum_vacuum_threshold = 20000")
		if !strings.Contains(res.Details[0], "SET (autovacuum_vacuum_threshold = 50000)") {
			t.Fatalf("undo %q", res.Details)
		}
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintSetTableStorageParams, DB: e.db, Tables: []string{"public.nope"},
			Settings: map[string]string{"autovacuum_vacuum_threshold": "1"}}, "no longer exists")
	})

	t.Run("no concurrent index build on a partitioned table", func(t *testing.T) {
		e.exec(`CREATE TABLE parted (id int, at date) PARTITION BY RANGE (at)`)
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db, Tables: []string{"parted"}, Columns: []string{"id"}},
			"partitioned table")
	})
}
