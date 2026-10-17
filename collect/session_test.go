package collect

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestLocalSettings(t *testing.T) {
	got := localSettings(map[string]string{"statement_timeout": "2000", "default_transaction_read_only": "on", "idle_in_transaction_session_timeout": "10000"})
	want := "SELECT set_config('default_transaction_read_only', 'on', true)"
	if strings.Contains(got, "idle_in") || !strings.Contains(got, "set_config('transaction_read_only', 'on', true)") ||
		!strings.Contains(got, "set_config('statement_timeout', '2000', true)") || got == want {
		t.Errorf("localSettings = %q", got)
	}
	if localSettings(nil) != "" {
		t.Error("no settings, no statement")
	}
}

// Through a connection string (a pooler's with ROWSAFE_TEST_POOLER_URL,
// else the local PostgreSQL's), each query carries the timeouts and the
// session keeps none.
func TestSessionCarriesSettings(t *testing.T) {
	url := os.Getenv("ROWSAFE_TEST_POOLER_URL")
	if url == "" {
		u, err := user.Current()
		if err != nil {
			t.Skip(err)
		}
		url = fmt.Sprintf("postgres://%s@/postgres?host=/tmp&port=5432", u.Username)
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Conn: cfg}
	s, err := tg.insightsConnect(t.Context(), tg.MaintenanceDB())
	if err != nil {
		t.Skipf("no PostgreSQL at %s: %v", tg, err)
	}
	defer s.Close(context.Background())
	var timeout, lock, ro string
	if err := s.QueryRow(t.Context(), `SELECT current_setting('statement_timeout'), current_setting('lock_timeout'), current_setting('transaction_read_only')`).Scan(&timeout, &lock, &ro); err != nil {
		t.Fatal(err)
	}
	if timeout != "5s" || lock != "200ms" || ro != "on" {
		t.Errorf("in a query: statement_timeout %s, lock_timeout %s, read only %s", timeout, lock, ro)
	}
	if err := s.Conn.QueryRow(t.Context(), `SELECT current_setting('statement_timeout'), current_setting('transaction_read_only')`).Scan(&timeout, &ro); err != nil {
		t.Fatal(err)
	}
	if timeout == "5s" || ro != "off" {
		t.Errorf("left in the session: statement_timeout %s, read only %s", timeout, ro)
	}
	// Bounded, and read-only.
	run := func(sql string) error {
		rows, err := s.Query(t.Context(), sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
		}
		return rows.Err()
	}
	if err := run(`SELECT pg_sleep(6)`); err == nil || !strings.Contains(err.Error(), "statement timeout") {
		t.Errorf("a slow query ran: %v", err)
	}
	if err := run(`CREATE TEMP TABLE rowsafe_x (a int)`); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("a write ran: %v", err)
	}
	// Errors leave the connection usable, rows and arguments come back.
	var n int
	var names []string
	if err := s.QueryRow(t.Context(), `SELECT $1::int + 1, $2::text[]`, 41, []string{"a", "b'c"}).Scan(&n, &names); err != nil || n != 42 || len(names) != 2 || names[1] != "b'c" {
		t.Errorf("after errors: %d %v %v", n, names, err)
	}
	if err := s.QueryRow(t.Context(), `SELECT 1 WHERE false`).Scan(&n); err != pgx.ErrNoRows {
		t.Errorf("no rows: %v", err)
	}
}
