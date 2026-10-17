package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
)

// Querier runs a reading's queries: a *pgx.Conn, or a session of a
// connection string (session).
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// session is a connection the readings query. Over the socket its
// session carries the timeouts (startup parameters). A connection string
// may go through a connection pooler (PgBouncer, Supavisor, Neon's), which
// refuses those startup parameters and, in transaction mode, keeps no
// session state from one query to the next; there each query carries its
// own settings: SET LOCAL in the same message (the simple protocol), which
// PostgreSQL runs as one transaction, so nothing stays behind on a server
// connection that others use.
type session struct {
	*pgx.Conn
	// local sets the settings for one transaction ("" over the socket).
	local string
}

// connectSession opens a session to dbname with settings: as startup
// parameters over the socket, else carried by each query.
func (t Target) connectSession(ctx context.Context, dbname, app string, settings map[string]string) (*session, error) {
	cfg, err := t.config(dbname)
	if err != nil {
		return nil, err
	}
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["application_name"] = app
	if t.Conn == nil {
		for k, v := range settings {
			cfg.RuntimeParams[k] = v
		}
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return &session{Conn: conn}, nil
	}
	conn, err := pginspect.ConnectConfig(ctx, cfg, "application_name")
	if err != nil {
		return nil, err
	}
	return &session{Conn: conn, local: localSettings(settings)}, nil
}

// localSettings is one statement that sets settings for the current
// transaction only. Names and values are Rowsafe's own constants. A
// transaction's own read-only flag stands for default_transaction_read_only;
// idle_in_transaction_session_timeout has nothing to bound (each
// transaction is one message).
func localSettings(settings map[string]string) string {
	if len(settings) == 0 {
		return ""
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		if k == "idle_in_transaction_session_timeout" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	calls := make([]string, len(keys))
	for i, k := range keys {
		name := k
		if k == "default_transaction_read_only" {
			name = "transaction_read_only"
		}
		calls[i] = fmt.Sprintf("set_config('%s', '%s', true)", name, settings[k])
	}
	return "SELECT " + strings.Join(calls, ", ")
}

// Query runs sql, after the session's settings when each query carries
// them.
func (s *session) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if s.local == "" {
		return s.Conn.Query(ctx, sql, args...)
	}
	b := &pgx.Batch{}
	b.Queue(s.local)
	b.Queue(sql, args...)
	br := s.SendBatch(ctx, b)
	if _, err := br.Exec(); err != nil {
		br.Close()
		return nil, err
	}
	rows, err := br.Query()
	if err != nil {
		br.Close()
		return nil, err
	}
	return &batchRows{Rows: rows, br: br}, nil
}

// QueryRow is Query for one row, like pgx's.
func (s *session) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if s.local == "" {
		return s.Conn.QueryRow(ctx, sql, args...)
	}
	rows, err := s.Query(ctx, sql, args...)
	return &oneRow{rows: rows, err: err}
}

// batchRows are a query's rows in a batch, which ends with them.
type batchRows struct {
	pgx.Rows
	br     pgx.BatchResults
	closed bool
	err    error
}

func (r *batchRows) Next() bool {
	if r.closed {
		return false
	}
	if r.Rows.Next() {
		return true
	}
	r.Close()
	return false
}

func (r *batchRows) Close() {
	if r.closed {
		return
	}
	r.closed = true
	r.Rows.Close()
	r.err = r.br.Close()
}

func (r *batchRows) Err() error {
	if err := r.Rows.Err(); err != nil {
		return err
	}
	return r.err
}

// oneRow is the first row of rows, like pgx's QueryRow.
type oneRow struct {
	rows pgx.Rows
	err  error
}

func (r *oneRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	defer r.rows.Close()
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := r.rows.Scan(dest...); err != nil {
		return err
	}
	r.rows.Close()
	return r.rows.Err()
}
