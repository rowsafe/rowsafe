package pginspect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Connection poolers (PgBouncer, Supavisor, Neon's pooler) sit between a
// connection string and PostgreSQL. They refuse startup parameters they
// don't know (statement_timeout, lock_timeout, ...), and in transaction
// mode each transaction may run on another server connection: session
// settings don't carry over from one statement to the next, and a SET
// stays behind on a server connection that other applications then use.
// So through a connection string nothing relies on session state: queries
// use the simple protocol (no prepared statements), reads carry their own
// timeouts (collect), and the fixes that need one session are refused
// through a pooler (Pooler).

// StartupRefused reports whether err is a server (most often a pooler)
// refusing a startup parameter: SQLSTATE 08P01 "unsupported startup
// parameter".
func StartupRefused(err error) bool {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return false
	}
	return pe.Code == "08P01" && strings.Contains(strings.ToLower(pe.Message), "startup parameter")
}

// ConnectConfig connects with cfg. Through a connection string, when the
// server refuses the startup parameters Rowsafe adds (only
// application_name; poolers accept it, but not all of them), it connects
// again without them.
func ConnectConfig(ctx context.Context, cfg *pgx.ConnConfig, added ...string) (*pgx.Conn, error) {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil || len(added) == 0 || !StartupRefused(err) {
		return conn, err
	}
	cfg = cfg.Copy()
	for _, k := range added {
		delete(cfg.RuntimeParams, k)
	}
	return pgx.ConnectConfig(ctx, cfg)
}

// ForConnString prepares a connection string's config: the simple
// protocol, because a pooler in transaction mode can't keep prepared
// statements (pgx's statement cache) between transactions.
func ForConnString(cfg *pgx.ConnConfig) {
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.StatementCacheCapacity = 0
	cfg.DescriptionCacheCapacity = 0
}

// PoolerReason is why a fix that needs one session of its own (VACUUM
// outside a transaction, CONCURRENTLY, its lock and statement timeouts)
// can't run through pooler.
func PoolerReason(pooler string) string {
	return fmt.Sprintf("it needs its own session in PostgreSQL, and this connection goes through %s: use the direct connection string, not the pooler's", pooler)
}

// Pooler says which connection pooler a connection string goes through
// ("" when it reaches PostgreSQL directly, or over the socket): by the
// hosts of Supabase's and Neon's poolers, by a refused startup parameter
// (PgBouncer and Neon's pooler refuse them), or because two queries of one
// connection ran in different server sessions, or two connections in the
// same one (transaction pooling). A session pooler that accepts startup
// parameters looks like PostgreSQL itself, which is right: it gives each
// connection a session of its own.
func (t Target) Pooler(ctx context.Context) (string, error) {
	if t.Conn == nil {
		return "", nil
	}
	h := strings.ToLower(t.Conn.Host)
	switch {
	case strings.HasSuffix(h, ".pooler.supabase.com"):
		return "Supabase's connection pooler (Supavisor)", nil
	case strings.Contains(h, "-pooler.") && strings.HasSuffix(h, ".neon.tech"):
		return "Neon's connection pooler", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	probe := t
	probe.AppName = "rowsafe-pooler-check"
	cfg, err := probe.config(probe.MaintenanceDB())
	if err != nil {
		return "", err
	}
	cfg.RuntimeParams["lock_timeout"] = "5s"
	a, err := pgx.ConnectConfig(ctx, cfg)
	if StartupRefused(err) {
		return "a connection pooler (it refused PostgreSQL session settings)", nil
	}
	if err != nil {
		return "", err
	}
	defer a.Close(context.WithoutCancel(ctx))
	b, err := probe.Connect(ctx, probe.MaintenanceDB())
	if err != nil {
		return "", err
	}
	defer b.Close(context.WithoutCancel(ctx))
	pid := func(c *pgx.Conn) (int, error) {
		var p int
		err := c.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&p)
		return p, err
	}
	var pids [3]int
	for i, c := range []*pgx.Conn{a, b, a} {
		if pids[i], err = pid(c); err != nil {
			return "", err
		}
	}
	if pids[0] != pids[2] || pids[0] == pids[1] {
		return "a connection pooler in transaction mode", nil
	}
	return "", nil
}
