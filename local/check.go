package local

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Server is what a check found at a connection string.
type Server struct {
	Database string `json:"database"`
	User     string `json:"user"`
	Version  string `json:"version"`
	// Redis and Valkey: the server's configuration and ACL files, for
	// keeping Rowsafe's user on its server ("" when none or unknown).
	ConfigFile string `json:"-"`
	ACLFile    string `json:"-"`
}

// Check connects once and reads who and what the connection reaches,
// changing nothing: rowsafe add uses it before it saves a connection
// string.
func (d *DB) Check(ctx context.Context) (Server, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if d.my != nil {
		return d.mysqlCheck(ctx)
	}
	if d.mg != nil {
		return d.mongoCheck(ctx)
	}
	if d.rd != nil {
		return d.redisCheck(ctx)
	}
	conn, err := pgx.ConnectConfig(ctx, d.conn.Copy())
	if err != nil {
		return Server{}, d.connectError(err)
	}
	defer conn.Close(context.Background())
	var s Server
	err = conn.QueryRow(ctx, `SELECT current_database(), current_user, current_setting('server_version')`).
		Scan(&s.Database, &s.User, &s.Version)
	return s, d.connectError(err)
}

// SocketPort reports whether the PostgreSQL this connection string reaches
// also listens on a Unix socket in dir, and on which port: in Docker, the
// agent's container shares the postgres container's socket directory, and
// postgres://app@postgres:5432/shop is that same server. It connects twice,
// over the string and over the socket with the same user and password, and
// compares when each server started (to the microsecond); ok is false for
// another server. Read-only.
func (d *DB) SocketPort(ctx context.Context, dir string) (port int, ok bool, err error) {
	if d.my != nil {
		return 0, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	started := func(cfg *pgx.ConnConfig) (time.Time, int, error) {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return time.Time{}, 0, err
		}
		defer conn.Close(context.Background())
		var t time.Time
		var p int
		err = conn.QueryRow(ctx, `SELECT pg_postmaster_start_time(), current_setting('port')::int`).Scan(&t, &p)
		return t, p, err
	}
	at, port, err := started(d.conn.Copy())
	if err != nil {
		return 0, false, d.connectError(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".s.PGSQL."+strconv.Itoa(port))); err != nil {
		return 0, false, nil
	}
	sc := d.conn.Copy()
	sc.Host, sc.Port, sc.TLSConfig, sc.Fallbacks = dir, uint16(port), nil, nil
	sockAt, _, err := started(sc)
	if err != nil {
		return 0, false, nil // another server, or one that only trusts TCP
	}
	return port, sockAt.Equal(at), nil
}
