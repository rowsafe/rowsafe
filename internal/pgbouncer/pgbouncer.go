// Package pgbouncer talks to PgBouncer's admin console (the virtual
// "pgbouncer" database): SHOW commands for monitoring, and PAUSE, RELOAD
// and RESUME to switch servers without failing clients. The console only
// speaks the simple query protocol and returns every value as text.
package pgbouncer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Target is how to reach an admin console.
type Target struct {
	// Host is a Unix socket directory (/var/run/postgresql) or a host name.
	Host     string
	Port     int
	User     string
	Password string
	// URL, when set, replaces the fields above
	// (postgres://stats:secret@pgbouncer:6432/pgbouncer).
	URL string
}

// Connect opens an admin console connection.
func (t Target) Connect(ctx context.Context) (*pgx.Conn, error) {
	var cfg *pgx.ConnConfig
	var err error
	if t.URL != "" {
		cfg, err = pgx.ParseConfig(t.URL)
		if err != nil {
			return nil, fmt.Errorf("the PgBouncer address is not a valid postgres:// URL")
		}
	} else {
		cfg, err = pgx.ParseConfig("")
		if err != nil {
			return nil, err
		}
		cfg.Host, cfg.Port, cfg.User, cfg.Password = t.Host, uint16(t.Port), t.User, t.Password
		// The admin console needs no TLS on a Unix socket or loopback.
		cfg.TLSConfig, cfg.Fallbacks = nil, nil
	}
	cfg.Database = "pgbouncer"
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.StatementCacheCapacity, cfg.DescriptionCacheCapacity = 0, 0
	cfg.ConnectTimeout = 5 * time.Second
	// The console refuses startup parameters it doesn't know.
	cfg.RuntimeParams = map[string]string{}
	return pgx.ConnectConfig(ctx, cfg)
}

// Redact removes the password from a postgres:// URL for messages.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

// Row is one line of a SHOW command, by column name.
type Row map[string]string

// Int returns a column as an integer (0 when absent or not a number).
func (r Row) Int(col string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(r[col]), 10, 64)
	return n
}

// Show runs "SHOW WHAT" (POOLS, STATS, DATABASES, VERSION, ...).
func Show(ctx context.Context, conn *pgx.Conn, what string) ([]Row, error) {
	switch what {
	case "POOLS", "STATS", "DATABASES", "VERSION", "LISTS", "CONFIG", "SERVERS", "CLIENTS":
	default:
		return nil, fmt.Errorf("unsupported SHOW %s", what)
	}
	rows, err := conn.Query(ctx, "SHOW "+what)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	var out []Row
	for rows.Next() {
		raw := rows.RawValues()
		row := Row{}
		for i, f := range fields {
			if i < len(raw) && raw[i] != nil {
				row[f.Name] = string(raw[i])
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Version returns PgBouncer's version ("1.24.1").
func Version(ctx context.Context, conn *pgx.Conn) (string, error) {
	rows, err := Show(ctx, conn, "VERSION")
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		for _, v := range r {
			return ParseVersion(v), nil
		}
	}
	return "", errors.New("SHOW VERSION returned nothing")
}

// ParseVersion takes "PgBouncer 1.24.1" (or "1.24.1") to "1.24.1".
func ParseVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "PgBouncer")
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// AtLeast reports whether version (1.24.1) is at least major.minor.
func AtLeast(version string, major, minor int) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || ma == major && mi >= minor
}

// Command runs one admin command: PAUSE, RESUME, RELOAD, or one of them
// for a database (PAUSE db).
func Command(ctx context.Context, conn *pgx.Conn, cmd string) error {
	verb, _, _ := strings.Cut(cmd, " ")
	switch verb {
	case "PAUSE", "RESUME", "RELOAD", "RECONNECT", "KILL":
	default:
		return fmt.Errorf("unsupported admin command %q", cmd)
	}
	_, err := conn.Exec(ctx, cmd)
	return err
}
