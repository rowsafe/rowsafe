package collect

import (
	"context"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// The extensions Rowsafe installs (protocol.PGPackagedExtensions) that are
// turned on in a database here, with each database's version
// (SettingsSnapshot.Extensions). Only servers that have one of them
// installed are scanned (most have none): every database that accepts
// connections, at most extensionScanDatabases of them within
// extensionScanBudget.

const (
	extensionScanDatabases = 100
	extensionScanBudget    = 5 * time.Second
)

// missingLibraryRE matches the error of a database whose TimescaleDB
// version's library is gone: could not access file
// "$libdir/timescaledb-2.30.1".
var missingLibraryRE = regexp.MustCompile(`\$libdir/(timescaledb)-([0-9][0-9A-Za-z.]*)"`)

// ExtensionUse reads which of the extensions Rowsafe installs are turned
// on where, on the server conn is connected to (any database); t connects
// to the others. Nil when none is.
func ExtensionUse(ctx context.Context, t Target, conn *pgx.Conn) ([]protocol.ExtensionUse, error) {
	names := make([]string, len(protocol.PGPackagedExtensions))
	for i, e := range protocol.PGPackagedExtensions {
		names[i] = e.Name
	}
	var preload, pending string
	avail := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT name::text, coalesce(default_version, '') FROM pg_available_extensions WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return nil, err
		}
		avail[n] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(avail) == 0 {
		return nil, nil
	}
	if err := conn.QueryRow(ctx, `
		SELECT current_setting('shared_preload_libraries'),
		       coalesce((SELECT setting FROM pg_file_settings WHERE name = 'shared_preload_libraries' AND error IS NULL
		                 ORDER BY seqno DESC LIMIT 1), current_setting('shared_preload_libraries'))`).Scan(&preload, &pending); err != nil {
		return nil, err
	}
	var dbs []string
	rows, err = conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname LIMIT $1`, extensionScanDatabases+1)
	if err != nil {
		return nil, err
	}
	if dbs, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, err
	}
	truncated := len(dbs) > extensionScanDatabases
	if truncated {
		dbs = dbs[:extensionScanDatabases]
	}
	var here string
	if err := conn.QueryRow(ctx, `SELECT current_database()::text`).Scan(&here); err != nil {
		return nil, err
	}
	uses := map[string]*protocol.ExtensionUse{}
	deadline := time.Now().Add(extensionScanBudget)
	for _, db := range dbs {
		if time.Now().After(deadline) {
			truncated = true
			break
		}
		c := conn
		if db != here {
			if c, err = t.connect(ctx, db); err != nil {
				truncated = true
				continue
			}
		}
		rows, err := c.Query(ctx, `SELECT extname::text, extversion FROM pg_extension WHERE extname = ANY($1)`, names)
		if err == nil {
			for rows.Next() {
				var n, v string
				if rows.Scan(&n, &v) != nil {
					continue
				}
				u := uses[n]
				if u == nil {
					u = &protocol.ExtensionUse{Name: n, DefaultVersion: avail[n]}
					if e, ok := protocol.PGPackagedExtensionFor(n); ok && e.Preload {
						u.Preload = true
						u.Loaded = slices.Contains(tune.Libraries(preload), n)
						u.PendingLoad = slices.Contains(tune.Libraries(pending), n)
					}
					uses[n] = u
				}
				u.Databases = append(u.Databases, protocol.ExtensionInDatabase{Database: db, Version: v})
			}
			rows.Close()
			err = rows.Err()
		}
		if err != nil {
			// TimescaleDB whose package was updated while this database
			// still runs the old version: every query fails, naming it.
			if m := missingLibraryRE.FindStringSubmatch(err.Error()); m != nil {
				u := uses[m[1]]
				if u == nil {
					u = &protocol.ExtensionUse{Name: m[1], DefaultVersion: avail[m[1]], Preload: true,
						Loaded: slices.Contains(tune.Libraries(preload), m[1]), PendingLoad: slices.Contains(tune.Libraries(pending), m[1])}
					uses[m[1]] = u
				}
				u.Databases = append(u.Databases, protocol.ExtensionInDatabase{Database: db, Version: m[2], Missing: true})
			} else {
				truncated = true
			}
		}
		if c != conn {
			c.Close(context.WithoutCancel(ctx))
		}
	}
	var out []protocol.ExtensionUse
	for _, n := range names {
		if u := uses[n]; u != nil {
			u.Truncated = truncated
			out = append(out, *u)
		}
	}
	return out, nil
}
