package local

import (
	"context"
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
