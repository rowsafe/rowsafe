package collect

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestTargetConnString(t *testing.T) {
	base, err := pgx.ParseConfig("postgres://app:s3cret@db.example.com:6543/shop?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Conn: base}
	if tg.MaintenanceDB() != "shop" || tg.OnlyDB() != "shop" || tg.Local() {
		t.Errorf("maintenance %q only %q local %v", tg.MaintenanceDB(), tg.OnlyDB(), tg.Local())
	}
	if s := tg.String(); strings.Contains(s, "s3cret") || s != "db.example.com port 6543 as app" {
		t.Errorf("String() = %q", s)
	}
	cfg, err := tg.config("other")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["statement_timeout"] = "2000"
	if cfg.Database != "other" || cfg.Password != "s3cret" || cfg.TLSConfig == nil {
		t.Errorf("config: db %q tls %v", cfg.Database, cfg.TLSConfig != nil)
	}
	// Each connection's settings stay its own.
	if base.Database != "shop" || base.RuntimeParams["statement_timeout"] != "" {
		t.Errorf("base changed: %q %v", base.Database, base.RuntimeParams)
	}

	sock := Target{SocketDir: "/var/run/postgresql", Port: 5433, User: "postgres"}
	if sock.MaintenanceDB() != "postgres" || sock.OnlyDB() != "" || !sock.Local() {
		t.Errorf("socket target: %q %q %v", sock.MaintenanceDB(), sock.OnlyDB(), sock.Local())
	}
	for host, local := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "/tmp": true, "10.0.0.5": false} {
		c, _ := pgx.ParseConfig("postgres://u@x/db")
		c.Host = host
		if got := (Target{Conn: c}).Local(); got != local {
			t.Errorf("Local() for %s = %v", host, got)
		}
	}
}
