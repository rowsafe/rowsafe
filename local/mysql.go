package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// MySQL and MariaDB (mysql://, mariadb://): the MySQL engine's own reading
// and fixes on the connection (internal/engine/mysql, direct.go), and
// pulse's MySQL rules. What needs the server itself is left out: the disk
// and table rebuilds when it runs on another machine, MariaDB's settings
// (kept in its configuration file), replication checks.

// isMySQLURL reports whether s is a mysql:// or mariadb:// URL.
func isMySQLURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "mysql://") || strings.HasPrefix(s, "mariadb://")
}

// openMySQL parses mysql://user:password@host:3306/db?tls=...: like the
// mysql client, it reads MYSQL_PWD when the string has no password, and
// encrypts the connection when the server offers it (ssl-mode=PREFERRED).
// Options: ssl-mode (DISABLED, PREFERRED, REQUIRED, VERIFY_CA,
// VERIFY_IDENTITY) or tls (false, preferred, skip-verify, true), and
// socket=/path for a Unix socket, charset.
func openMySQL(connString string) (*DB, error) {
	u, err := url.Parse(connString)
	if err != nil {
		// Never the string itself in the error: it may hold a password.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("reading the connection string: %w", err)
	}
	cfg := mysqldriver.NewConfig()
	cfg.Net, cfg.Addr = "tcp", "127.0.0.1:3306"
	host, port := u.Hostname(), u.Port()
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "3306"
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return nil, fmt.Errorf("reading the connection string: bad port %q", port)
	}
	cfg.Addr = net.JoinHostPort(host, port)
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	d := &DB{my: cfg, myHost: host, myPort: port}
	if u.User != nil {
		cfg.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			cfg.Passwd, d.PasswordInURL = p, true
		}
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Passwd == "" {
		cfg.Passwd = os.Getenv("MYSQL_PWD")
	}
	cfg.TLSConfig = "preferred"
	q := u.Query()
	for k, vs := range q {
		v := vs[len(vs)-1]
		switch strings.ToLower(strings.ReplaceAll(k, "_", "-")) {
		case "ssl-mode", "sslmode":
			mode, ok := map[string]string{"DISABLED": "false", "PREFERRED": "preferred", "REQUIRED": "skip-verify",
				"VERIFY-CA": "true", "VERIFY-IDENTITY": "true"}[strings.ToUpper(strings.ReplaceAll(v, "_", "-"))]
			if !ok {
				return nil, fmt.Errorf("reading the connection string: ssl-mode=%s: use DISABLED, PREFERRED, REQUIRED, VERIFY_CA or VERIFY_IDENTITY", v)
			}
			cfg.TLSConfig = mode
		case "tls":
			switch strings.ToLower(v) {
			case "true", "false", "preferred", "skip-verify":
				cfg.TLSConfig = strings.ToLower(v)
			default:
				return nil, fmt.Errorf("reading the connection string: tls=%s: use true, false, preferred or skip-verify", v)
			}
		case "socket":
			cfg.Net, cfg.Addr, d.myHost = "unix", v, "localhost"
		case "charset":
			cfg.Params = map[string]string{"charset": v}
		default:
			return nil, fmt.Errorf("reading the connection string: unknown option %q (Rowsafe reads ssl-mode, tls and socket)", k)
		}
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	d.Ref = u.String()
	return d, nil
}

// mysqlLocal: the server runs on this machine.
func (d *DB) mysqlLocal() bool {
	h := d.myHost
	return d.my.Net == "unix" || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (d *DB) mysqlConnectError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("can't read %s on %s as %s: %w", d.Name(), d.Host(), d.my.User, err)
}
