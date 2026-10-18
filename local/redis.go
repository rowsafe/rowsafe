package local

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Redis and Valkey (redis://, rediss://, valkey://, valkeys://): the Redis
// engine's own reading, fixes and settings on the connection
// (internal/engine/redis, direct.go), and pulse's Redis rules. What needs
// the server itself is left out: the disk when it runs on another machine,
// backups.

// redisConn is a Redis or Valkey server reached with a connection string.
type redisConn struct {
	addr, host     string
	user, password string
	tls, insecure  bool
	db             int
}

// isRedisURL reports whether s is a redis:// or rediss:// (valkey://,
// valkeys://) URL.
func isRedisURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"redis://", "rediss://", "valkey://", "valkeys://", "redis+unix://", "unix://"} {
		if strings.HasPrefix(s, p) && (p != "unix://" || strings.Contains(s, ".sock")) {
			return true
		}
	}
	return false
}

// openRedis parses redis://user:password@host:6379/0 (rediss:// for TLS,
// ?insecure=true or ssl_cert_reqs=none to skip checking its certificate;
// redis+unix:///path/redis.sock for a socket). Like redis-cli, it reads
// REDISCLI_AUTH when the string has no password.
func openRedis(connString string) (*DB, error) {
	u, err := url.Parse(connString)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("reading the connection string: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	rc := &redisConn{tls: scheme == "rediss" || scheme == "valkeys"}
	d := &DB{rd: rc}
	if u.User != nil {
		rc.user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			rc.password, d.PasswordInURL = p, true
		}
	}
	if rc.password == "" {
		rc.password = os.Getenv("REDISCLI_AUTH")
	}
	if rc.user == "default" && rc.password != "" {
		rc.user = "" // the legacy AUTH, which Redis 5 and older take too
	}
	switch {
	case scheme == "redis+unix" || scheme == "unix":
		rc.addr, rc.host = u.Path, "localhost"
	default:
		rc.host = u.Hostname()
		if rc.host == "" {
			rc.host = "localhost"
		}
		port := u.Port()
		if port == "" {
			port = "6379"
		}
		if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("reading the connection string: bad port %q", port)
		}
		rc.addr = net.JoinHostPort(rc.host, port)
		if p := strings.Trim(u.Path, "/"); p != "" {
			if rc.db, err = strconv.Atoi(p); err != nil || rc.db < 0 {
				return nil, fmt.Errorf("reading the connection string: %q isn't a database number (redis://host:6379/0)", p)
			}
		}
	}
	q := u.Query()
	for k, vs := range q {
		v := strings.ToLower(vs[len(vs)-1])
		switch strings.ToLower(k) {
		case "insecure", "skip_verify", "tls_insecure":
			rc.insecure = v == "true" || v == "1" || v == "yes"
		case "ssl_cert_reqs":
			rc.insecure = v == "none"
		case "db":
			if rc.db, err = strconv.Atoi(v); err != nil {
				return nil, fmt.Errorf("reading the connection string: db=%s isn't a number", v)
			}
		case "protocol", "client_name", "timeout", "dial_timeout":
		default:
			return nil, fmt.Errorf("reading the connection string: unknown option %q (Rowsafe reads insecure, ssl_cert_reqs and db)", k)
		}
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	d.Ref = u.String()
	return d, nil
}

func (r *redisConn) name() string {
	if r.db != 0 {
		return "db" + strconv.Itoa(r.db)
	}
	return "redis"
}

// hostPort is where it runs, for people.
func (r *redisConn) hostPort() string {
	if strings.HasPrefix(r.addr, "/") {
		return "localhost"
	}
	if h, p, err := net.SplitHostPort(r.addr); err == nil && p == "6379" {
		return h
	}
	return r.addr
}

func (r *redisConn) local() bool {
	h := r.host
	return strings.HasPrefix(r.addr, "/") || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (d *DB) redisConnectError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("can't read %s on %s: %w", d.EngineName(), d.Host(), err)
}

// errRedisNotHere: a command Redis has no equivalent of here.
func errRedisNotHere(cmd, instead string) error {
	return fmt.Errorf("rowsafe %s reads tables and queries, which Redis and Valkey don't have: %s", cmd, instead)
}
