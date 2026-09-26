package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// conninfo is a PostgreSQL connection string as libpq keywords (host, port,
// user, password, dbname, sslmode...). People paste either a URL
// (postgres://user:pass@host:5432/db?sslmode=require) or key=value pairs;
// both become this, so the agent can hand libpq tools a connection string
// without the password (it goes in a passfile instead) and never puts the
// password on a command line.
type conninfo map[string]string

// libpqKeywords are the keywords accepted from a pasted connection string.
// Anything else is refused rather than passed on (a typo, or an option that
// could make libpq read files or run commands).
var libpqKeywords = map[string]bool{
	"host": true, "hostaddr": true, "port": true, "dbname": true, "user": true, "password": true,
	"sslmode": true, "sslrootcert": true, "sslcert": false, "sslkey": false, "sslcrl": false,
	"sslsni": true, "sslnegotiation": true, "ssl_min_protocol_version": true, "ssl_max_protocol_version": true,
	"channel_binding": true, "connect_timeout": true, "application_name": true, "options": true,
	"target_session_attrs": true, "keepalives": true, "keepalives_idle": true,
	"keepalives_interval": true, "keepalives_count": true, "gssencmode": true, "krbsrvname": false,
	"require_auth": true, "load_balance_hosts": true, "tcp_user_timeout": true,
}

func parseConninfo(s string) (conninfo, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("the connection string is empty")
	}
	var ci conninfo
	var err error
	if strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://") {
		ci, err = parseConnURL(s)
	} else {
		ci, err = parseConnKV(s)
	}
	if err != nil {
		return nil, err
	}
	for k := range ci {
		if !libpqKeywords[k] {
			return nil, fmt.Errorf("the connection string has an option Rowsafe doesn't accept: %q", k)
		}
	}
	// Files on this server are never named by a pasted string: only the
	// system's trusted roots.
	if v, ok := ci["sslrootcert"]; ok && v != "system" {
		return nil, errors.New("sslrootcert may only be \"system\" (the server's trusted certificates)")
	}
	if ci["host"] == "" && ci["hostaddr"] == "" {
		return nil, errors.New("the connection string has no host")
	}
	if strings.HasPrefix(ci["host"], "/") {
		return nil, errors.New("the connection string points to a local socket; use the database's network address")
	}
	if p := ci["port"]; p != "" {
		for _, one := range strings.Split(p, ",") {
			if n, err := strconv.Atoi(one); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("the port %q isn't a number between 1 and 65535", p)
			}
		}
	}
	if ci["user"] == "" {
		return nil, errors.New("the connection string has no user name")
	}
	if ci["dbname"] == "" {
		ci["dbname"] = ci["user"] // libpq's default
	}
	return ci, nil
}

func parseConnURL(s string) (conninfo, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("the connection string isn't a valid URL (check for special characters in the password: they must be percent-encoded)")
	}
	ci := conninfo{}
	if u.User != nil {
		ci["user"] = u.User.Username()
		if p, ok := u.User.Password(); ok {
			ci["password"] = p
		}
	}
	// Multiple hosts (h1:5432,h2:5432) are kept as libpq lists.
	var hosts, ports []string
	for _, hp := range strings.Split(u.Host, ",") {
		if hp == "" {
			continue
		}
		h, p := hp, ""
		if strings.HasPrefix(hp, "[") { // [ipv6]:port
			if i := strings.LastIndex(hp, "]"); i > 0 {
				h = hp[1:i]
				p = strings.TrimPrefix(hp[i+1:], ":")
			}
		} else if i := strings.LastIndex(hp, ":"); i >= 0 {
			h, p = hp[:i], hp[i+1:]
		}
		hosts = append(hosts, h)
		ports = append(ports, p)
	}
	if len(hosts) > 0 {
		ci["host"] = strings.Join(hosts, ",")
		if strings.Join(ports, "") != "" {
			ci["port"] = strings.Join(ports, ",")
		}
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		ci["dbname"] = db
	}
	for k, v := range u.Query() {
		if len(v) > 0 {
			ci[k] = v[len(v)-1]
		}
	}
	return ci, nil
}

// parseConnKV parses key=value pairs; values may be single-quoted with \'
// and \\ escapes, as libpq does.
func parseConnKV(s string) (conninfo, error) {
	ci := conninfo{}
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= len(s) {
			return ci, nil
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			return nil, errors.New("the connection string isn't a URL (postgres://...) or key=value pairs")
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 1
		for i < len(s) && s[i] == ' ' {
			i++
		}
		var val strings.Builder
		if i < len(s) && s[i] == '\'' {
			i++
			closed := false
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					val.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '\'' {
					closed = true
					i++
					break
				}
				val.WriteByte(c)
				i++
			}
			if !closed {
				return nil, errors.New("the connection string has an unterminated quote")
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
		}
		if key == "" || strings.ContainsAny(key, " '\\") {
			return nil, errors.New("the connection string isn't a URL (postgres://...) or key=value pairs")
		}
		ci[key] = val.String()
	}
}

// String renders the connection string as key=value pairs, keys sorted.
// Leave the password out with without("password").
func (ci conninfo) String() string {
	keys := make([]string, 0, len(ci))
	for k := range ci {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteString("='")
		b.WriteString(strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(ci[k]))
		b.WriteByte('\'')
	}
	return b.String()
}

func (ci conninfo) without(keys ...string) conninfo {
	out := conninfo{}
	for k, v := range ci {
		out[k] = v
	}
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func (ci conninfo) with(k, v string) conninfo {
	out := ci.without()
	out[k] = v
	return out
}

// firstHost is the first host of a host list.
func (ci conninfo) firstHost() string {
	h := ci["host"]
	if h == "" {
		h = ci["hostaddr"]
	}
	h, _, _ = strings.Cut(h, ",")
	return h
}

func (ci conninfo) firstPort() int {
	p, _, _ := strings.Cut(ci["port"], ",")
	n, err := strconv.Atoi(p)
	if err != nil {
		return 5432
	}
	return n
}

// libpqOnly are keywords pgx doesn't understand; they are left out of the
// agent's own connections (libpq tools still get them).
var libpqOnly = []string{"channel_binding", "gssencmode", "require_auth", "load_balance_hosts",
	"sslnegotiation", "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count",
	"ssl_max_protocol_version", "tcp_user_timeout"}

// connect opens the agent's own connection to the source. Every session
// turns default_transaction_read_only off for itself, so Rowsafe can still
// clean up after it made the source read-only.
func (ci conninfo) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(ci.without(libpqOnly...).String())
	if err != nil {
		return nil, fmt.Errorf("reading the connection string: %w", err)
	}
	cfg.RuntimeParams["application_name"] = "rowsafe-move-in"
	if cfg.ConnectTimeout == 0 || cfg.ConnectTimeout > 20*time.Second {
		cfg.ConnectTimeout = 20 * time.Second
	}
	// Rowsafe never uses prepared statements against a provider's poolers.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, plainConnectError(ci, err)
	}
	if _, err := conn.Exec(ctx, "SET default_transaction_read_only = off"); err != nil {
		conn.Close(ctx)
		return nil, err
	}
	return conn, nil
}

// plainConnectError explains a failed connection to the source.
func plainConnectError(ci conninfo, err error) error {
	msg := err.Error()
	host := ci.firstHost()
	switch {
	case strings.Contains(msg, "password authentication failed"), strings.Contains(msg, "SASL authentication failed"):
		return fmt.Errorf("the user name or password was not accepted by %s. Copy the connection string again from your provider", host)
	case strings.Contains(msg, "no such host"):
		return fmt.Errorf("the host %s wasn't found. Check the connection string", host)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "timeout"), strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "network is unreachable"):
		return fmt.Errorf("this server can't reach %s on port %d. Allow this server's IP address at your provider (trusted sources, security group or firewall), then try again (%v)", host, ci.firstPort(), err)
	case strings.Contains(msg, "no pg_hba.conf entry"):
		return fmt.Errorf("%s doesn't accept connections from this server: allow this server's IP address at your provider, then try again", host)
	case strings.Contains(msg, "does not exist") && strings.Contains(msg, "database"):
		return fmt.Errorf("the database %q doesn't exist on %s", ci["dbname"], host)
	case strings.Contains(msg, "SSL"), strings.Contains(msg, "tls"):
		return fmt.Errorf("the secure connection to %s failed: %v. Add sslmode=require to the connection string", host, err)
	}
	return fmt.Errorf("connecting to %s: %w", host, err)
}

// writePassfile writes a libpq password file with the source's password,
// readable only by the agent's user (and PostgreSQL, which runs as the same
// user and reads it for the live sync).
func writePassfile(path string, ci conninfo) error {
	esc := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
	// Wildcards: libpq matches host and port as they appear in the
	// connection string, which may be a list.
	line := fmt.Sprintf("*:*:*:%s:%s\n", esc.Replace(ci["user"]), esc.Replace(ci["password"]))
	return writeFileAtomic(path, []byte(line), 0o600)
}

// libpqConninfo is what libpq tools and the subscription get: everything but
// the password, which they read from passfile.
func (ci conninfo) libpqConninfo(passfile string) string {
	out := ci.without("password")
	if ci["password"] != "" {
		out["passfile"] = passfile
	}
	return out.String()
}

// removeAll deletes a migration directory, ignoring a missing one.
func removeAll(dir string) error {
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
