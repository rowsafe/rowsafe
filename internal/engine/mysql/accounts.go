package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"

	"github.com/rowsafe/rowsafe/protocol"
)

// How accounts log in, for the security check and Databases & users.
// mysql.user says it for MySQL. On MariaDB 10.4+ it is a view of
// mysql.global_priv that leaves out what matters: whether an account is
// locked (mariadb.sys, which has no password), and the other ways it may
// log in (IDENTIFIED VIA mysql_native_password USING 'invalid' OR
// unix_socket: root and mysql on Debian and Ubuntu, which only the
// system's root and mysql users can use). And there mysql_native_password
// is how MariaDB stores every password unless a plugin is installed
// (Rowsafe's own too), so it isn't an old-style one there; the pre-4.1
// mysql_old_password is.

// accountAuth is how one account logs in.
type accountAuth struct {
	login bool   // some way works (not locked, a usable password or socket)
	kind  string // protocol.Password*: the weakest way that works
}

// nativeHashRE is a mysql_native_password hash; anything else ("invalid")
// matches no password.
var nativeHashRE = regexp.MustCompile(`^\*[0-9A-Fa-f]{40}$`)

// mariadbAccounts reads MariaDB's accounts from mysql.global_priv; nil on
// MySQL, before 10.4, or when it can't be read.
func (s *server) mariadbAccounts(ctx context.Context, db *sql.DB) map[dbaUser]accountAuth {
	if !s.flavor.mariadb() {
		return nil
	}
	rows, err := db.QueryContext(ctx, "SELECT User, Host, Priv FROM mysql.global_priv")
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[dbaUser]accountAuth{}
	for rows.Next() {
		var u dbaUser
		var priv string
		if rows.Scan(&u.user, &u.host, &priv) != nil {
			continue
		}
		out[u] = mariadbAuth(priv)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// mariadbAuth reads one account's Priv (JSON).
func mariadbAuth(priv string) accountAuth {
	type method struct {
		Plugin string `json:"plugin"`
		Auth   string `json:"authentication_string"`
	}
	var p struct {
		method
		Locked bool              `json:"account_locked"`
		Or     []json.RawMessage `json:"auth_or"`
	}
	if json.Unmarshal([]byte(priv), &p) != nil {
		return accountAuth{login: true, kind: protocol.PasswordSet} // unknown: no finding
	}
	methods := []method{p.method}
	if len(p.Or) > 0 {
		methods = methods[:0]
		for _, raw := range p.Or {
			var m method
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			if m.Plugin == "" { // {}: the account's own plugin and string
				m = p.method
			}
			methods = append(methods, m)
		}
	}
	a := accountAuth{}
	rank := map[string]int{protocol.PasswordSocket: 1, protocol.PasswordSet: 2, protocol.PasswordWeak: 3, protocol.PasswordNone: 4}
	for _, m := range methods {
		kind, ok := mariadbMethod(m.Plugin, m.Auth)
		if !ok {
			continue
		}
		if !a.login || rank[kind] > rank[a.kind] {
			a.login, a.kind = true, kind
		}
	}
	if !a.login {
		a.kind = protocol.PasswordSet // no password matches: nobody logs in with one
	}
	if p.Locked {
		a.login = false
	}
	return a
}

// mariadbMethod is the kind of one way to log in; false when no password
// can match it.
func mariadbMethod(plugin, auth string) (string, bool) {
	switch plugin {
	case "", "mysql_native_password":
		if auth == "" {
			return protocol.PasswordNone, true
		}
		return protocol.PasswordSet, nativeHashRE.MatchString(auth)
	case "mysql_old_password":
		if auth == "" {
			return protocol.PasswordNone, true
		}
		return protocol.PasswordWeak, true
	}
	return passwordKind(plugin, auth == ""), true
}

// loginKind is how account u logs in: from MariaDB's accounts when read,
// else from mysql.user's plugin, an empty authentication_string and
// whether it is locked.
func (s *server) loginKind(auth map[dbaUser]accountAuth, u dbaUser, plugin string, empty, locked bool) (kind string, login bool) {
	if a, ok := auth[u]; ok {
		return a.kind, a.login
	}
	kind = passwordKind(plugin, empty)
	if s.flavor.mariadb() && plugin == "mysql_native_password" && kind == protocol.PasswordWeak {
		kind = protocol.PasswordSet
	}
	return kind, !locked
}
