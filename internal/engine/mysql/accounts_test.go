package mysql

import (
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// MariaDB's accounts as mysql.global_priv holds them on a new Debian
// server, and others.
func TestMariaDBAuth(t *testing.T) {
	for priv, want := range map[string]accountAuth{
		// mariadb.sys: locked, no password.
		`{"access":0,"plugin":"mysql_native_password","authentication_string":"","account_locked":true}`: {false, protocol.PasswordNone},
		// root and mysql: no password matches 'invalid'; the system's user through the socket.
		`{"access":18446744073709551615,"plugin":"mysql_native_password","authentication_string":"invalid","auth_or":[{},{"plugin":"unix_socket"}]}`: {true, protocol.PasswordSocket},
		// Rowsafe's account, an app's: MariaDB's own way of storing passwords.
		`{"plugin":"mysql_native_password","authentication_string":"*B69027D44F6E5EDC07F1AEAD1477967B16F28227"}`: {true, protocol.PasswordSet},
		`{"plugin":"mysql_native_password","authentication_string":""}`:                                          {true, protocol.PasswordNone},
		`{"plugin":"mysql_old_password","authentication_string":"7f2a3c1d5e6b4a90"}`:                             {true, protocol.PasswordWeak},
		`{"plugin":"ed25519","authentication_string":"ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY"}`:             {true, protocol.PasswordSet},
		// A password or the socket: the password counts.
		`{"plugin":"unix_socket","authentication_string":"","auth_or":[{"plugin":"mysql_native_password","authentication_string":""},{}]}`: {true, protocol.PasswordNone},
		// Only 'invalid': nobody logs in.
		`{"plugin":"mysql_native_password","authentication_string":"invalid"}`: {false, protocol.PasswordSet},
	} {
		if got := mariadbAuth(priv); got != want {
			t.Errorf("%s: %+v, want %+v", priv, got, want)
		}
	}
	s := &server{flavor: flavorMariaDB}
	if kind, login := s.loginKind(nil, dbaUser{"app", "%"}, "mysql_native_password", false, false); kind != protocol.PasswordSet || !login {
		t.Errorf("MariaDB without global_priv: %s %v", kind, login)
	}
	s.flavor = flavorMySQL
	if kind, _ := s.loginKind(nil, dbaUser{"app", "%"}, "mysql_native_password", false, false); kind != protocol.PasswordWeak {
		t.Errorf("MySQL's mysql_native_password: %s", kind)
	}
}
