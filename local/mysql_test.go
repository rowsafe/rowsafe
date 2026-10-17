package local

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestOpenMySQL(t *testing.T) {
	for _, s := range []string{"mysql://u@h/db", "MARIADB://h", " mysql://root:pw@127.0.0.1:3307/shop "} {
		if !IsConnString(s) {
			t.Errorf("%q is a connection string", s)
		}
	}
	d, err := Open("mysql://app:s3cret@db.example.com:3307/shop?ssl-mode=VERIFY_IDENTITY")
	if err != nil {
		t.Fatal(err)
	}
	if !d.PasswordInURL || strings.Contains(d.Ref, "s3cret") || d.Ref != "mysql://app@db.example.com:3307/shop?ssl-mode=VERIFY_IDENTITY" {
		t.Errorf("ref %q (password in URL %v)", d.Ref, d.PasswordInURL)
	}
	if d.Name() != "shop" || d.Host() != "db.example.com:3307" || d.Local() || d.Engine() != protocol.EngineMySQL || d.my.TLSConfig != "true" {
		t.Errorf("name %q host %q local %v engine %s tls %q", d.Name(), d.Host(), d.Local(), d.Engine(), d.my.TLSConfig)
	}
	if got := d.Command("fix"); got != "rowsafe fix 'mysql://app@db.example.com:3307/shop?ssl-mode=VERIFY_IDENTITY'" {
		t.Errorf("command %q", got)
	}
	m, err := Open("mariadb://root@localhost/shop")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Local() || m.Host() != "localhost" || m.Engine() != protocol.EngineMariaDB || m.my.TLSConfig != "preferred" || m.my.Addr != "localhost:3306" {
		t.Errorf("mariadb: local %v host %q engine %s tls %q addr %s", m.Local(), m.Host(), m.Engine(), m.my.TLSConfig, m.my.Addr)
	}
	s, err := Open("mysql://root@/shop?socket=/run/mysqld/mysqld.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Local() || s.my.Net != "unix" || s.my.Addr != "/run/mysqld/mysqld.sock" {
		t.Errorf("socket: local %v %s %s", s.Local(), s.my.Net, s.my.Addr)
	}
	for _, bad := range []string{"mysql://app:s3cret@h:notaport/shop", "mysql://h/db?ssl-mode=SOMETIMES", "mysql://h/db?foo=1"} {
		if _, err := Open(bad); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
