package local

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestOpenMongoDB(t *testing.T) {
	for _, s := range []string{"mongodb://h", "MONGODB+SRV://u:p@cluster0.example.net/shop"} {
		if !IsConnString(s) {
			t.Errorf("%q is a connection string", s)
		}
	}
	d, err := Open("mongodb://app:s3cret@db1.example.com:27017,db2.example.com:27018/shop?authSource=admin&replicaSet=rs0")
	if err != nil {
		t.Fatal(err)
	}
	if !d.PasswordInURL || d.Ref != "mongodb://app@db1.example.com:27017,db2.example.com:27018/shop?authSource=admin&replicaSet=rs0" {
		t.Errorf("ref %q (password in URL %v)", d.Ref, d.PasswordInURL)
	}
	if d.Name() != "shop" || d.Host() != "db1.example.com" || d.Local() || d.Engine() != protocol.EngineMongoDB || d.EngineName() != "MongoDB" {
		t.Errorf("name %q host %q local %v engine %s", d.Name(), d.Host(), d.Local(), d.Engine())
	}
	l, err := Open("mongodb://127.0.0.1:27018/?directConnection=true")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Local() || l.Host() != "127.0.0.1:27018" || l.Name() != "mongodb" || l.PasswordInURL {
		t.Errorf("local %v host %q name %q", l.Local(), l.Host(), l.Name())
	}
	if srv, _ := Open("mongodb+srv://u:pw@localhost.example.net/x"); srv == nil || srv.Local() {
		t.Error("an SRV record is never this machine")
	}
	for _, bad := range []string{"mongodb://app:s3cret@h:notaport/shop", "mongodb://app:s3cret@h/shop?replicaSet=a&directConnection=true&connect=bogus"} {
		if _, err := Open(bad); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if s := withoutPassword("mongodb://a:b@c@h/db?x=@"); s != "mongodb://a@h/db?x=@" {
		t.Errorf("withoutPassword %q", s)
	}
	if _, err := d.ChangeSettings(t.Context(), protocol.SettingsParams{}); err == nil || !strings.Contains(err.Error(), "mongod.conf") {
		t.Errorf("settings: %v", err)
	}
	if _, err := d.Explain(t.Context(), "SELECT 1", ExplainOptions{}); err == nil || !strings.Contains(err.Error(), "PostgreSQL for now, not MongoDB") {
		t.Errorf("explain: %v", err)
	}
}
