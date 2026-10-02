package clickhouse

import (
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestAdminGrantsOK(t *testing.T) {
	ok := `GRANT SHOW ACCESS ON *.* TO rowsafe
GRANT CREATE USER, ALTER USER, DROP USER ON * TO rowsafe
GRANT SELECT, INSERT, ALTER, CREATE DATABASE, CREATE TABLE, DROP DATABASE, DROP TABLE ON *.* TO rowsafe WITH GRANT OPTION`
	if !adminGrantsOK(ok) {
		t.Error("ok")
	}
	if adminGrantsOK("GRANT SELECT, INSERT, BACKUP ON *.* TO rowsafe") {
		t.Error("old login")
	}
	if !adminGrantsOK("GRANT ALL ON *.* TO default WITH GRANT OPTION") {
		t.Error("all")
	}
	if adminGrantsOK("GRANT CREATE USER ON * TO r\nGRANT CREATE DATABASE, CREATE TABLE, DROP DATABASE, SELECT ON *.* TO r") {
		t.Error("no grant option")
	}
}

func TestCHPasswordKindAndListen(t *testing.T) {
	for in, want := range map[string]string{"no_password": protocol.PasswordNone, "['plaintext_password']": protocol.PasswordWeak,
		"sha256_password": protocol.PasswordSet, "['bcrypt_password']": protocol.PasswordSet} {
		if got := chPasswordKind(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	got := xmlListenHosts([]byte(`<clickhouse><listen_host>::</listen_host><x><listen_host>no</listen_host></x><listen_host>10.0.0.1</listen_host></clickhouse>`))
	if len(got) != 2 || got[0] != "::" || got[1] != "10.0.0.1" {
		t.Error(got)
	}
}
