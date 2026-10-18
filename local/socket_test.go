// SPDX-License-Identifier: Apache-2.0

package local

import (
	"fmt"
	"os"
	"os/user"
	"testing"
)

// The agent's Docker container reaches the postgres service over TCP and
// over the shared socket: the same server only when both answer with the
// same start time.
func TestSocketPortLocalPostgres(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	socket, port := "/tmp", "5432"
	if v := os.Getenv("ROWSAFE_TEST_PG_SOCKET"); v != "" {
		socket = v
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_PORT"); v != "" {
		port = v
	}
	d, err := Open(fmt.Sprintf("postgres://%s@127.0.0.1:%s/postgres?sslmode=disable", u.Username, port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Check(t.Context()); err != nil {
		t.Skipf("no local PostgreSQL over TCP on port %s: %v", port, err)
	}
	p, ok, err := d.SocketPort(t.Context(), socket)
	if err != nil || !ok || fmt.Sprint(p) != port {
		t.Fatalf("SocketPort(%s) = %d, %v, %v; want %s, true", socket, p, ok, err, port)
	}
	// No server's socket in an empty directory.
	if p, ok, err := d.SocketPort(t.Context(), t.TempDir()); err != nil || ok {
		t.Fatalf("SocketPort(empty dir) = %d, %v, %v; want false", p, ok, err)
	}
	// A server that can't be reached is an error, not a match.
	far, _ := Open("postgres://nobody@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=2")
	if _, ok, err := far.SocketPort(t.Context(), socket); err == nil || ok {
		t.Fatalf("SocketPort(unreachable) = %v, %v; want an error", ok, err)
	}
}

func TestSocketPortMySQL(t *testing.T) {
	d, err := Open("mysql://app@db:3306/shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := d.SocketPort(t.Context(), "/var/run/postgresql"); ok || err != nil {
		t.Fatalf("MySQL: %v, %v", ok, err)
	}
}
