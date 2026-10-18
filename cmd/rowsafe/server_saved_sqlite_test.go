package main

import (
	"strings"
	"testing"
)

// A SQLite file where the connection string goes: the installer adds it.
func TestAddSQLiteFile(t *testing.T) {
	noLogin(t)
	err := savedAdd(t.Context(), []string{"app", "/srv/my app/database.sqlite"})
	if err == nil || !strings.Contains(err.Error(), "--no-account --sqlite '/srv/my app/database.sqlite'") {
		t.Fatalf("add a SQLite file: %v", err)
	}
	if err := savedAdd(t.Context(), []string{"app", "/srv/app/database.sqlite-wal"}); err == nil || strings.Contains(err.Error(), "--sqlite") {
		t.Fatalf("a -wal file: %v", err)
	}
}
