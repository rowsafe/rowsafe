package client

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestNewCopyPassword(t *testing.T) {
	pw, v, err := NewCopyPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 24 || strings.ContainsAny(pw, "0O1lI:/@?#") || !protocol.ValidPasswordVerifier(v) {
		t.Fatalf("password %q verifier %q", pw, v)
	}
	if strings.Contains(v, pw) {
		t.Fatal("the verifier contains the password")
	}
}

// TestSCRAMVerifierMatchesPostgres compares the verifier with the one
// PostgreSQL computes itself for the same password and salt.
func TestSCRAMVerifierMatchesPostgres(t *testing.T) {
	url := os.Getenv("ROWSAFE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ROWSAFE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Skip(err)
	}
	defer conn.Close(ctx)
	role := "rowsafe_scram_test_" + strconv.Itoa(os.Getpid())
	if _, err := conn.Exec(ctx, "SET password_encryption = 'scram-sha-256'; CREATE ROLE "+role+" PASSWORD 'correct horse battery'"); err != nil {
		t.Skip(err)
	}
	defer conn.Exec(ctx, "DROP ROLE "+role)
	var stored string
	if err := conn.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	// SCRAM-SHA-256$<iter>:<salt>$<stored>:<server>
	head, _, _ := strings.Cut(strings.TrimPrefix(stored, "SCRAM-SHA-256$"), "$")
	iterStr, saltB64, _ := strings.Cut(head, ":")
	iter, _ := strconv.Atoi(iterStr)
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	got, err := SCRAMVerifier("correct horse battery", salt, iter)
	if err != nil {
		t.Fatal(err)
	}
	if got != stored {
		t.Fatalf("verifier\n got %s\nwant %s", got, stored)
	}
	if !protocol.ValidPasswordVerifier(stored) {
		t.Fatalf("PostgreSQL's own verifier is rejected: %s", stored)
	}
}

func TestConnectionString(t *testing.T) {
	cp := protocol.SafeCopy{Host: "10.0.0.5", Port: 55440, DB: "app", Role: "rowsafe_copy_ab12"}
	if got := ConnectionString(cp, "s3cret"); got != "postgresql://rowsafe_copy_ab12:s3cret@10.0.0.5:55440/app?sslmode=require" {
		t.Error(got)
	}
	if got := ConnectionString(cp, ""); got != "postgresql://rowsafe_copy_ab12@10.0.0.5:55440/app?sslmode=require" {
		t.Error(got)
	}
	cp.Host = "fd00::1"
	if got := ConnectionString(cp, ""); !strings.Contains(got, "[fd00::1]:55440") {
		t.Error(got)
	}
}
