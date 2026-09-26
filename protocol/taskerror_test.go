package protocol

import (
	"strings"
	"testing"
)

// Real pgBackRest console output (2.55), keys shortened.
const out403 = `2026-09-26 04:46:00.101 P00   INFO: stanza-create command begin 2.55.0: --exec-id=1234-abcd --log-level-console=info --pg1-path=/var/lib/postgresql/16/main --repo1-cipher-pass=<redacted> --repo1-path=/rowsafe/main --repo1-s3-bucket=acme-backups --repo1-s3-endpoint=s3.eu-central-1.amazonaws.com --repo1-s3-key=<redacted> --repo1-s3-key-secret=<redacted> --repo1-type=s3 --stanza=main
2026-09-26 04:46:00.345 P00  ERROR: [039]: HTTP request failed with 403 (Forbidden):
                                    *** Path/Query ***:
                                    GET /?delimiter=%2F&list-type=2&prefix=rowsafe%2Fmain%2Farchive%2Fmain%2F
                                    *** Request Headers ***:
                                    authorization: <redacted>
                                    content-length: 0
                                    host: acme-backups.s3.eu-central-1.amazonaws.com
                                    x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                                    x-amz-date: 20260926T044600Z
                                    x-amz-security-token: <redacted>
                                    *** Response Headers ***:
                                    content-type: application/xml
                                    *** Response Content ***:
                                    <?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>
2026-09-26 04:46:00.346 P00   INFO: stanza-create command end: aborted with exception [039]`

func TestClassifyStorage403(t *testing.T) {
	te := ClassifyToolFailure("pgbackrest", 39, out403)
	if te.Code != TaskErrStorageDenied {
		t.Fatalf("code = %s, want %s", te.Code, TaskErrStorageDenied)
	}
	if te.Facts[TaskFactHTTPStatus] != "403" || te.Facts[TaskFactS3Code] != "AccessDenied" {
		t.Fatalf("facts = %v", te.Facts)
	}
	if !strings.HasPrefix(te.Message, "HTTP request failed with 403 (Forbidden):") {
		t.Fatalf("message = %q", te.Message)
	}
	if strings.Contains(te.Detail, "command begin") || strings.Contains(te.Detail, "command end") {
		t.Fatalf("detail keeps the command lines:\n%s", te.Detail)
	}
	if !strings.Contains(te.Detail, "<Code>AccessDenied</Code>") {
		t.Fatalf("detail lost the storage's answer:\n%s", te.Detail)
	}
}

func TestClassifyPgBackRestCodes(t *testing.T) {
	line := func(code, msg string) string {
		return "2026-09-26 04:46:00.345 P00  ERROR: [" + code + "]: " + msg + "\n2026-09-26 04:46:00.346 P00   INFO: check command end: aborted with exception [" + code + "]"
	}
	for _, c := range []struct {
		exit int
		out  string
		want string
	}{
		{40, line("040", "backup directory and/or archive directory not empty"), TaskErrPathNotEmpty},
		{28, line("028", "backup and archive info files exist but do not match the database\n                                    HINT: is this the correct stanza?"), TaskErrStanzaMismatch},
		{95, line("095", "unable to load info file '/rowsafe/main/archive/main/archive.info' or '/rowsafe/main/archive/main/archive.info.copy':\n    CryptoError: cipher header invalid\n    HINT: is or was the repo encrypted?"), TaskErrCipherMismatch},
		{95, line("095", "unable to verify certificate presented by 'minio.local:9000 (10.0.0.2)': [20] unable to get local issuer certificate"), TaskErrStorageTLS},
		{55, line("055", "unable to load info file '/rowsafe/main/archive/main/archive.info' or '/rowsafe/main/archive/main/archive.info.copy':\n    FileMissingError: unable to open missing file\n    HINT: archive.info cannot be opened but is required to push/get WAL segments.\n    HINT: has a stanza-create been performed?"), TaskErrStanzaMissing},
		{87, line("087", "archive_mode must be enabled"), TaskErrArchiveNotSet},
		{68, line("068", "archive_command '(disabled)' must contain pgbackrest"), TaskErrArchiveNotSet},
		{82, line("082", "WAL segment 000000010000000000000003 was not archived before the 120000ms timeout"), TaskErrArchiveTimeout},
		{50, line("050", "unable to acquire lock on file '/tmp/pgbackrest/main-backup.lock': Resource temporarily unavailable"), TaskErrLockHeld},
		{49, line("049", "unable to get address for 'nope.example.com': [-2] Name or service not known"), TaskErrStorageUnreachable},
		{56, line("056", "unable to connect to 'dbname='postgres' port=5432': connection to server on socket failed"), TaskErrPGUnreachable},
		{64, line("064", "unable to write '/var/spool/pgbackrest/archive/main/out/x': [28] No space left on device"), TaskErrDiskFull},
		{41, line("041", "unable to open file '/var/log/pgbackrest/main-backup.log' for write: [13] Permission denied"), TaskErrPermission},
		{46, line("046", "invalid PostgreSQL version 180000"), TaskErrVersionUnsupported},
		{38, line("038", "unable to restore while PostgreSQL is running"), TaskErrPGRunning},
		{39, line("039", "HTTP request failed with 404 (Not Found):\n    *** Response Content ***:\n    <Error><Code>NoSuchBucket</Code></Error>"), TaskErrStorageNoBucket},
		{39, line("039", "HTTP request failed with 400 (Bad Request):\n    <Error><Code>AuthorizationHeaderMalformed</Code><Message>the region 'us-east-1' is wrong; expecting 'eu-west-1'</Message></Error>"), TaskErrStorageRegion},
		{39, line("039", "HTTP request failed with 403 (Forbidden):\n    <Error><Code>SignatureDoesNotMatch</Code></Error>"), TaskErrStorageBadKeys},
		{39, line("039", "HTTP request failed with 403 (Forbidden):\n    <Error><Code>RequestTimeTooSkewed</Code></Error>"), TaskErrClockSkew},
		{101, line("101", "HTTP request failed with 503 (Service Unavailable)"), TaskErrStorageError},
		{25, line("025", "something unexpected"), TaskErrOther},
		{40, "", TaskErrPathNotEmpty}, // no output: the exit status alone
		{-1, "", TaskErrNotInstalled},
	} {
		te := ClassifyToolFailure("pgbackrest", c.exit, c.out)
		if te.Code != c.want {
			t.Errorf("exit %d %q: code = %s, want %s", c.exit, firstLine(c.out), te.Code, c.want)
		}
	}
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

func TestClassifyOtherTools(t *testing.T) {
	for out, want := range map[string]string{
		"initdb: error: could not create directory \"/x\": No space left on device": TaskErrPGDiskFull,
		"pg_ctl: could not open PID file \"/x/postmaster.pid\": Permission denied":  TaskErrPGPermission,
		"LOG:  could not bind IPv4 address \"127.0.0.1\": Address already in use":   TaskErrPGPortInUse,
		"pg_ctl: server did not start in time":                                      TaskErrPGFailed,
	} {
		if te := ClassifyToolFailure("pg_ctl", 1, out); te.Code != want {
			t.Errorf("%q: code = %s, want %s", out, te.Code, want)
		}
	}
	if got := ToolName("nice", "-n", "10", "/usr/bin/pgbackrest", "--stanza=main", "backup"); got != "pgbackrest" {
		t.Errorf("ToolName(nice ... pgbackrest) = %s", got)
	}
	if got := ToolName("env", "PGPORT=1", "/usr/lib/postgresql/18/bin/pg_upgrade", "--check"); got != "pg_upgrade" {
		t.Errorf("ToolName(env ... pg_upgrade) = %s", got)
	}
}

func TestClassifyTaskText(t *testing.T) {
	// An older agent: the error has only the exit status, the log has the output.
	te, ok := ClassifyTaskText("pgbackrest stanza-create: exit status 39", "04:46:00 found PostgreSQL 16\n04:46:01 stanza-create output:\n"+out403)
	if !ok || te.Code != TaskErrStorageDenied {
		t.Fatalf("ClassifyTaskText = %+v, %v", te, ok)
	}
	// No log at all: the exit status alone.
	te, ok = ClassifyTaskText("pgbackrest stanza-create: exit status 40", "")
	if !ok || te.Code != TaskErrPathNotEmpty {
		t.Fatalf("exit status only: %+v, %v", te, ok)
	}
	if _, ok := ClassifyTaskText("archive_mode is still off: restart PostgreSQL", "04:46:00 found PostgreSQL 16"); ok {
		t.Fatal("classified an error that isn't pgBackRest's")
	}
}

func TestRedact(t *testing.T) {
	in := strings.Join([]string{
		"--repo1-s3-key=AKIAABCDEFGHIJKLMNOP --repo1-s3-key-secret=abc/def+ghi --repo1-cipher-pass=<redacted>",
		"connecting to postgres://app:hunter2hunter2@db.example.com:5432/app",
		"GET /x?X-Amz-Credential=AKIA%2F2026&X-Amz-Signature=deadbeef&list-type=2",
		"authorization: AWS4-HMAC-SHA256 Credential=abc/20260926, Signature=123",
		"PGPASSWORD=s3cr3t-value pg_dump",
		"the passphrase is my-very-own-passphrase-123",
		"token rsa_0123456789abcdef",
	}, "\n")
	got := Redact(in, "my-very-own-passphrase-123")
	for _, secret := range []string{"AKIAABCDEFGHIJKLMNOP", "abc/def+ghi", "hunter2hunter2", "deadbeef", "Signature=123", "s3cr3t-value", "my-very-own-passphrase-123", "rsa_0123456789abcdef"} {
		if strings.Contains(got, secret) {
			t.Errorf("Redact kept %q:\n%s", secret, got)
		}
	}
	for _, keep := range []string{"db.example.com:5432/app", "list-type=2", "--repo1-cipher-pass=<redacted>"} {
		if !strings.Contains(got, keep) {
			t.Errorf("Redact removed %q:\n%s", keep, got)
		}
	}
}
