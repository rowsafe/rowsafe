package protocol

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Why a task failed, in a form the control plane can explain. When a tool
// the agent runs (pgBackRest, pg_ctl, initdb, ...) fails, the agent keeps the
// end of its output (secrets removed) and a stable code for what went wrong,
// and sends both with the task's outcome (CompleteRequest.ErrorInfo). The
// control plane turns the code into plain words and, where it can, a button
// that fixes it (TaskView.Problem).
//
// The same classifier runs on the control plane for agents that predate
// ErrorInfo: it reads the task's error and log instead.

// TaskError is a failed task's error: a stable code, the tool, its exit
// code and the last lines of its output with secrets removed.
type TaskError struct {
	// Code is stable, e.g. "pgbackrest.path_not_empty" (TaskErr* below).
	Code     string `json:"code"`
	Tool     string `json:"tool,omitempty"`      // "pgbackrest", "pg_ctl", ...
	ExitCode int    `json:"exit_code,omitempty"` // the tool's exit code (pgBackRest: its error code)
	// Message is the tool's own one-line error ("HTTP request failed with
	// 403 (Forbidden)"), secrets removed.
	Message string `json:"message,omitempty"`
	// Detail is the end of the tool's output, secrets removed.
	Detail string `json:"detail,omitempty"`
	// Facts the agent found out after the failure, e.g. whether the
	// backups already in the folder belong to this database (TaskFact*).
	Facts map[string]string `json:"facts,omitempty"`
}

// Task error codes. pgBackRest's own error codes (its exit status) are
// defined in pgBackRest's src/build/error/error.yaml; they have not changed
// from 2.50 to 2.59: 28 file-invalid, 38 pg-running, 39 protocol (also every
// failed HTTP request to the storage), 40 path-not-empty, 44
// archive-mismatch, 46 version-not-supported, 49 host-connect, 50
// lock-acquire, 51 backup-mismatch, 55 file-missing, 56 db-connect, 58
// db-mismatch, 68 archive-command-invalid, 82 archive-timeout, 87
// archive-disabled, 95 crypto, 101 service, 103 repo-invalid, 105 access,
// 106 clock.
const (
	TaskErrStorageBadKeys     = "pgbackrest.storage_bad_keys"     // the storage doesn't accept the key (wrong, expired, malformed)
	TaskErrStorageDenied      = "pgbackrest.storage_denied"       // the key works but may not use this bucket or folder
	TaskErrStorageNoBucket    = "pgbackrest.storage_no_bucket"    // the bucket doesn't exist (or is named differently)
	TaskErrStorageRegion      = "pgbackrest.storage_wrong_region" // the bucket is in another region than the one set
	TaskErrStorageUnreachable = "pgbackrest.storage_unreachable"  // DNS, firewall, wrong endpoint
	TaskErrStorageTLS         = "pgbackrest.storage_tls"          // the storage's certificate isn't trusted
	TaskErrStorageError       = "pgbackrest.storage_error"        // any other storage error (5xx, throttling)
	TaskErrClockSkew          = "pgbackrest.clock_skew"           // the server's clock is off, so requests are refused
	TaskErrPathNotEmpty       = "pgbackrest.path_not_empty"       // the backup folder has files but no backup index
	TaskErrStanzaMismatch     = "pgbackrest.stanza_mismatch"      // the backups in the folder are of another database (or version)
	TaskErrCipherMismatch     = "pgbackrest.cipher_mismatch"      // the backups in the folder were encrypted with another key
	TaskErrStanzaMissing      = "pgbackrest.stanza_missing"       // backups were never set up in this folder
	TaskErrArchiveNotSet      = "pgbackrest.archive_not_configured"
	TaskErrArchiveTimeout     = "pgbackrest.archive_timeout" // PostgreSQL didn't hand over a WAL file in time
	TaskErrLockHeld           = "pgbackrest.lock_held"       // another backup command is running
	TaskErrDiskFull           = "pgbackrest.disk_full"
	TaskErrPermission         = "pgbackrest.permission_denied"
	TaskErrPGUnreachable      = "pgbackrest.pg_unreachable" // pgBackRest can't connect to PostgreSQL
	TaskErrPGRunning          = "pgbackrest.pg_running"     // a restore target is in use by a running PostgreSQL
	TaskErrVersionUnsupported = "pgbackrest.version_unsupported"
	TaskErrVersionMismatch    = "pgbackrest.version_mismatch"
	TaskErrNotInstalled       = "pgbackrest.not_installed"
	TaskErrOther              = "pgbackrest.other"

	// Other tools (pg_ctl, initdb, pg_upgrade, pg_dump, ...).
	TaskErrPGDiskFull   = "pg.disk_full"
	TaskErrPGPermission = "pg.permission_denied"
	TaskErrPGPortInUse  = "pg.port_in_use"
	TaskErrPGFailed     = "pg.failed"
)

// Facts (TaskError.Facts).
const (
	// TaskFactRepoBelongs says whose backups are in the folder:
	// "this_database", "another_database" or "unknown".
	TaskFactRepoBelongs = "repo_belongs"
	// TaskFactRepoVersion is the PostgreSQL major version of the backups
	// in the folder; TaskFactDBVersion the running one.
	TaskFactRepoVersion = "repo_pg_version"
	TaskFactDBVersion   = "db_pg_version"
	// TaskFactRepoFolder is the folder (repo1-path) the task used.
	TaskFactRepoFolder = "repo_folder"
	TaskFactHTTPStatus = "http_status"
	TaskFactS3Code     = "s3_code"
)

// Values of TaskFactRepoBelongs.
const (
	RepoBelongsThis    = "this_database"
	RepoBelongsOther   = "another_database"
	RepoBelongsUnknown = "unknown"
)

// ExistingBackups* are AdoptParams.ExistingBackups: what to do when the
// backup folder already has something in it.
const (
	// ExistingBackupsUse continues with the backups already in the folder
	// (they are this database's: same system; after a major upgrade the
	// folder is moved to the new version).
	ExistingBackupsUse = "use"
	// ExistingBackupsNewFolder sets backups up in a new, empty folder next
	// to the old one (the agent picks <stanza>-<UTC date and time>). The
	// old folder and its files are left as they are.
	ExistingBackupsNewFolder = "new_folder"
)

// TaskProblem is the control plane's plain explanation of a failed task:
// what happened, what Rowsafe can do about it (Fixes: buttons, applied with
// POST /v1/databases/{ref}/fixes and FindingID) and, only when nothing can
// be done remotely, what a person can do (DoItYourself).
type TaskProblem struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	// CanDo says what Rowsafe can do, in a sentence ("" when the fixes
	// speak for themselves).
	CanDo string `json:"can_do,omitempty"`
	// FindingID names this problem for POST /v1/databases/{ref}/fixes
	// ("task:<task id>"); set when there are fixes.
	FindingID string       `json:"finding_id,omitempty"`
	Fixes     []FindingFix `json:"fixes,omitempty"`
	// DoItYourself: steps for a person, when Rowsafe can't do it for them
	// (keys that never leave the server).
	DoItYourself string `json:"do_it_yourself,omitempty"`
	// DoItYourselfCommand goes with it, when there is one to run on the
	// server.
	DoItYourselfCommand string `json:"do_it_yourself_command,omitempty"`
	// DocsPath is the troubleshooting section on rowsafe.sh.
	DocsPath string `json:"docs_path,omitempty"`
	// Detail is the tool's output (secrets removed), for a collapsed
	// "Details".
	Detail string `json:"detail,omitempty"`
}

// TaskProblemFindingPrefix starts a TaskProblem's FindingID.
const TaskProblemFindingPrefix = "task:"

// ---- Classifying a tool's output ----

// pgBackRest console lines start with a timestamp and a process id:
// "2026-09-26 04:46:00.123 P00  ERROR: [039]: HTTP request failed with 403".
var (
	pgbrLineRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} P\d{2}\s+([A-Z]+):\s?(.*)$`)
	pgbrErrorRE   = regexp.MustCompile(`(?:^|\s)ERROR: \[(\d{3})\]: (.*)$`)
	httpStatusRE  = regexp.MustCompile(`HTTP request failed with (\d{3})`)
	s3CodeRE      = regexp.MustCompile(`<Code>([A-Za-z]+)</Code>`)
	exitStatusRE  = regexp.MustCompile(`exit status (\d{1,3})\b`)
	knownPGTools  = map[string]bool{"pg_ctl": true, "initdb": true, "pg_upgrade": true, "pg_dump": true, "pg_restore": true, "pg_dumpall": true, "psql": true, "pg_basebackup": true, "pg_controldata": true, "pg_rewind": true, "postgres": true}
	commandBeginR = regexp.MustCompile(`\b[a-z-]+ command (begin|end)\b`)
)

// maxDetail bounds TaskError.Detail.
const (
	maxDetailLines = 30
	maxDetailBytes = 4000
)

// ToolName is the tool a command line runs: the command itself, or for
// wrappers (nice, ionice, env, ...) the first known tool among its
// arguments.
func ToolName(name string, args ...string) string {
	base := func(s string) string { return s[strings.LastIndex(s, "/")+1:] }
	tool := base(name)
	if tool == "pgbackrest" || knownPGTools[tool] {
		return tool
	}
	for _, a := range args {
		if b := base(a); b == "pgbackrest" || knownPGTools[b] {
			return b
		}
	}
	return tool
}

// ClassifyToolFailure explains a failed command from its output: exitCode
// is its exit status (-1: it didn't run), out what it printed. secrets are
// values to remove from what is kept (keys, passphrases), besides the
// patterns Redact knows.
func ClassifyToolFailure(tool string, exitCode int, out string, secrets ...string) TaskError {
	out = Redact(out, secrets...)
	te := TaskError{Tool: tool, ExitCode: exitCode, Detail: tailDetail(out)}
	if tool == "pgbackrest" {
		code, msg := pgbackrestError(out)
		if code == 0 {
			code = exitCode
		}
		te.Message = msg
		te.Code = classifyPgBackRest(code, msg+"\n"+out, &te)
		if exitCode < 0 && te.Code == TaskErrOther && out == "" {
			te.Code = TaskErrNotInstalled
		}
		return te
	}
	te.Message = lastLine(out)
	switch {
	case strings.Contains(out, "No space left on device"):
		te.Code = TaskErrPGDiskFull
	case strings.Contains(out, "Permission denied"):
		te.Code = TaskErrPGPermission
	case strings.Contains(out, "Address already in use") || strings.Contains(out, "could not bind"):
		te.Code = TaskErrPGPortInUse
	default:
		te.Code = TaskErrPGFailed
	}
	return te
}

// ClassifyTaskText explains a failed task from its error and log alone
// (agents that predate TaskError): it finds pgBackRest's error in the log,
// or its exit status in the error. ok is false when neither names a
// pgBackRest failure.
func ClassifyTaskText(errText, log string) (TaskError, bool) {
	out := log
	code, _ := pgbackrestError(out)
	if code == 0 { // older agents put the output of pgbackrest info in the error
		out = errText + "\n" + log
		code, _ = pgbackrestError(out)
	}
	if code == 0 && strings.Contains(errText, "pgbackrest") {
		if m := exitStatusRE.FindStringSubmatch(errText); m != nil {
			code, _ = strconv.Atoi(m[1])
		}
	}
	if code == 0 {
		return TaskError{}, false
	}
	return ClassifyToolFailure("pgbackrest", code, out), true
}

// pgbackrestError finds the last "ERROR: [NNN]: message" in pgBackRest's
// output, with the message's continuation lines.
func pgbackrestError(out string) (int, string) {
	lines := strings.Split(out, "\n")
	code, msg := 0, ""
	for i := 0; i < len(lines); i++ {
		m := pgbrErrorRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		code, _ = strconv.Atoi(m[1])
		parts := []string{strings.TrimSpace(m[2])}
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if pgbrLineRE.MatchString(l) || strings.TrimSpace(l) == "" || pgbrErrorRE.MatchString(l) {
				break
			}
			parts = append(parts, strings.TrimSpace(l))
		}
		msg = strings.Join(parts, "\n")
	}
	return code, msg
}

// classifyPgBackRest maps pgBackRest's error code and message to a
// TaskErr* code, noting what it found in te.Facts.
func classifyPgBackRest(code int, text string, te *TaskError) string {
	fact := func(k, v string) {
		if te.Facts == nil {
			te.Facts = map[string]string{}
		}
		te.Facts[k] = v
	}
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.Contains(text, x) {
				return true
			}
		}
		return false
	}
	// Whatever the command, a full disk is a full disk.
	if has("No space left on device") && !has("HTTP request failed") {
		return TaskErrDiskFull
	}
	// Storage requests (39 protocol, 101 service, 103 no valid repository
	// with the storage's answer inside).
	if m := httpStatusRE.FindStringSubmatch(text); m != nil {
		status, _ := strconv.Atoi(m[1])
		fact(TaskFactHTTPStatus, m[1])
		s3 := ""
		if c := s3CodeRE.FindStringSubmatch(text); c != nil {
			s3 = c[1]
			fact(TaskFactS3Code, s3)
		}
		return classifyStorage(status, s3, text)
	}
	switch code {
	case 28, 51: // file-invalid, backup-mismatch
		if has("do not match the database", "do not match", "is this the correct stanza") {
			return TaskErrStanzaMismatch
		}
	case 38:
		return TaskErrPGRunning
	case 40:
		return TaskErrPathNotEmpty
	case 44: // archive-mismatch: WAL of another database or version
		return TaskErrStanzaMismatch
	case 46:
		return TaskErrVersionUnsupported
	case 49:
		return TaskErrStorageUnreachable
	case 50:
		return TaskErrLockHeld
	case 55, 41, 42: // file-missing, file-open, file-read
		switch {
		case has("Permission denied"):
			return TaskErrPermission
		case has("stanza-create been performed", "cannot be opened but is required", "missing stanza"):
			return TaskErrStanzaMissing
		}
	case 56:
		return TaskErrPGUnreachable
	case 58:
		return TaskErrVersionMismatch
	case 68, 87:
		return TaskErrArchiveNotSet
	case 82:
		return TaskErrArchiveTimeout
	case 95: // crypto: the storage's certificate, or the backups' passphrase
		if has("certificate", "TLS", "SSL", "tls") {
			return TaskErrStorageTLS
		}
		return TaskErrCipherMismatch
	case 101:
		return TaskErrStorageError
	case 105:
		return TaskErrStorageBadKeys
	case 106:
		return TaskErrClockSkew
	case 47, 53, 64, 61, 60, 88: // path-create, path-open, file-write, path/file-remove, file-owner
		if has("Permission denied", "Operation not permitted") {
			return TaskErrPermission
		}
	}
	if has("Permission denied") {
		return TaskErrPermission
	}
	if has("stanza-create been performed", "missing stanza path") {
		return TaskErrStanzaMissing
	}
	return TaskErrOther
}

// classifyStorage maps a failed storage request (HTTP status, S3 error
// code) to a TaskErr* code.
func classifyStorage(status int, s3, text string) string {
	switch s3 {
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidToken", "ExpiredToken", "TokenRefreshRequired", "InvalidSecurity":
		return TaskErrStorageBadKeys
	case "AccessDenied", "AllAccessDisabled", "AccountProblem", "Unauthorized":
		return TaskErrStorageDenied
	case "NoSuchBucket":
		return TaskErrStorageNoBucket
	case "PermanentRedirect", "IllegalLocationConstraintException", "InvalidRegionName", "IncorrectEndpoint":
		return TaskErrStorageRegion
	case "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError":
		if strings.Contains(text, "region") {
			return TaskErrStorageRegion
		}
		return TaskErrStorageBadKeys
	case "RequestTimeTooSkewed":
		return TaskErrClockSkew
	case "InvalidArgument":
		if strings.Contains(text, "access key") || strings.Contains(text, "Credential") {
			return TaskErrStorageBadKeys // R2: "Credential access key has length 20, should be 32"
		}
	}
	switch {
	case status == 401:
		return TaskErrStorageBadKeys
	case status == 403:
		return TaskErrStorageDenied
	case status == 404:
		return TaskErrStorageNoBucket
	case status == 301 || status == 307:
		return TaskErrStorageRegion
	}
	return TaskErrStorageError
}

// ---- Removing secrets ----

var redactRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// URLs with credentials: scheme://user:secret@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]*:)[^\s@/]+@`), `${1}<redacted>@`},
	// key=value and key: value where the key names a secret.
	{regexp.MustCompile(`(?i)((?:--)?[a-z0-9_.-]*(?:pass|passphrase|password|secret|token|key-secret|key_secret|s3-key|access[-_]?key|credential|signature|authorization|apikey|api[-_]key)[a-z0-9_.-]*\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&"',]+)`), `${1}<redacted>`},
	// Signed URL query parameters.
	{regexp.MustCompile(`(?i)(X-Amz-(?:Credential|Signature|Security-Token)=)[^&\s]+`), `${1}<redacted>`},
	// AWS access key ids and bearer tokens.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), `<redacted>`},
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`), `${1}<redacted>`},
	// Rowsafe keys and tokens.
	{regexp.MustCompile(`\brs[a-z]_[A-Za-z0-9_-]{8,}`), `<redacted>`},
}

// Redact removes secrets from a tool's output: the given values (keys,
// passphrases the agent knows) and anything that looks like one (a URL's
// password, key=value pairs naming a secret, signed URL parameters, access
// key ids). Values pgBackRest already hid ("<redacted>") stay as they are.
func Redact(s string, secrets ...string) string {
	for _, v := range secrets {
		if len(v) >= 6 {
			s = strings.ReplaceAll(s, v, "<redacted>")
		}
	}
	for _, r := range redactRules {
		s = r.re.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasSuffix(m, "<redacted>") {
				return m
			}
			return r.re.ReplaceAllString(m, r.repl)
		})
	}
	return s
}

// tailDetail is the end of a tool's output: at most maxDetailLines lines
// and maxDetailBytes, without pgBackRest's "command begin/end" lines (the
// full option list).
func tailDetail(out string) string {
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if commandBeginR.MatchString(l) && pgbrLineRE.MatchString(l) {
			continue
		}
		l = strings.TrimRight(l, " \r")
		if strings.HasPrefix(l, "                ") { // pgBackRest's continuation lines line up under the message
			l = "    " + strings.TrimLeft(l, " ")
		}
		keep = append(keep, l)
	}
	if len(keep) > maxDetailLines {
		keep = keep[len(keep)-maxDetailLines:]
	}
	s := strings.TrimSpace(strings.Join(keep, "\n"))
	if len(s) > maxDetailBytes {
		s = "…" + s[len(s)-maxDetailBytes:]
	}
	return s
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300] + "…"
			}
			return l
		}
	}
	return ""
}

// String is a one-line summary for logs: "pgbackrest.storage_denied
// (pgbackrest exit 39: HTTP request failed with 403 (Forbidden))".
func (e TaskError) String() string {
	msg := e.Message
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return fmt.Sprintf("%s (%s exit %d: %s)", e.Code, e.Tool, e.ExitCode, msg)
}
