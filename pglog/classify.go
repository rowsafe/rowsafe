package pglog

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

var (
	durationRE      = regexp.MustCompile(`^duration: ([0-9.]+) ms(?:\s+(?:statement|execute|bind|parse|fastpath)|$)`)
	lockWaitRE      = regexp.MustCompile(`^process \d+ (?:still waiting for|acquired) \S+ on .* after ([0-9.]+) ms`)
	pgHbaHostRE     = regexp.MustCompile(`no pg_hba\.conf entry for (?:replication connection from )?host "([^"]+)"`)
	connReceivedRE  = regexp.MustCompile(`^connection received: host=(\S+)`)
	tempFileRE      = regexp.MustCompile(`^temporary file: path "[^"]*", size \d+`)
	checkpointRE    = regexp.MustCompile(`^(?:checkpoint|restartpoint)s? (?:starting|complete)|^checkpoints are occurring too frequently|^recovery restart point`)
	autovacuumRE    = regexp.MustCompile(`^automatic (?:aggressive )?(?:vacuum|analyze) (?:to prevent wraparound )?of table`)
	statementLogRE  = regexp.MustCompile(`^(?:statement|execute [^:]*|bind [^:]*|parse [^:]*): `)
	tooManyRE       = regexp.MustCompile(`too many clients already|remaining connection slots are reserved|too many connections for (?:role|database)`)
	authFailRE      = regexp.MustCompile(`authentication failed for user|no pg_hba\.conf entry|^role "[^"]*" does not exist|^password authentication failed`)
	serverLifecycle = []string{
		"database system is ready to accept", "database system is shut down", "database system was shut down",
		"database system was interrupted", "received fast shutdown request", "received smart shutdown request",
		"received immediate shutdown request", "received SIGHUP, reloading configuration files",
		"parameter \"", "starting PostgreSQL", "listening on ", "redo starts at", "redo done at",
		"database system was not properly shut down", "server process (PID", "terminating any other active server processes",
		"all server processes terminated", "shutting down", "aborting any active transactions",
		"background worker \"logical replication launcher\" (PID", "database system is ready to accept read-only connections",
		"consistent recovery state reached", "entering standby mode", "archive recovery complete", "selected new timeline",
	}
)

// Classify sets an entry's kind and duration from its message and
// SQLSTATE. It runs before redaction (on the message as PostgreSQL wrote
// it), and reads the client address out of the message when the prefix
// had none.
func Classify(e *Entry) {
	msg := e.Message
	switch {
	case e.SQLState == "40P01" || strings.HasPrefix(msg, "deadlock detected"):
		e.Kind = protocol.LogKindDeadlock
	case e.SQLState == "53300" || tooManyRE.MatchString(msg):
		e.Kind = protocol.LogKindTooManyConnections
	case e.SQLState == "28P01" || (e.Severity == "FATAL" && (e.SQLState == "28000" || authFailRE.MatchString(msg))):
		e.Kind = protocol.LogKindAuthFailure
		if m := pgHbaHostRE.FindStringSubmatch(msg); m != nil && (e.Client == "" || e.Client == "[local]") {
			e.Client = m[1]
		}
	case lockWaitRE.MatchString(msg):
		e.Kind = protocol.LogKindLockWait
		if m := lockWaitRE.FindStringSubmatch(msg); m != nil {
			e.DurationMs = parseMs(m[1])
		}
	case durationRE.MatchString(msg):
		m := durationRE.FindStringSubmatch(msg)
		e.DurationMs = parseMs(m[1])
		e.Kind = protocol.LogKindSlowQuery
		// "duration: 1.2 ms" alone (log_duration) says which statement
		// only with log_statement; it is still a timing.
	case IsError(e.Severity):
		e.Kind = protocol.LogKindError
	case checkpointRE.MatchString(msg):
		e.Kind = protocol.LogKindCheckpoint
	case autovacuumRE.MatchString(msg):
		e.Kind = protocol.LogKindAutovacuum
	case tempFileRE.MatchString(msg):
		e.Kind = protocol.LogKindTempFile
	case strings.HasPrefix(msg, "connection received:") || strings.HasPrefix(msg, "connection authorized:") ||
		strings.HasPrefix(msg, "connection authenticated:") || strings.HasPrefix(msg, "disconnection:") ||
		strings.HasPrefix(msg, "replication connection authorized:"):
		e.Kind = protocol.LogKindConnection
		if m := connReceivedRE.FindStringSubmatch(msg); m != nil && e.Client == "" {
			e.Client = m[1]
		}
	case statementLogRE.MatchString(msg):
		e.Kind = protocol.LogKindStatement
	case isServerLifecycle(msg):
		e.Kind = protocol.LogKindServer
	default:
		e.Kind = protocol.LogKindOther
	}
}

func isServerLifecycle(msg string) bool {
	for _, p := range serverLifecycle {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

func parseMs(s string) *float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

// Grouping. Repeated messages share a fingerprint: the kind, SQLSTATE and
// message with values, numbers and statements taken out.

var (
	fpQuotedRE  = regexp.MustCompile(`"(?:[^"]|"")*"|'(?:[^']|'')*'`)
	fpNumberRE  = regexp.MustCompile(`\b\d+(?:[.,:/-]\d+)*\b|0x[0-9a-fA-F]+`)
	fpSpaceRE   = regexp.MustCompile(`\s+`)
	fpParamRE   = regexp.MustCompile(`\$\d+`)
	fpDurPrefix = regexp.MustCompile(`^duration: [0-9.]+ ms\s+`)
)

// identifierQuoted: messages whose quoted names identify the problem
// (the relation, column, role or constraint), so they stay in the
// fingerprint.
var identifierQuoted = regexp.MustCompile(`^(?:relation|column|table|index|function|operator|type|schema|constraint|database|role|extension|sequence|view|trigger|publication|subscription) "|violates (?:unique|foreign key|check|not-null|exclusion) constraint|does not exist$|already exists$|permission denied for`)

// Fingerprint groups repeated messages: "duplicate key value violates
// unique constraint "users_email_key"" is one group whatever the value,
// and so is every slow run of one statement.
func Fingerprint(kind, sqlstate, message string) string {
	m := fpDurPrefix.ReplaceAllString(message, "")
	switch kind {
	case protocol.LogKindSlowQuery, protocol.LogKindStatement:
		// The statement is the message; normalize it again so the full
		// text setting doesn't split groups.
		if i := strings.Index(m, ": "); i >= 0 {
			m = m[:i+2] + NormalizeSQL(m[i+2:])
		}
		m = fpParamRE.ReplaceAllString(m, "?")
	case protocol.LogKindAuthFailure, protocol.LogKindConnection, protocol.LogKindCheckpoint,
		protocol.LogKindAutovacuum, protocol.LogKindTempFile, protocol.LogKindLockWait:
		// One group per kind of event, whoever and whatever it was about.
		m = fpQuotedRE.ReplaceAllString(m, "?")
	default:
		if !identifierQuoted.MatchString(m) {
			m = fpQuotedRE.ReplaceAllString(m, "?")
		}
	}
	m = fpNumberRE.ReplaceAllString(m, "N")
	m = fpSpaceRE.ReplaceAllString(strings.TrimSpace(m), " ")
	if len(m) > 400 {
		m = m[:400]
	}
	sum := sha256.Sum256([]byte(kind + "\x00" + sqlstate + "\x00" + m))
	return hex.EncodeToString(sum[:8])
}
