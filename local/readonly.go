package local

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
)

// readOnly runs fn in a READ ONLY transaction on its own connection, with
// a statement timeout and a short lock timeout, and rolls it back.
// Nothing fn runs can change data: PostgreSQL refuses writes in it.
func (d *DB) readOnly(ctx context.Context, timeout time.Duration, fn func(pgx.Tx) error) error {
	// pginspect's connection: no session settings at startup and the simple
	// protocol, so it works through connection poolers too; the
	// transaction carries its own timeouts.
	conn, err := pginspect.Target{Conn: d.conn, AppName: "rowsafe"}.Connect(ctx, d.conn.Database)
	if err != nil {
		return d.connectError(err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return d.connectError(err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', '1s', true),
		set_config('idle_in_transaction_session_timeout', '60s', true)`, strconv.FormatInt(timeout.Milliseconds(), 10)); err != nil {
		return err
	}
	return fn(tx)
}

// statementText is one SQL statement as a person or an agent gave it.
type statementText struct {
	// SQL without a trailing semicolon.
	SQL string
	// MaxParam is the highest $n placeholder (0: none).
	MaxParam int
	// FirstWord is the first keyword, upper case (WITH, SELECT, ...).
	FirstWord string
}

// readStatement checks that sql holds exactly one statement and finds its
// placeholders, skipping quoted text, comments and dollar-quoted bodies.
func readStatement(sql string) (statementText, error) {
	s := strings.TrimSpace(sql)
	var out statementText
	end := -1 // index of a top-level semicolon
	for i := 0; i < len(s); {
		c := s[i]
		comment := c == '-' && i+1 < len(s) && s[i+1] == '-' || c == '/' && i+1 < len(s) && s[i+1] == '*'
		if end >= 0 && !comment && c != ';' && !unicode.IsSpace(rune(c)) {
			return out, errors.New("give one statement at a time")
		}
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depth := 0
			for i < len(s) {
				if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			if depth != 0 {
				return out, errors.New("the statement has an unterminated /* comment")
			}
			continue
		case c == '\'' || c == '"':
			escapes := c == '\'' && i > 0 && (s[i-1] == 'E' || s[i-1] == 'e') && (i < 2 || !isIdentByte(s[i-2]))
			j := i + 1
			for ; j < len(s); j++ {
				if escapes && s[j] == '\\' {
					j++
					continue
				}
				if s[j] == c {
					if j+1 < len(s) && s[j+1] == c {
						j++
						continue
					}
					break
				}
			}
			if j >= len(s) {
				return out, errors.New("the statement has an unterminated quote")
			}
			i = j + 1
			continue
		case c == '$':
			if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' && (i == 0 || !isIdentByte(s[i-1])) {
				j := i + 1
				for j < len(s) && s[j] >= '0' && s[j] <= '9' {
					j++
				}
				if n, err := strconv.Atoi(s[i+1 : j]); err == nil && n > out.MaxParam {
					out.MaxParam = n
				}
				i = j
				continue
			}
			if i == 0 || !isIdentByte(s[i-1]) {
				if tag, ok := dollarTag(s[i:]); ok {
					k := strings.Index(s[i+len(tag):], tag)
					if k < 0 {
						return out, errors.New("the statement has an unterminated $$ body")
					}
					i += len(tag) + k + len(tag)
					continue
				}
			}
		case c == ';':
			if end < 0 {
				end = i
			}
		}
		i++
	}
	if end >= 0 {
		s = strings.TrimSpace(s[:end])
	}
	if s == "" {
		return out, errors.New("no statement given")
	}
	out.SQL = s
	out.FirstWord = firstWord(s)
	return out, nil
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// dollarTag reads a $tag$ opening at the start of s.
func dollarTag(s string) (string, bool) {
	for j := 1; j < len(s); j++ {
		if s[j] == '$' {
			return s[:j+1], true
		}
		if !isIdentByte(s[j]) || (j == 1 && s[j] >= '0' && s[j] <= '9') {
			return "", false
		}
	}
	return "", false
}

// firstWord is the statement's first keyword, after comments and opening
// parentheses.
func firstWord(s string) string {
	for {
		s = strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '(' })
		switch {
		case strings.HasPrefix(s, "--"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(s, "/*"):
			if i := strings.Index(s, "*/"); i >= 0 {
				s = s[i+2:]
				continue
			}
			return ""
		}
		break
	}
	i := strings.IndexFunc(s, func(r rune) bool { return !unicode.IsLetter(r) })
	if i < 0 {
		i = len(s)
	}
	return strings.ToUpper(s[:i])
}

// sideEffectFuncs are functions that act outside the query even in a
// read-only transaction (end sessions, sleep, take locks, reset statistics,
// reach other servers...): a statement calling one is never run.
var sideEffectFuncs = regexp.MustCompile(`(?i)\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_sleep\w*|` +
	`pg_(try_)?advisory\w*|set_config|pg_switch_w[a-z]+|pg_create_restore_point|pg_promote|pg_stat_reset\w*|pg_stat_statements_reset|` +
	`lo_\w+|pg_file_\w+|pg_read_\w*file|dblink\w*|pg_notify|nextval|setval|pg_logical_emit_message|pg_\w*replication_slot\w*|` +
	`pg_wal_replay_\w+|pg_backup_\w+|pg_start_backup|pg_stop_backup|pg_log_backend_memory_contexts|pg_import_system_collations|` +
	`txid_current|pg_current_xact_id)\s*\(`)
