package preview

import (
	"regexp"
	"strings"
)

// SplitSQLite splits a SQLite script into statements at semicolons outside
// strings ('...'), quoted names ("...", `...`, [...]), comments (-- and
// /* */) and the BEGIN ... END bodies of CREATE TRIGGER (whose CASE ...
// END expressions are followed too). Lines that start with a dot where a
// statement would start are sqlite3 shell commands (.read, .mode ...):
// Meta statements, never run. Leading comments are not part of a
// statement's text.
func SplitSQLite(sql string) ([]Stmt, error) {
	var out []Stmt
	start, line, startLine := 0, 1, 1
	begun := false
	// The statement's first words (to recognise CREATE TRIGGER) and the
	// trigger body's BEGIN/CASE ... END depth.
	var words []string
	trigger, depth := false, 0
	flush := func(end int) {
		text := strings.TrimSpace(sql[start:end])
		if begun && text != "" {
			out = append(out, Stmt{Text: text, Line: startLine})
		}
		begun, words, trigger, depth = false, nil, false, 0
	}
	lineEnd := func(i int) int {
		if end := strings.IndexByte(sql[i:], '\n'); end >= 0 {
			return i + end
		}
		return len(sql)
	}
	i := 0
	for i < len(sql) {
		c := sql[i]
		lineComment := c == '-' && strings.HasPrefix(sql[i:], "--")
		blockComment := c == '/' && strings.HasPrefix(sql[i:], "/*")
		if !begun {
			switch {
			case c == '\n':
				line++
				i++
				start = i
				continue
			case c == ' ' || c == '\t' || c == '\r' || c == ';':
				i++
				start = i
				continue
			case lineComment:
				i = lineEnd(i)
				start = i
				continue
			case blockComment:
				end := strings.Index(sql[i+2:], "*/")
				if end < 0 {
					return nil, ErrUnterminated
				}
				line += strings.Count(sql[i:i+2+end], "\n")
				i += 2 + end + 2
				start = i
				continue
			case c == '.':
				// A sqlite3 shell command runs to the end of its line.
				out = append(out, Stmt{Text: strings.TrimSpace(sql[i:lineEnd(i)]), Line: line, Meta: true})
				i = lineEnd(i)
				start = i
				continue
			}
			begun = true
			startLine = line
		}
		switch {
		case c == '\n':
			line++
			i++
		case lineComment:
			i = lineEnd(i)
		case blockComment:
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, ErrUnterminated
			}
			line += strings.Count(sql[i:i+2+end], "\n")
			i += 2 + end + 2
		case c == '\'' || c == '"' || c == '`' || c == '[':
			closer := c
			if c == '[' {
				closer = ']'
			}
			j, closed := i+1, false
			for j < len(sql) && !closed {
				switch {
				case sql[j] == closer && c != '[' && j+1 < len(sql) && sql[j+1] == closer:
					j += 2 // '' inside a string, "" inside a name
				case sql[j] == closer:
					closed = true
				default:
					if sql[j] == '\n' {
						line++
					}
					j++
				}
			}
			if !closed {
				return nil, ErrUnterminated
			}
			i = j + 1
		case isWordStart(c):
			j := i + 1
			for j < len(sql) && isIdentChar(sql[j]) || j < len(sql) && sql[j] == '$' {
				j++
			}
			w := strings.ToUpper(sql[i:j])
			if len(words) < 3 {
				words = append(words, w)
				trigger = trigger || isCreateTrigger(words)
			}
			if trigger {
				switch w {
				case "BEGIN", "CASE":
					depth++
				case "END":
					if depth > 0 {
						depth--
					}
				}
			}
			i = j
		case c == ';' && depth == 0:
			flush(i)
			i++
			start = i
		default:
			i++
		}
	}
	flush(len(sql))
	return out, nil
}

func isWordStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// isCreateTrigger: CREATE [TEMP|TEMPORARY] TRIGGER.
func isCreateTrigger(words []string) bool {
	if len(words) < 2 || words[0] != "CREATE" {
		return false
	}
	if words[1] == "TRIGGER" {
		return true
	}
	return len(words) == 3 && (words[1] == "TEMP" || words[1] == "TEMPORARY") && words[2] == "TRIGGER"
}

var (
	sqliteTxnRE = regexp.MustCompile(`(?i)^(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b`)
	// Statements SQLite can't run (or ignores) inside a transaction: a
	// script with them was written to run statement by statement.
	sqliteNoTxnRE = regexp.MustCompile(`(?i)^(VACUUM\b|PRAGMA\s+(\w+\.)?(journal_mode|foreign_keys|wal_checkpoint)\b)`)
)

// ModeSQLite says how a SQLite script runs on the copy: in one transaction
// (what migration tools do), or as written when it opens transactions
// itself or has statements that can't run in one (VACUUM, PRAGMA
// journal_mode, PRAGMA foreign_keys, which SQLite ignores inside a
// transaction).
func ModeSQLite(stmts []Stmt) string {
	for _, s := range stmts {
		n := Normalize(s.Text)
		if !s.Meta && (sqliteTxnRE.MatchString(n) || sqliteNoTxnRE.MatchString(n)) {
			return "as_written"
		}
	}
	return "transaction"
}

var (
	sqliteAttachRE     = regexp.MustCompile(`(?i)^(ATTACH|DETACH)\b`)
	sqliteVacuumIntoRE = regexp.MustCompile(`(?i)^VACUUM\b.*\bINTO\b`)
	sqliteDirPragmaRE  = regexp.MustCompile(`(?i)^PRAGMA\s+(\w+\.)?(temp_store_directory|data_store_directory)\b`)
	sqliteLoadExtRE    = regexp.MustCompile(`(?i)\bload_extension\s*\(`)
)

// SkipSQLite is why a statement isn't run on the copy ("" to run it):
// shell commands, and statements that would open or write files outside
// the copy or load native code.
func SkipSQLite(s Stmt) string {
	if s.Meta {
		return "A sqlite3 shell command, not SQL: skipped."
	}
	n := Normalize(s.Text)
	switch {
	case sqliteAttachRE.MatchString(n):
		return "Opens or closes another database file: not run on the copy, which only uses its own file."
	case sqliteVacuumIntoRE.MatchString(n):
		return "Writes a copy of the database into another file: not run on the copy."
	case sqliteDirPragmaRE.MatchString(n):
		return "Changes where SQLite keeps files on the server: not run on the copy."
	case sqliteLoadExtRE.MatchString(n):
		return "Loads a native library into SQLite: not run on the copy."
	}
	return ""
}

var sqliteBeginWriteRE = regexp.MustCompile(`(?i)^BEGIN\s+(IMMEDIATE|EXCLUSIVE)\b`)

// sqliteTxnState follows the transactions a script opens itself.
type sqliteTxnState struct{ depth int }

// step moves past statement text and reports whether the statement ran
// inside a transaction the script opened, and whether it ended one.
func (t *sqliteTxnState) step(text string) (inside, ended bool) {
	n := strings.ToUpper(Normalize(text))
	switch {
	case strings.HasPrefix(n, "BEGIN"):
		t.depth = 1
		return true, false
	case strings.HasPrefix(n, "SAVEPOINT"):
		t.depth++
		return true, false
	case strings.HasPrefix(n, "COMMIT") || strings.HasPrefix(n, "END"):
		was := t.depth > 0
		t.depth = 0
		return was, was
	case strings.HasPrefix(n, "ROLLBACK") && !strings.Contains(n, " TO "):
		was := t.depth > 0
		t.depth = 0
		return was, was
	case strings.HasPrefix(n, "RELEASE"):
		was := t.depth > 0
		if t.depth > 0 {
			t.depth--
		}
		return was, was && t.depth == 0
	}
	return t.depth > 0, false
}
