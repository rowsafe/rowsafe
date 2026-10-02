package preview

import (
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// SplitFor splits a migration script in the engine's SQL dialect:
// PostgreSQL's (Split), or MySQL's, MariaDB's and ClickHouse's
// (SplitMySQL). MongoDB migrations are scripts, not SQL: they aren't split.
func SplitFor(engine, sql string) ([]Stmt, error) {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineMySQL, protocol.EngineMariaDB, protocol.EngineClickHouse:
		return SplitMySQL(sql)
	}
	return Split(sql)
}

var delimiterRE = regexp.MustCompile(`(?i)^DELIMITER\s+(\S+)`)

// SplitMySQL splits a MySQL, MariaDB or ClickHouse script into statements
// at the delimiter (; unless a DELIMITER line changes it, as mysql dumps of
// procedures and triggers do) outside quotes, backquoted names and
// comments (--, # and /* */). DELIMITER lines become Meta statements.
// Leading comments are not part of a statement's text.
func SplitMySQL(sql string) ([]Stmt, error) {
	var out []Stmt
	delim := ";"
	start, line, startLine := 0, 1, 1
	begun := false
	flush := func(end int) {
		text := strings.TrimSpace(sql[start:end])
		if begun && text != "" {
			out = append(out, Stmt{Text: text, Line: startLine})
		}
		begun = false
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
		lineComment := (c == '-' && strings.HasPrefix(sql[i:], "--") && (i+2 == len(sql) || strings.ContainsRune(" \t\r\n", rune(sql[i+2])))) || c == '#'
		if !begun {
			switch {
			case c == '\n':
				line++
				i++
				start = i
				continue
			case c == ' ' || c == '\t' || c == '\r':
				i++
				start = i
				continue
			case lineComment:
				i = lineEnd(i)
				start = i
				continue
			case c == '/' && strings.HasPrefix(sql[i:], "/*") && !strings.HasPrefix(sql[i:], "/*!"):
				end := strings.Index(sql[i+2:], "*/")
				if end < 0 {
					return nil, ErrUnterminated
				}
				line += strings.Count(sql[i:i+2+end], "\n")
				i += 2 + end + 2
				start = i
				continue
			}
			if m := delimiterRE.FindStringSubmatch(sql[i:lineEnd(i)]); m != nil {
				out = append(out, Stmt{Text: strings.TrimSpace(sql[i:lineEnd(i)]), Line: line, Meta: true})
				delim = m[1]
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
		case c == '/' && strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, ErrUnterminated
			}
			line += strings.Count(sql[i:i+2+end], "\n")
			i += 2 + end + 2
		case c == '\'' || c == '"' || c == '`':
			j, closed := i+1, false
			for j < len(sql) && !closed {
				switch {
				case sql[j] == '\\' && c != '`' && j+1 < len(sql):
					if sql[j+1] == '\n' {
						line++
					}
					j += 2
				case sql[j] == c && j+1 < len(sql) && sql[j+1] == c:
					j += 2
				case sql[j] == c:
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
		case strings.HasPrefix(sql[i:], delim):
			flush(i)
			i += len(delim)
			start = i
		default:
			i++
		}
	}
	flush(len(sql))
	return out, nil
}
