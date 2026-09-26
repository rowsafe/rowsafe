// Package preview is Guard's migration preview logic that doesn't need a
// database: splitting SQL into statements, recognising risky DDL, and turning
// what a migration did on a copy into a verdict with plain-words impact and
// suggestions. The agent runs the migration (internal/agent); the CLI,
// dashboard and GitHub Action show the result.
package preview

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// Stmt is one SQL statement of a script.
type Stmt struct {
	Text string // as written, without the trailing semicolon
	Line int    // 1-based line where it starts
	// Meta is a psql meta-command (\set, \c ...): not SQL, not run.
	Meta bool
}

// ErrUnterminated is returned for a quote, comment or dollar-quoted string
// that never ends.
var ErrUnterminated = errors.New("the SQL ends inside a quoted string or comment")

var dollarTagRE = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$`)

// Split splits a script into statements at semicolons outside quotes,
// dollar-quoted bodies and comments. Empty statements are dropped. psql
// meta-commands (lines starting with a backslash) become Meta statements.
func Split(sql string) ([]Stmt, error) {
	var out []Stmt
	start, line, startLine := 0, 1, 1
	begun := false // a non-space, non-comment character was seen
	flush := func(end int) {
		text := strings.TrimSpace(sql[start:end])
		if begun && stripComments(text) != "" {
			out = append(out, Stmt{Text: text, Line: startLine})
		}
		begun = false
	}
	i := 0
	for i < len(sql) {
		c := sql[i]
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
			case c == '\\':
				// A psql meta-command runs to the end of the line.
				end := strings.IndexByte(sql[i:], '\n')
				if end < 0 {
					end = len(sql) - i
				}
				out = append(out, Stmt{Text: strings.TrimSpace(sql[i : i+end]), Line: line, Meta: true})
				i += end
				start = i
				continue
			case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			default:
				begun = true
				startLine = line
			}
		}
		switch {
		case c == '\n':
			line++
			i++
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				i = len(sql)
			} else {
				i += end
			}
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			depth := 1
			i += 2
			for i < len(sql) && depth > 0 {
				switch {
				case sql[i] == '\n':
					line++
					i++
				case strings.HasPrefix(sql[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(sql[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth > 0 {
				return nil, ErrUnterminated
			}
		case c == '\'':
			// E'...' strings allow backslash escapes.
			escapes := i > 0 && (sql[i-1] == 'E' || sql[i-1] == 'e') && (i == 1 || !isIdentChar(sql[i-2]))
			i++
			closed := false
			for i < len(sql) {
				switch {
				case sql[i] == '\n':
					line++
					i++
				case escapes && sql[i] == '\\' && i+1 < len(sql):
					if sql[i+1] == '\n' {
						line++
					}
					i += 2
				case sql[i] == '\'' && i+1 < len(sql) && sql[i+1] == '\'':
					i += 2
				case sql[i] == '\'':
					i++
					closed = true
				default:
					i++
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, ErrUnterminated
			}
		case c == '"':
			j, closed := i+1, false
			for j < len(sql) && !closed {
				switch {
				case sql[j] == '"' && j+1 < len(sql) && sql[j+1] == '"': // "" inside an identifier
					j += 2
				case sql[j] == '"':
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
		case c == '$' && (i == 0 || !isIdentChar(sql[i-1])):
			tag := dollarTagRE.FindString(sql[i:])
			if tag == "" {
				i++
				continue
			}
			end := strings.Index(sql[i+len(tag):], tag)
			if end < 0 {
				return nil, ErrUnterminated
			}
			body := sql[i : i+len(tag)+end+len(tag)]
			line += strings.Count(body, "\n")
			i += len(body)
		case c == ';':
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

func isIdentChar(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// stripComments removes -- and /* */ comments and collapses whitespace
// outside quotes, for recognising statements (not for running them).
func stripComments(s string) string {
	var b strings.Builder
	space := false
	i := 0
	emit := func(c byte) {
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(c)
	}
	for i < len(s) {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				i = len(s)
			} else {
				i += end
			}
			space = true
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depth := 1
			i += 2
			for i < len(s) && depth > 0 {
				switch {
				case strings.HasPrefix(s[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(s[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			space = true
		case c == '\'' || c == '"':
			end := i + 1
			for end < len(s) {
				if s[end] == c {
					if end+1 < len(s) && s[end+1] == c {
						end += 2
						continue
					}
					break
				}
				end++
			}
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteString(s[i:min(end+1, len(s))])
			i = end + 1
		case unicode.IsSpace(rune(c)):
			space = true
			i++
		default:
			emit(c)
			i++
		}
	}
	return b.String()
}

// Normalize is a statement without comments, on one line, for matching.
func Normalize(stmt string) string { return stripComments(stmt) }

// Shorten cuts a statement for reports: whitespace collapsed, at most n
// characters.
func Shorten(stmt string, n int) string {
	s := stripComments(stmt)
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 { // don't split a UTF-8 character
		cut = cut[:len(cut)-1]
	}
	if len(cut) > 0 && cut[len(cut)-1] >= 0xC0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}
