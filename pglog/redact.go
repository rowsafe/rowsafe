package pglog

import (
	"regexp"
	"strconv"
	"strings"
)

// Redaction. Statements in PostgreSQL's log carry whatever the application
// sent: e-mail addresses, names, tokens. Before an entry leaves the server
// the agent
//
//   - normalizes statements like pg_stat_statements does: every string,
//     number, bit or hex constant becomes $1, $2, ... and comments are
//     removed (NormalizeSQL);
//   - removes the values PostgreSQL quotes in error messages and details
//     ("invalid input syntax for type integer: "abc"", "Key (email)=(...)",
//     "Failing row contains (...)", COPY data, bind parameters), and every
//     quoted string and number in messages raised by the database's own
//     functions (SQLSTATE class P0);
//   - always replaces statements that may carry a password (CREATE/ALTER
//     ROLE ... PASSWORD, connection strings with password=, pgcrypto
//     calls), even when full query text is on.

// PasswordPlaceholder replaces a statement that may contain a password.
const PasswordPlaceholder = "<redacted: the statement may contain a password>"

// Hidden replaces a value in a message.
const Hidden = "…"

// passwordRE matches text that may carry a password in clear text: the
// same rule as the activity collector's (collect/postgres.go), plus
// foreign server and user mapping options.
var passwordRE = regexp.MustCompile(`(?is)\b(create|alter)\s+(role|user)\b.*\bpassword\b|\bpassword\s*=\s*\S|\bpgp_sym_(en|de)crypt\s*\(|\bcrypt\s*\(|\boptions\s*\(.*\bpassword\b|\bpassword\s+'`)

// MayContainPassword reports whether text may carry a password.
func MayContainPassword(s string) bool { return passwordRE.MatchString(s) }

// maxStatement bounds a statement's length after normalization.
const maxStatement = 4000

// NormalizeSQL replaces constants in a statement with $n placeholders
// (numbered after the statement's own parameters) and removes comments.
// Identifiers, keywords and operators are kept. It never fails: text that
// isn't valid SQL is normalized as far as it lexes. A statement that may
// carry a password becomes PasswordPlaceholder.
func NormalizeSQL(q string) string {
	if MayContainPassword(q) {
		return PasswordPlaceholder
	}
	n := maxParam(q)
	var b strings.Builder
	b.Grow(len(q))
	param := func() {
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	prevIdent := false // the previous byte continues an identifier or number
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c == '-' && i+1 < len(q) && q[i+1] == '-': // line comment
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				i = len(q)
			} else {
				i += j
			}
			prevIdent = false
			continue
		case c == '/' && i+1 < len(q) && q[i+1] == '*': // block comment (nests in PostgreSQL)
			depth, j := 1, i+2
			for j < len(q) && depth > 0 {
				switch {
				case strings.HasPrefix(q[j:], "/*"):
					depth++
					j += 2
				case strings.HasPrefix(q[j:], "*/"):
					depth--
					j += 2
				default:
					j++
				}
			}
			i = j
			if b.Len() > 0 && !strings.HasSuffix(b.String(), " ") {
				b.WriteByte(' ')
			}
			prevIdent = false
			continue
		case c == '\'':
			i = skipString(q, i, false)
			param()
			prevIdent = true
			continue
		case (c == 'E' || c == 'e') && !prevIdent && i+1 < len(q) && q[i+1] == '\'':
			i = skipString(q, i+1, true)
			param()
			prevIdent = true
			continue
		case (c == 'B' || c == 'b' || c == 'X' || c == 'x' || c == 'N' || c == 'n') && !prevIdent && i+1 < len(q) && q[i+1] == '\'':
			i = skipString(q, i+1, false)
			param()
			prevIdent = true
			continue
		case (c == 'U' || c == 'u') && !prevIdent && strings.HasPrefix(q[i+1:], "&'"):
			i = skipString(q, i+2, false)
			param()
			prevIdent = true
			continue
		case c == '"': // quoted identifier: kept
			j := i + 1
			for j < len(q) {
				if q[j] == '"' {
					if j+1 < len(q) && q[j+1] == '"' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			b.WriteString(q[i:j])
			i = j
			prevIdent = true
			continue
		case c == '$' && !prevIdent:
			if j, ok := dollarQuote(q, i); ok {
				i = j
				param()
				prevIdent = true
				continue
			}
			// $1: a parameter, kept.
			j := i + 1
			for j < len(q) && isDigit(q[j]) {
				j++
			}
			b.WriteString(q[i:j])
			i = j
			prevIdent = true
			continue
		case isDigit(c) && !prevIdent, c == '.' && !prevIdent && i+1 < len(q) && isDigit(q[i+1]):
			i = skipNumber(q, i)
			param()
			prevIdent = true
			continue
		}
		b.WriteByte(c)
		prevIdent = isIdentByte(c)
		i++
	}
	out := strings.TrimSpace(trailingSpaceRE.ReplaceAllString(b.String(), "\n"))
	if len(out) > maxStatement {
		out = clipUTF8(out, maxStatement) + "…"
	}
	return out
}

// trailingSpaceRE: spaces left before a newline (a removed comment).
var trailingSpaceRE = regexp.MustCompile(`[ \t]+\n`)

// maxParam is the highest $n in q (0 without parameters).
func maxParam(q string) int {
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] != '$' || (i > 0 && isIdentByte(q[i-1])) {
			continue
		}
		j := i + 1
		for j < len(q) && isDigit(q[j]) {
			j++
		}
		if j > i+1 {
			if v, err := strconv.Atoi(q[i+1 : j]); err == nil && v > n && v < 1<<16 {
				n = v
			}
		}
	}
	return n
}

// skipString returns the index after the string literal starting at the
// quote q[i]. backslash: an escape string (E'...'), where \' doesn't end
// the string.
func skipString(q string, i int, backslash bool) int {
	j := i + 1
	for j < len(q) {
		switch q[j] {
		case '\\':
			if backslash {
				j += 2
				continue
			}
		case '\'':
			if j+1 < len(q) && q[j+1] == '\'' {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(q)
}

// dollarQuote recognizes $tag$...$tag$ at i and returns the index after it.
func dollarQuote(q string, i int) (int, bool) {
	j := i + 1
	for j < len(q) && (isLetter(q[j]) || q[j] == '_' || (j > i+1 && isDigit(q[j]))) {
		j++
	}
	if j >= len(q) || q[j] != '$' {
		return 0, false
	}
	tag := q[i : j+1]
	end := strings.Index(q[j+1:], tag)
	if end < 0 {
		return len(q), true
	}
	return j + 1 + end + len(tag), true
}

// skipNumber returns the index after the numeric constant at i: decimal,
// with a fraction and exponent, or 0x/0o/0b with underscores (PostgreSQL
// 16).
func skipNumber(q string, i int) int {
	j := i
	if q[j] == '0' && j+1 < len(q) && strings.ContainsRune("xXoObB", rune(q[j+1])) {
		j += 2
		for j < len(q) && (isHex(q[j]) || q[j] == '_') {
			j++
		}
		return j
	}
	for j < len(q) && (isDigit(q[j]) || q[j] == '_') {
		j++
	}
	if j < len(q) && q[j] == '.' {
		j++
		for j < len(q) && (isDigit(q[j]) || q[j] == '_') {
			j++
		}
	}
	if j < len(q) && (q[j] == 'e' || q[j] == 'E') {
		k := j + 1
		if k < len(q) && (q[k] == '+' || q[k] == '-') {
			k++
		}
		if k < len(q) && isDigit(q[k]) {
			j = k
			for j < len(q) && isDigit(q[j]) {
				j++
			}
		}
	}
	return j
}

func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isLetter(c byte) bool    { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 }
func isHex(c byte) bool       { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func isIdentByte(c byte) bool { return isLetter(c) || isDigit(c) || c == '_' || c == '$' }

// clipUTF8 cuts s to at most n bytes without splitting a character.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// ---- messages ----

// valuePatterns are PostgreSQL messages that quote a value; the value
// group is replaced. Messages are matched in English only (lc_messages).
var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(invalid input syntax for (?:type )?[^:]*: ")(.*)(")`),
	regexp.MustCompile(`(invalid input value for enum [^:]*: ")(.*)(")`),
	regexp.MustCompile(`(value ")(.*)(" is out of range for type)`),
	regexp.MustCompile(`(field value out of range: ")(.*)(")`),
	regexp.MustCompile(`(malformed (?:array|record|range) literal: ")(.*)(")`),
	regexp.MustCompile(`((?:un)?terminated quoted (?:string|identifier) at or near ")(.*)(")`),
	regexp.MustCompile(`(Token ")(.*)(" is invalid)`),
	regexp.MustCompile(`(Failing row contains \()(.*)(\)\.?)`),
	regexp.MustCompile(`(=\()(.*)(\) (?:already exists|is not present in table|is still referenced from table|conflicts with existing key|is duplicated))`),
	regexp.MustCompile(`(COPY [^,]+, line \d+, column [^:]+: ")(.*)(")`),
	regexp.MustCompile(`(COPY [^,]+, line \d+: ")(.*)(")`),
	regexp.MustCompile(`(invalid byte sequence for encoding "[^"]+": )(.*)()`),
	regexp.MustCompile(`(character with byte sequence )(.*?)( in encoding)`),
	regexp.MustCompile(`(unrecognized (?:value|key word)[^"]*")(.*?)(")`),
	// A value quoted at the end: invalid value for parameter "x": "...".
	regexp.MustCompile(`(: ")(.*)("\s*)$`),
}

// syntaxNearRE: "syntax error at or near "x"" names a token; a string or
// number token is a value.
var syntaxNearRE = regexp.MustCompile(`(at or near ")(['0-9$E].*?|[^"]*'[^"]*)(")`)

// singleQuotedRE matches a single-quoted string in a message.
var singleQuotedRE = regexp.MustCompile(`'(?:[^']|'')*'`)

// doubleQuotedRE and numberRE: everything quoted, and numbers, in
// messages raised by the database's own functions.
var (
	doubleQuotedRE = regexp.MustCompile(`"(?:[^"]|"")*"`)
	numberRE       = regexp.MustCompile(`\b\d[\d.,_]*\b`)
)

// statementPrefixes introduce a statement inside a LOG message
// (log_statement, log_min_duration_statement, auto_explain-like lines).
var statementPrefixRE = regexp.MustCompile(`^((?:duration: [0-9.]+ ms\s+)?(?:statement|(?:execute|bind|parse) [^:]*|fastpath function call|query): )`)

// RedactMessage removes the values PostgreSQL quotes in a message or
// DETAIL. sqlstate is the entry's SQLSTATE ("" when unknown).
func RedactMessage(msg, sqlstate string) (string, bool) {
	if msg == "" {
		return msg, false
	}
	if m := statementPrefixRE.FindStringSubmatch(msg); m != nil {
		rest := msg[len(m[1]):]
		norm := NormalizeSQL(rest)
		return m[1] + norm, norm != rest
	}
	if MayContainPassword(msg) {
		return PasswordPlaceholder, true
	}
	orig := msg
	if strings.HasPrefix(sqlstate, "P0") {
		// RAISE in the database's own functions: keep only the words.
		msg = singleQuotedRE.ReplaceAllString(msg, "'"+Hidden+"'")
		msg = doubleQuotedRE.ReplaceAllString(msg, `"`+Hidden+`"`)
		msg = numberRE.ReplaceAllString(msg, Hidden)
		return msg, msg != orig
	}
	for _, re := range valuePatterns {
		msg = re.ReplaceAllString(msg, "${1}"+Hidden+"${3}")
	}
	msg = syntaxNearRE.ReplaceAllString(msg, "${1}"+Hidden+"${3}")
	msg = singleQuotedRE.ReplaceAllString(msg, "'"+Hidden+"'")
	return msg, msg != orig
}

// processLineRE is a deadlock DETAIL line naming a process's statement.
var processLineRE = regexp.MustCompile(`^(Process \d+: )(.*)$`)

// parametersRE is the DETAIL of an extended-protocol statement's bind
// parameters (log_parameter_max_length).
var parametersRE = regexp.MustCompile(`^(?:Parameters|parameters): `)

// sqlContextRE is a CONTEXT line quoting SQL: SQL statement "...",
// PL/pgSQL assignment "...", SQL function "f" statement 1 is kept.
var sqlContextRE = regexp.MustCompile(`^((?:SQL statement|PL/pgSQL assignment|SQL expression) ")(.*)(")(.*)$`)

// RedactDetail redacts a DETAIL: deadlock reports keep their structure
// with normalized statements, bind parameters are dropped.
func RedactDetail(detail, sqlstate string) (string, bool) {
	if detail == "" {
		return detail, false
	}
	if parametersRE.MatchString(detail) {
		return "parameters: " + Hidden, true
	}
	lines := strings.Split(detail, "\n")
	changed := false
	for i, l := range lines {
		if m := processLineRE.FindStringSubmatch(l); m != nil {
			n := NormalizeSQL(m[2])
			changed = changed || n != m[2]
			lines[i] = m[1] + n
			continue
		}
		r, ch := RedactMessage(l, sqlstate)
		lines[i] = r
		changed = changed || ch
	}
	return strings.Join(lines, "\n"), changed
}

// RedactContext redacts a CONTEXT: quoted SQL is normalized, other lines
// are redacted like messages.
func RedactContext(ctx, sqlstate string) (string, bool) {
	if ctx == "" {
		return ctx, false
	}
	lines := strings.Split(ctx, "\n")
	changed := false
	for i, l := range lines {
		if m := sqlContextRE.FindStringSubmatch(l); m != nil {
			n := NormalizeSQL(m[2])
			changed = changed || n != m[2]
			lines[i] = m[1] + n + m[3] + m[4]
			continue
		}
		r, ch := RedactMessage(l, sqlstate)
		lines[i] = r
		changed = changed || ch
	}
	return strings.Join(lines, "\n"), changed
}

// Redact removes literal values from an entry (fullText false), or only
// passwords (fullText true). It reports whether anything changed.
func Redact(e *Entry, fullText bool) {
	if fullText {
		for _, f := range []*string{&e.Message, &e.Detail, &e.Hint, &e.Context, &e.Statement, &e.Query} {
			if MayContainPassword(*f) {
				*f = PasswordPlaceholder
				e.Redacted = true
			}
		}
		return
	}
	var ch [6]bool
	e.Message, ch[0] = RedactMessage(e.Message, e.SQLState)
	e.Detail, ch[1] = RedactDetail(e.Detail, e.SQLState)
	e.Hint, ch[2] = RedactMessage(e.Hint, e.SQLState)
	e.Context, ch[3] = RedactContext(e.Context, e.SQLState)
	if e.Statement != "" {
		n := NormalizeSQL(e.Statement)
		ch[4] = n != e.Statement
		e.Statement = n
	}
	if e.Query != "" {
		n := NormalizeSQL(e.Query)
		ch[5] = n != e.Query
		e.Query = n
	}
	for _, c := range ch {
		e.Redacted = e.Redacted || c
	}
}
