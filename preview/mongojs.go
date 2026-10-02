package preview

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MongoDB previews run a migration written as plain mongosh calls,
// db.orders.updateMany({...}, {...}) or db.getCollection("x").drop(),
// with literal arguments. The agent runs each call itself with the
// driver: a mongosh script is JavaScript that could do anything on the
// server (require("child_process")), so Rowsafe never hands one to
// mongosh. Loops, variables and functions aren't supported; the preview
// says so.

// MongoCall is one call of a MongoDB migration.
type MongoCall struct {
	Line int
	Text string
	// DB is set by use NAME or db.getSiblingDB("NAME"); "" is the
	// migration's database.
	DB string
	// Collection is "" for database methods (createCollection,
	// dropDatabase, runCommand).
	Collection string
	Method     string
	// Args are the arguments as relaxed Extended JSON.
	Args []string
	// Use: a "use NAME" line (DB is NAME; nothing runs).
	Use bool
}

// Name is how reports show the call: db.orders.updateMany.
func (c MongoCall) Name() string {
	if c.Use {
		return "use"
	}
	if c.Collection == "" {
		return "db." + c.Method
	}
	return "db." + c.Collection + "." + c.Method
}

// ErrUnsupportedScript explains what MongoDB previews accept.
var ErrUnsupportedScript = errors.New("Rowsafe previews MongoDB migrations written as plain mongosh calls with literal arguments " +
	"(db.orders.updateMany({status: \"old\"}, {$set: {archived: true}}), db.users.createIndex({email: 1}), db.logs.drop(), ...); " +
	"variables, loops, functions and require() aren't run")

var (
	useLineRE  = regexp.MustCompile(`^use\s+([A-Za-z0-9_-]+)\s*;?$`)
	callHeadRE = regexp.MustCompile(`^db(?:\.getSiblingDB\(\s*(?:"([^"]+)"|'([^']+)')\s*\))?(?:\.getCollection\(\s*(?:"([^"]+)"|'([^']+)')\s*\)|\.([A-Za-z_$][\w$]*))?\.([A-Za-z_]\w*)\(`)
	identRE    = regexp.MustCompile(`^[A-Za-z_$][\w$]*`)
	numberRE   = regexp.MustCompile(`^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?`)
)

// ParseMongoScript splits a mongosh script into calls.
func ParseMongoScript(script string) ([]MongoCall, error) {
	code := stripJSComments(script)
	var out []MongoCall
	line := 1
	i := 0
	for i < len(code) {
		c := code[i]
		switch {
		case c == '\n':
			line++
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == ';':
			i++
			continue
		}
		end := strings.IndexByte(code[i:], '\n')
		if end < 0 {
			end = len(code) - i
		}
		if m := useLineRE.FindStringSubmatch(strings.TrimSpace(code[i : i+end])); m != nil {
			out = append(out, MongoCall{Line: line, Text: strings.TrimSpace(code[i : i+end]), DB: m[1], Use: true})
			i += end
			continue
		}
		m := callHeadRE.FindStringSubmatchIndex(code[i:])
		if m == nil || m[0] != 0 {
			return nil, fmt.Errorf("line %d: %w", line, ErrUnsupportedScript)
		}
		sub := func(k int) string {
			if m[2*k] < 0 {
				return ""
			}
			return code[i+m[2*k] : i+m[2*k+1]]
		}
		call := MongoCall{Line: line, DB: sub(1) + sub(2), Collection: sub(3) + sub(4) + sub(5), Method: sub(6)}
		// The arguments run to the matching parenthesis.
		args, n, err := splitArgs(code[i+m[1]:])
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		stop := i + m[1] + n
		// Nothing may follow but ; or the end of the line.
		rest := strings.TrimLeft(code[stop:], " \t\r")
		if rest != "" && rest[0] != ';' && rest[0] != '\n' {
			return nil, fmt.Errorf("line %d: %w", line, ErrUnsupportedScript)
		}
		call.Text = strings.TrimSpace(code[i:stop])
		for _, a := range args {
			j, err := JSToExtJSON(a)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", line, err)
			}
			call.Args = append(call.Args, j)
		}
		out = append(out, call)
		line += strings.Count(code[i:stop], "\n")
		i = stop
	}
	if len(out) == 0 {
		return nil, errors.New("the script has no calls")
	}
	return out, nil
}

// splitArgs reads s up to the parenthesis closing the call and returns the
// top-level arguments and the bytes read (the closing one included).
func splitArgs(s string) ([]string, int, error) {
	depth := 0
	var quote byte
	start := 0
	var args []string
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '{', '[':
			depth++
		case '}', ']':
			depth--
		case ')':
			if depth == 0 {
				if a := strings.TrimSpace(s[start:i]); a != "" || len(args) > 0 {
					args = append(args, a)
				}
				return args, i + 1, nil
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return nil, 0, errors.New("a call isn't closed")
}

// JSToExtJSON turns a JavaScript literal (unquoted keys, single quotes,
// ObjectId("..."), ISODate("..."), NumberLong(1), /regex/i, trailing
// commas) into relaxed Extended JSON. Anything that isn't a literal is an
// error.
func JSToExtJSON(js string) (string, error) {
	var b strings.Builder
	s := strings.TrimSpace(js)
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '{' || c == '}' || c == '[' || c == ']' || c == ':':
			b.WriteByte(c)
			i++
		case c == ',':
			// Drop trailing commas.
			j := i + 1
			for j < len(s) && strings.ContainsRune(" \t\r\n", rune(s[j])) {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				i = j
				continue
			}
			b.WriteByte(',')
			i++
		case c == '"' || c == '\'':
			str, n, err := readJSString(s[i:])
			if err != nil {
				return "", err
			}
			b.WriteString(strconv.Quote(str))
			i += n
		case c == '/' && i+1 < len(s):
			end := strings.IndexByte(s[i+1:], '/')
			if end < 0 {
				return "", errors.New("a regular expression isn't closed")
			}
			pat := s[i+1 : i+1+end]
			i += end + 2
			flags := identRE.FindString(s[i:])
			i += len(flags)
			fmt.Fprintf(&b, `{"$regularExpression":{"pattern":%s,"options":%s}}`, strconv.Quote(pat), strconv.Quote(flags))
		case c == '-' || c == '.' || (c >= '0' && c <= '9'):
			n := numberRE.FindString(s[i:])
			if n == "" {
				return "", fmt.Errorf("can't read %q", firstWord(s[i:]))
			}
			b.WriteString(n)
			i += len(n)
		default:
			id := identRE.FindString(s[i:])
			if id == "" {
				return "", fmt.Errorf("can't read %q", firstWord(s[i:]))
			}
			rest := strings.TrimLeft(s[i+len(id):], " \t\r\n")
			switch {
			case strings.HasPrefix(rest, ":"):
				b.WriteString(strconv.Quote(id)) // a key
				i += len(id)
			case id == "true" || id == "false" || id == "null":
				b.WriteString(id)
				i += len(id)
			case id == "new":
				i += len(id) // new Date(...)
			default:
				out, n, err := jsConstructor(id, s[i+len(id):])
				if err != nil {
					return "", err
				}
				b.WriteString(out)
				i += len(id) + n
			}
		}
	}
	return b.String(), nil
}

func readJSString(s string) (string, int, error) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
		case c == q:
			return b.String(), i + 1, nil
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, errors.New("a string isn't closed")
}

// jsConstructor reads ObjectId("..."), ISODate("..."), Date("..."),
// NumberLong(n), NumberInt(n), NumberDecimal("n"), UUID("...").
func jsConstructor(name, rest string) (string, int, error) {
	lead := len(rest) - len(strings.TrimLeft(rest, " \t"))
	rest = rest[lead:]
	if !strings.HasPrefix(rest, "(") {
		return "", 0, fmt.Errorf("%s isn't a literal value (%s)", name, ErrUnsupportedScript)
	}
	args, n, err := splitArgs(rest[1:])
	if err != nil {
		return "", 0, err
	}
	n += lead + 1
	arg := ""
	if len(args) > 0 {
		arg = strings.TrimSpace(args[0])
		if arg != "" && (arg[0] == '"' || arg[0] == '\'') {
			if arg, _, err = readJSString(arg); err != nil {
				return "", 0, err
			}
		}
	}
	switch name {
	case "ObjectId":
		return fmt.Sprintf(`{"$oid":%s}`, strconv.Quote(arg)), n, nil
	case "ISODate", "Date":
		if arg == "" {
			return "", 0, errors.New("a date needs a value: ISODate(\"2026-01-01T00:00:00Z\")")
		}
		return fmt.Sprintf(`{"$date":%s}`, strconv.Quote(arg)), n, nil
	case "NumberLong":
		return fmt.Sprintf(`{"$numberLong":%s}`, strconv.Quote(arg)), n, nil
	case "NumberInt":
		return fmt.Sprintf(`{"$numberInt":%s}`, strconv.Quote(arg)), n, nil
	case "NumberDecimal", "Decimal128":
		return fmt.Sprintf(`{"$numberDecimal":%s}`, strconv.Quote(arg)), n, nil
	case "UUID":
		return fmt.Sprintf(`{"$uuid":%s}`, strconv.Quote(arg)), n, nil
	}
	return "", 0, fmt.Errorf("%s(...) isn't a literal value (%s)", name, ErrUnsupportedScript)
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return Shorten(f[0], 30)
	}
	return s
}
