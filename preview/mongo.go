package preview

import (
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB migrations are mongosh scripts (JavaScript): they run whole on
// the copy, and these rules recognise the calls that drop or rewrite data.

type mongoRule struct {
	id, severity, title, suggestion string
	re                              *regexp.Regexp
}

var mongoRules = []mongoRule{
	{id: "drop_database", severity: protocol.PreviewDangerous, re: regexp.MustCompile(`\.dropDatabase\s*\(`),
		title:      "dropDatabase() deletes the whole database",
		suggestion: "Make sure this is meant, and save a Mark right before (rowsafe mark) so Rewind can bring it back."},
	{id: "drop_collection", severity: protocol.PreviewDangerous, re: regexp.MustCompile(`\.drop\s*\(\s*\)|runCommand\s*\(\s*\{\s*['"]?drop['"]?\s*:`),
		title:      "drop() deletes a collection and its documents",
		suggestion: "Deploy code that no longer uses the collection first, and save a Mark right before so Rewind can bring it back."},
	{id: "delete_all", severity: protocol.PreviewDangerous, re: regexp.MustCompile(`\.(deleteMany|remove)\s*\(\s*(\{\s*\})?\s*[,)]`),
		title:      "deleteMany({}) deletes every document of the collection",
		suggestion: "Make sure this is meant for every document; to empty a collection, drop and recreate it, and save a Mark first."},
	{id: "update_all", severity: protocol.PreviewCareful, re: regexp.MustCompile(`\.(updateMany|update)\s*\(\s*\{\s*\}\s*,`),
		title:      "updateMany({}, ...) changes every document",
		suggestion: "Make sure this is meant for every document, and change large collections in batches."},
	{id: "drop_index", severity: protocol.PreviewCareful, re: regexp.MustCompile(`\.dropIndex(es)?\s*\(`),
		title:      "Dropping an index can make queries that used it slow",
		suggestion: "Check the index is unused first (Pulse lists unused indexes), or hide it with hideIndex() before dropping it."},
	{id: "rename_collection", severity: protocol.PreviewCareful, re: regexp.MustCompile(`\.renameCollection\s*\(`),
		title:      "Renaming a collection breaks the code that still uses the old name",
		suggestion: "Rename in steps: deploy code that reads both names, rename, then remove the old name from the code."},
	{id: "unset_field", severity: protocol.PreviewCareful, re: regexp.MustCompile(`\$unset\s*:`),
		title:      "$unset deletes the field's values for good",
		suggestion: "Deploy code that no longer reads the field first, and save a Mark right before."},
	{id: "validator", severity: protocol.PreviewCareful, re: regexp.MustCompile(`validationLevel\s*:\s*['"]strict['"]|\$jsonSchema`),
		title:      "A new validator rejects writes that don't match it",
		suggestion: "Start with validationAction: \"warn\" and check the log before switching to \"error\"."},
}

// MongoFindings lists the risky calls in a mongosh script.
func MongoFindings(script string) []protocol.PreviewFinding {
	code := stripJSComments(script)
	var out []protocol.PreviewFinding
	for _, r := range mongoRules {
		if r.re.MatchString(code) {
			out = append(out, protocol.PreviewFinding{Rule: r.id, Severity: r.severity, Statement: 1, Title: r.title, Suggestion: r.suggestion})
		}
	}
	return out
}

// stripJSComments removes // and /* */ comments outside strings.
func stripJSComments(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
			b.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += 2 + end + 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
