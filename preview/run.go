package preview

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Helpers the engines share when they run a preview on a copy.

var quotedValueRE = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)

// RedactValues replaces quoted text in a database error message that isn't
// in the migration itself (so it may be a value from the data, such as a
// duplicate key) with "(a value from your data)". Names and literals the
// migration wrote stay.
func RedactValues(msg, sql string) string {
	lower := strings.ToLower(sql)
	return quotedValueRE.ReplaceAllStringFunc(msg, func(q string) string {
		inner := q[1 : len(q)-1]
		if inner == "" || strings.Contains(lower, strings.ToLower(inner)) {
			return q
		}
		// A schema-qualified name (db.table, table.index) whose parts are
		// in the migration is a name too.
		if parts := strings.Split(inner, "."); len(parts) > 1 && !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(lower, strings.ToLower(p)) }) {
			return q
		}
		return q[:1] + "(a value from your data)" + q[:1]
	})
}

// PickDB chooses the database a migration runs in: want when given, else
// the one named like the Rowsafe database, else the only user database.
func PickDB(want, rowsafeName string, dbs []string) (string, error) {
	if want != "" {
		if slices.Contains(dbs, want) {
			return want, nil
		}
		return "", fmt.Errorf("there is no database %q (databases: %s)", want, strings.Join(dbs, ", "))
	}
	if slices.Contains(dbs, rowsafeName) {
		return rowsafeName, nil
	}
	switch len(dbs) {
	case 0:
		return "", fmt.Errorf("the copy has no database to run the migration in")
	case 1:
		return dbs[0], nil
	}
	return "", fmt.Errorf("say which database the migration is for: %s", strings.Join(dbs, ", "))
}
