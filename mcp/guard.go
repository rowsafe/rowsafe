package mcp

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// DestructiveDBCommand reports whether a shell command is likely to change a
// database destructively: schema migrations, resets and drops, SQL with
// DROP, TRUNCATE, ALTER ... DROP, or DELETE/UPDATE without WHERE sent to a
// SQL client (psql, mysql, mariadb, clickhouse-client, ...), or a MongoDB
// shell script that drops or empties collections. It returns a short
// reason. It is a heuristic tuned for few false positives: status, dry-run
// and help invocations, and commands that only mention a tool (echo, grep,
// git commit -m ...), don't match.
//
// readFile, if not nil, reads the SQL or script files passed to a client
// (psql -f, mysql < file, clickhouse-client --queries-file, mongosh
// script.js) so their contents can be checked too.
func DestructiveDBCommand(command string, readFile func(string) ([]byte, error)) (string, bool) {
	sawSQL, sawMongo := false, false
	var sqlFiles, mongoFiles []string
	for _, seg := range splitSegments(command) {
		words := commandWords(seg)
		if len(words) == 0 || harmlessCommand(words) {
			continue
		}
		if helpInvocation(words) {
			continue
		}
		if reason, ok := destructiveTool(words); ok {
			return reason, true
		}
		for i, w := range words {
			switch client := clientKind(words, i); client {
			case "sql", "mongo":
				files := clientFiles(base(w), words[i+1:])
				if client == "sql" {
					sawSQL = true
					sqlFiles = append(sqlFiles, files...)
				} else {
					sawMongo = true
					mongoFiles = append(mongoFiles, files...)
				}
			}
		}
	}
	check := func(saw bool, files []string, fn func(string) (string, bool)) (string, bool) {
		if !saw {
			return "", false
		}
		if reason, ok := fn(command); ok {
			return reason, true
		}
		if readFile != nil {
			for _, f := range files {
				if data, err := readFile(f); err == nil {
					if reason, ok := fn(string(data)); ok {
						return reason + " (in " + f + ")", true
					}
				}
			}
		}
		return "", false
	}
	if reason, ok := check(sawSQL, sqlFiles, destructiveSQL); ok {
		return reason, true
	}
	return check(sawMongo, mongoFiles, destructiveMongo)
}

// helpInvocation is true for --help, --version and --dry-run runs. -h
// counts only as the last word: psql, mysql and clickhouse-client take
// -h HOST.
func helpInvocation(words []string) bool {
	if hasAny(words, "--help", "help", "--dry-run", "--version") {
		return true
	}
	return words[len(words)-1] == "-h"
}

// clientKind says whether words[i] runs a database client: "sql" for
// psql, pgcli, mysql, mariadb, mycli and clickhouse-client (or
// clickhouse client), "mongo" for mongosh and mongo, "" otherwise.
func clientKind(words []string, i int) string {
	switch base(words[i]) {
	case "psql", "pgcli", "mysql", "mariadb", "mycli", "clickhouse-client", "clickhouse-local":
		return "sql"
	case "clickhouse":
		if i+1 < len(words) && (words[i+1] == "client" || words[i+1] == "local") {
			return "sql"
		}
	case "mongosh", "mongo":
		return "mongo"
	}
	return ""
}

// clientFiles lists the script files a client invocation reads: psql -f,
// clickhouse-client --queries-file, mongosh --file or positional .js
// files, and any client's stdin redirection (< file).
func clientFiles(tool string, args []string) []string {
	var files []string
	for j := 0; j < len(args); j++ {
		a := args[j]
		next := func() string {
			if j+1 < len(args) {
				return args[j+1]
			}
			return ""
		}
		switch {
		case a == "<" && next() != "":
			files = append(files, next())
		case strings.HasPrefix(a, "<") && !strings.HasPrefix(a, "<<") && len(a) > 1:
			files = append(files, a[1:])
		case (tool == "psql" || tool == "pgcli") && (a == "-f" || a == "--file") && next() != "":
			files = append(files, next())
		case (tool == "psql" || tool == "pgcli" || tool == "mongosh" || tool == "mongo") && strings.HasPrefix(a, "--file="):
			files = append(files, strings.TrimPrefix(a, "--file="))
		case (tool == "mongosh" || tool == "mongo") && (a == "-f" || a == "--file") && next() != "":
			files = append(files, next())
		case (tool == "mongosh" || tool == "mongo") && strings.HasSuffix(a, ".js") && !strings.HasPrefix(a, "-"):
			files = append(files, a)
		case strings.HasPrefix(tool, "clickhouse") && a == "--queries-file" && next() != "":
			files = append(files, next())
		case strings.HasPrefix(tool, "clickhouse") && strings.HasPrefix(a, "--queries-file="):
			files = append(files, strings.TrimPrefix(a, "--queries-file="))
		}
	}
	return files
}

// splitSegments splits a command line at ;, &&, ||, | and newlines, outside quotes.
func splitSegments(s string) []string {
	var segs []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			segs = append(segs, t)
		}
		cur.Reset()
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' && i+1 < len(rs) {
				cur.WriteRune(r)
				i++
				r = rs[i]
			}
			cur.WriteRune(r)
			continue
		case r == '\'' || r == '"':
			quote = r
			cur.WriteRune(r)
			continue
		case r == ';' || r == '\n' || r == '|' || r == '&':
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()
	return segs
}

// commandWords splits a segment into words, removing quotes, leading
// environment assignments and wrappers such as sudo, npx or bundle exec.
// Quoted command strings (bash -c "...", docker exec ... sh -c '...') are
// expanded in place.
func commandWords(seg string) []string {
	words := shellWords(seg)
	var out []string
	for _, w := range words {
		if strings.ContainsAny(w, " \t\n") {
			// A quoted script: its words count only if it is a command.
			if inner := commandWords(w); len(inner) > 0 && looksLikeCommandArg(out) {
				out = append(out, inner...)
				continue
			}
		}
		out = append(out, w)
	}
	// Drop leading env assignments and wrappers.
	for len(out) > 0 {
		w := out[0]
		switch {
		case envAssignRE.MatchString(w):
			out = out[1:]
		case slices.Contains([]string{"sudo", "env", "time", "nohup", "exec", "command", "npx", "bunx", "pnpx", "dotenv", "doppler", "op"}, base(w)):
			out = out[1:]
			// Skip the wrapper's own flags (sudo -u postgres, doppler run --, ...).
			for len(out) > 0 && (strings.HasPrefix(out[0], "-") || out[0] == "run") {
				if out[0] == "--" {
					out = out[1:]
					break
				}
				if slices.Contains([]string{"-u", "--user", "-p", "--project", "-c", "--config", "-e"}, out[0]) && len(out) > 1 {
					out = out[1:]
				}
				out = out[1:]
			}
		case slices.Contains([]string{"bundle", "pnpm", "yarn", "poetry", "pipenv", "uv", "pdm", "hatch"}, base(w)) && len(out) > 1 && (out[1] == "exec" || out[1] == "run" || out[1] == "dlx"):
			out = out[2:]
		default:
			return out
		}
	}
	return out
}

var envAssignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// looksLikeCommandArg reports whether a quoted argument following prev is a
// script to run (bash -c "...", kubectl exec ... -- "...").
func looksLikeCommandArg(prev []string) bool {
	if len(prev) == 0 {
		return true
	}
	last := prev[len(prev)-1]
	if last == "-c" || last == "--command" || last == "--" || last == "exec" || last == "run" {
		return true
	}
	// bash -lc "...", sh -ec '...': combined shell flags that include -c.
	return len(prev) >= 2 && shellFlagsRE.MatchString(last) &&
		slices.Contains([]string{"bash", "sh", "zsh", "dash", "ash", "ksh"}, base(prev[len(prev)-2]))
}

var shellFlagsRE = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

// shellWords splits on unquoted whitespace and removes quotes.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	in := false
	var quote rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' && i+1 < len(rs) {
				i++
				cur.WriteRune(rs[i])
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == '\\' && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
			in = true
		case r == ' ' || r == '\t':
			if in {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		words = append(words, cur.String())
	}
	return words
}

func base(w string) string { return filepath.Base(w) }

func hasAny(words []string, flags ...string) bool {
	for _, w := range words {
		if slices.Contains(flags, w) {
			return true
		}
	}
	return false
}

// harmlessCommand is true when the segment only prints, searches or records
// text that may mention a migration tool.
func harmlessCommand(words []string) bool {
	return slices.Contains([]string{"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "git", "gh", "cat", "less",
		"more", "head", "tail", "man", "which", "whereis", "type", "tldr", "sed", "awk", "jq", "yq", "ls", "tee", "wc", "sort",
		"diff", "code", "vim", "vi", "nano", "open"}, base(words[0]))
}

// after returns the first non-flag word after the word whose base is tool,
// and its index (-1 if there is none).
func after(words []string, tool string) (string, int) {
	for i, w := range words {
		if base(w) == tool || strings.TrimSuffix(base(w), ".js") == tool {
			for j := i + 1; j < len(words); j++ {
				if !strings.HasPrefix(words[j], "-") {
					return words[j], j
				}
			}
			return "", -1
		}
	}
	return "", -1
}

func destructiveTool(words []string) (string, bool) {
	sub := func(tool string) string { s, _ := after(words, tool); return s }
	sub2 := func(tool string) (string, string) {
		s, i := after(words, tool)
		if i < 0 {
			return "", ""
		}
		for j := i + 1; j < len(words); j++ {
			if !strings.HasPrefix(words[j], "-") {
				return s, words[j]
			}
		}
		return s, ""
	}
	in := func(s string, set ...string) bool { return slices.Contains(set, s) }

	// Prisma
	if a, b := sub2("prisma"); (a == "migrate" && in(b, "deploy", "reset", "dev")) || (a == "db" && in(b, "push", "execute")) {
		return "prisma " + a + " " + b, true
	}
	// Rails / Rake
	for _, tool := range []string{"rails", "rake"} {
		for _, w := range words[1:] {
			if rails := railsTask(w); rails != "" && slices.ContainsFunc(words, func(x string) bool { return base(x) == tool }) {
				return tool + " " + rails, true
			}
		}
	}
	// Alembic (upgrade --sql only prints SQL)
	if s := sub("alembic"); in(s, "upgrade", "downgrade") && !hasAny(words, "--sql") {
		return "alembic " + s, true
	}
	// Django
	for i, w := range words {
		if (base(w) == "manage.py" || base(w) == "django-admin") && i+1 < len(words) {
			if s := words[i+1]; in(s, "migrate", "flush", "reset_db") && !hasAny(words, "--plan", "--check", "--list", "-l") {
				return "django " + s, true
			}
		}
	}
	// Knex, Sequelize, TypeORM
	if s := sub("knex"); in(s, "migrate:latest", "migrate:up", "migrate:down", "migrate:rollback", "seed:run") {
		return "knex " + s, true
	}
	for _, tool := range []string{"sequelize", "sequelize-cli"} {
		if s := sub(tool); in(s, "db:migrate", "db:migrate:undo", "db:migrate:undo:all", "db:drop", "db:seed", "db:seed:all", "db:seed:undo", "db:seed:undo:all") {
			return "sequelize " + s, true
		}
	}
	for _, w := range words {
		if strings.HasPrefix(base(w), "typeorm") {
			if s := sub(base(w)); in(s, "migration:run", "migration:revert", "schema:sync", "schema:drop") {
				return "typeorm " + s, true
			}
		}
	}
	// Drizzle
	if s := sub("drizzle-kit"); in(s, "push", "migrate", "drop") {
		return "drizzle-kit " + s, true
	}
	// Go: goose, golang-migrate, dbmate, atlas
	if slices.ContainsFunc(words, func(w string) bool { return base(w) == "goose" }) {
		for _, w := range words {
			if in(w, "up", "up-by-one", "up-to", "down", "down-to", "redo", "reset") {
				return "goose " + w, true
			}
		}
	}
	if base(words[0]) == "migrate" {
		for _, w := range words[1:] {
			if in(w, "up", "down", "drop", "goto", "force") {
				return "migrate " + w, true
			}
		}
	}
	if s := sub("dbmate"); in(s, "up", "migrate", "rollback", "down", "drop") {
		return "dbmate " + s, true
	}
	if a, b := sub2("atlas"); (a == "schema" && b == "apply") || (a == "migrate" && in(b, "apply", "down")) || (a == "schema" && b == "clean") {
		return "atlas " + a + " " + b, true
	}
	// Rust: sqlx, diesel, refinery
	if a, b := sub2("sqlx"); (a == "migrate" && in(b, "run", "revert")) || (a == "database" && in(b, "drop", "reset")) {
		return "sqlx " + a + " " + b, true
	}
	if a, b := sub2("diesel"); (a == "migration" && in(b, "run", "revert", "redo")) || (a == "database" && b == "reset") {
		return "diesel " + a + " " + b, true
	}
	// JVM and others
	if s := sub("flyway"); in(s, "migrate", "clean", "undo", "baseline") {
		return "flyway " + s, true
	}
	if s := sub("liquibase"); in(s, "update", "update-count", "update-to-tag", "rollback", "rollback-count", "rollback-to-date", "drop-all", "dropAll", "updateCount", "rollbackCount") {
		return "liquibase " + s, true
	}
	if s := sub("mix"); in(s, "ecto.migrate", "ecto.rollback", "ecto.drop", "ecto.reset") {
		return "mix " + s, true
	}
	if a, _ := sub2("artisan"); (a == "migrate" || strings.HasPrefix(a, "migrate:") && a != "migrate:status" && a != "migrate:install") || a == "db:wipe" {
		return "artisan " + a, true
	}
	if a, b := sub2("supabase"); (a == "db" && in(b, "reset", "push")) || (a == "migration" && in(b, "up", "down")) {
		return "supabase " + a + " " + b, true
	}
	// PostgreSQL client tools
	if base(words[0]) == "dropdb" || base(words[0]) == "pg_dropcluster" {
		return base(words[0]), true
	}
	if slices.ContainsFunc(words, func(w string) bool { return base(w) == "pg_restore" }) {
		for _, w := range words {
			if w == "--clean" || (strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.ContainsRune(w, 'c')) {
				return "pg_restore --clean", true
			}
		}
	}
	// MySQL, MariaDB and MongoDB client tools
	for _, tool := range []string{"mysqladmin", "mariadb-admin"} {
		if slices.ContainsFunc(words, func(w string) bool { return base(w) == tool }) && hasAny(words, "drop") {
			return tool + " drop", true
		}
	}
	if slices.ContainsFunc(words, func(w string) bool { return base(w) == "mongorestore" }) && hasAny(words, "--drop") {
		return "mongorestore --drop", true
	}
	if slices.ContainsFunc(words, func(w string) bool { return base(w) == "myloader" }) && hasAny(words, "--overwrite-tables", "-o") {
		return "myloader --overwrite-tables", true
	}
	// Package-manager scripts named like migrations (npm run db:migrate, yarn migrate).
	for i, w := range words {
		if in(base(w), "npm", "pnpm", "yarn", "bun") && i+1 < len(words) {
			script := words[i+1]
			if script == "run" || script == "run-script" {
				if i+2 >= len(words) {
					break
				}
				script = words[i+2]
			}
			if migrationScript(script) {
				return base(w) + " run " + script, true
			}
		}
	}
	return "", false
}

var railsTaskRE = regexp.MustCompile(`^db:(migrate(:(up|down|redo|reset))?|rollback|drop(:all)?|reset|purge(:all)?|schema:load|structure:load|truncate_all|seed:replant|setup|prepare)$`)

func railsTask(w string) string {
	if railsTaskRE.MatchString(w) {
		return w
	}
	return ""
}

var migrationScriptRE = regexp.MustCompile(`^(db:)?(migrate|migrations?:(run|up|latest|deploy|down|rollback|revert|undo|reset|apply)|migrate:(up|latest|deploy|down|rollback|revert|undo|reset|fresh|refresh|apply|prod)|db:(push|reset|drop|wipe|migrate:(deploy|reset|down|undo)))$`)

func migrationScript(s string) bool { return migrationScriptRE.MatchString(s) }

var (
	dropRE     = regexp.MustCompile("(?i)\\bdrop\\s+(table|schema|database|index|view|materialized\\s+view|type|function|extension|owned|sequence|trigger|column|constraint|role|user|procedure|event|dictionary|partition|part)\\b")
	truncateRE = regexp.MustCompile("(?i)\\btruncate\\s+(table\\s+)?(only\\s+)?[\\w.\"`]+")
	// ALTER TABLE ... DROP/RENAME/type changes; MySQL MODIFY/CHANGE COLUMN;
	// ClickHouse mutations (ALTER TABLE ... DELETE/UPDATE) and partition drops.
	alterRE  = regexp.MustCompile("(?i)\\balter\\s+table\\s+[\\w.\"`]+\\s+[^;]*\\b(drop\\b|rename\\b|delete\\s+where\\b|update\\s+[\\w\"`]+\\s*=|modify\\s+column\\b|change\\s+column\\b|alter\\s+column\\s+[\\w\"`]+\\s+(set\\s+data\\s+)?type\\b)")
	deleteRE = regexp.MustCompile("(?i)\\bdelete\\s+from\\s+[\\w.\"`]+")
	updateRE = regexp.MustCompile("(?i)\\bupdate\\s+[\\w.\"`]+\\s+set\\b")
	whereRE  = regexp.MustCompile(`(?i)\bwhere\b`)
)

// destructiveSQL looks for statements that remove or rewrite data wholesale.
func destructiveSQL(sql string) (string, bool) {
	if m := dropRE.FindString(sql); m != "" {
		return "SQL " + strings.ToUpper(strings.Join(strings.Fields(m), " ")), true
	}
	if m := truncateRE.FindString(sql); m != "" {
		return "SQL TRUNCATE", true
	}
	if m := alterRE.FindString(sql); m != "" {
		return "SQL ALTER TABLE", true
	}
	if m := renameRE.FindString(sql); m != "" {
		return "SQL RENAME TABLE", true
	}
	for _, re := range []struct {
		re   *regexp.Regexp
		name string
	}{{deleteRE, "DELETE"}, {updateRE, "UPDATE"}} {
		for _, loc := range re.re.FindAllStringIndex(sql, -1) {
			rest := sql[loc[1]:]
			if end := strings.IndexAny(rest, ";'\"\n"); end >= 0 {
				rest = rest[:end]
			}
			if !whereRE.MatchString(rest) {
				return "SQL " + re.name + " without WHERE", true
			}
		}
	}
	return "", false
}

var renameRE = regexp.MustCompile(`(?i)\brename\s+(table|database)\b`)

var (
	// db.orders.drop(), db.dropDatabase(), db.getCollection("x").drop(),
	// dropIndex(es), renameCollection.
	mongoDropRE = regexp.MustCompile(`\.(drop|dropDatabase|dropIndex|dropIndexes|renameCollection)\s*\(`)
	// deleteMany({}), remove({}), updateMany({}, ...), replaceOne({}, ...)
	// with an empty filter.
	mongoEmptyFilterRE = regexp.MustCompile(`\.(deleteMany|remove|updateMany|update)\s*\(\s*(\{\s*\})?\s*[,)]`)
	mongoDropCmdRE     = regexp.MustCompile(`(?i)(runCommand|adminCommand)\s*\(\s*\{\s*['"]?(drop|dropDatabase|dropIndexes)['"]?\s*:`)
)

// destructiveMongo looks for MongoDB shell calls that drop or empty
// collections, or change every document.
func destructiveMongo(js string) (string, bool) {
	if m := mongoDropRE.FindStringSubmatch(js); m != nil {
		return "MongoDB " + m[1] + "()", true
	}
	if m := mongoDropCmdRE.FindStringSubmatch(js); m != nil {
		return "MongoDB " + m[2] + " command", true
	}
	if m := mongoEmptyFilterRE.FindStringSubmatch(js); m != nil {
		return "MongoDB " + m[1] + " on every document", true
	}
	return "", false
}
