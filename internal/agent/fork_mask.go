package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a fork happens inside it, on its server, while it only listens on
// a private socket: nobody can connect before the personal data is
// replaced. Each masked column is rewritten with one UPDATE per table
// (PostgreSQL computes the fake values), the table is then rewritten
// (VACUUM FULL, so the old values don't stay in its files), statistics are
// rebuilt and materialized views refreshed (they hold their own copy).
//
// Values are replaced deterministically under a random key made for this
// fork and thrown away afterwards: the same email becomes the same fake
// email in every table (joins keep working), and nobody can map them back.
//
// This is the fork's masking engine; the strategies and rules are those of
// Guard's safe copies (feat/copies), so a database's saved masking rules
// apply to its forks too.

// Masking strategies (ForkMaskRule.Strategy).
const (
	maskKeep      = "keep"
	maskNull      = "null"
	maskEmail     = "email"
	maskFirstName = "first_name"
	maskLastName  = "last_name"
	maskFullName  = "full_name"
	maskAddress   = "address"
	maskCity      = "city"
	maskFormat    = "format"
	maskIP        = "ip"
	maskPassword  = "password"
	maskLorem     = "lorem"
	maskNoise     = "noise"
	maskDateShift = "date_shift"
	maskJSON      = "json"
)

// maskCopyPasswordHash is bcrypt("rowsafe-copy") at cost 10: every bcrypt
// password hash becomes it, so people can sign in to their app on the fork.
const maskCopyPasswordHash = "$2a$10$ZQzBfrwZ1yImcA9o8meBnuNjAS3OaRMHmqV5Jx3Yqx6IMMSrKniR6"

var maskFirstNames = []string{"Olivia", "Liam", "Emma", "Noah", "Ava", "Elijah", "Sophia", "Lucas", "Mia", "Mateo", "Amelia", "Leo",
	"Harper", "Ethan", "Nora", "Hugo", "Ines", "Omar", "Yara", "Kenji", "Lena", "Arjun", "Sara", "Theo"}
var maskLastNames = []string{"Martin", "Garcia", "Silva", "Novak", "Kowalski", "Nguyen", "Okafor", "Haddad", "Larsen", "Rossi",
	"Dubois", "Tanaka", "Moreau", "Schmidt", "Costa", "Walker", "Patel", "Ibrahim", "Jensen", "Morales"}
var maskStreets = []string{"Maple Avenue", "Oak Street", "Harbor Road", "Mill Lane", "Station Road", "Cedar Drive", "River Walk",
	"Park Lane", "Hill Street", "Garden Row"}
var maskCities = []string{"Riverton", "Lakewood", "Fairview", "Brookside", "Westfield", "Ashford", "Kingsbridge", "Northgate",
	"Clearwater", "Stonehaven"}

// maskClass is what a column's type allows.
func maskClass(typ string) string {
	t := strings.ToLower(typ)
	switch {
	case strings.HasSuffix(t, "[]"):
		return "other"
	case t == "text" || strings.HasPrefix(t, "character") || strings.HasPrefix(t, "varchar") || t == "citext" || t == "name":
		return "text"
	case t == "inet" || t == "cidr":
		return "inet"
	case t == "json" || t == "jsonb":
		return "json"
	case t == "date" || strings.HasPrefix(t, "timestamp"):
		return "date"
	case t == "smallint" || t == "integer" || t == "bigint":
		return "int"
	case strings.HasPrefix(t, "numeric") || t == "real" || t == "double precision":
		return "number"
	}
	return "other"
}

// maskFits reports whether a strategy can mask a column of class.
func maskFits(strategy, class string) bool {
	switch strategy {
	case maskKeep, maskNull:
		return true
	case maskEmail, maskFirstName, maskLastName, maskFullName, maskAddress, maskCity, maskFormat, maskPassword, maskLorem:
		return class == "text"
	case maskIP:
		return class == "text" || class == "inet"
	case maskNoise:
		return class == "int" || class == "number"
	case maskDateShift:
		return class == "date"
	case maskJSON:
		return class == "json"
	}
	return false
}

// maskWords splits a column or table name into lowercase words.
func maskWords(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	prevLower := false
	for _, r := range s {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.':
			flush()
			prevLower = false
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			cur.WriteRune(r + ('a' - 'A'))
			prevLower = false
		default:
			cur.WriteRune(r)
			prevLower = r >= 'a' && r <= 'z'
		}
	}
	flush()
	return out
}

// maskPersonTable: tables whose "name" columns are people's names.
func maskPersonTable(table string) bool {
	_, name, _ := strings.Cut(table, ".")
	if name == "" {
		name = table
	}
	for _, w := range maskWords(name) {
		switch strings.TrimSuffix(w, "s") {
		case "user", "customer", "person", "people", "contact", "member", "account", "employee", "patient", "client",
			"profile", "subscriber", "author", "owner", "guest", "student", "applicant", "candidate", "lead", "buyer", "seller":
			return true
		}
	}
	return false
}

// maskSuggest picks a strategy for a column that looks personal, or "".
func maskSuggest(table, column, typ string) string {
	class := maskClass(typ)
	w := maskWords(column)
	has := func(words ...string) bool {
		for _, x := range w {
			if slices.Contains(words, x) {
				return true
			}
		}
		return false
	}
	joined := strings.Join(w, "_")
	switch {
	case class == "inet":
		return maskIP
	case class == "text" && (has("email", "mail") || joined == "e_mail"):
		return maskEmail
	case class == "text" && (has("password", "passwd", "pwd") || joined == "encrypted_password" || joined == "password_hash"):
		return maskPassword
	case class == "text" && (joined == "first_name" || joined == "firstname" || joined == "given_name" || joined == "forename"):
		return maskFirstName
	case class == "text" && (joined == "last_name" || joined == "lastname" || joined == "surname" || joined == "family_name"):
		return maskLastName
	case class == "text" && (joined == "full_name" || joined == "fullname" || joined == "display_name" || joined == "contact_name" ||
		joined == "customer_name" || joined == "billing_name" || joined == "shipping_name" || (joined == "name" && maskPersonTable(table))):
		return maskFullName
	case class == "text" && has("phone", "mobile", "tel", "telephone", "fax", "msisdn"):
		return maskFormat
	case class == "text" && (has("ssn", "iban", "passport", "tin", "nin", "vat") || joined == "tax_id" || joined == "national_id" ||
		joined == "card_number" || joined == "credit_card" || joined == "account_number" || joined == "social_security_number"):
		return maskFormat
	case class == "text" && (has("address", "street", "addr") || joined == "address_line1" || joined == "address_line2"):
		if has("ip") {
			return maskIP
		}
		return maskAddress
	case class == "text" && has("city", "town"):
		return maskCity
	case class == "text" && (has("ip") || joined == "remote_addr" || joined == "last_sign_in_ip" || joined == "current_sign_in_ip"):
		return maskIP
	case class == "text" && (has("token", "secret") || joined == "api_key" || joined == "otp_secret" || joined == "reset_password_token"):
		return maskFormat
	case class == "date" && (has("birth", "dob", "birthday", "birthdate")):
		return maskDateShift
	case class == "json" && (has("address", "contact", "profile", "personal", "pii")):
		return maskNull
	}
	return ""
}

// maskHash is SQL for a stable 0..2^31 number from the key and a value.
func maskHash(val string) string {
	return fmt.Sprintf("(('x' || substr(md5($1::text || (%s)::text), 1, 8))::bit(32)::bigint)", val)
}

func sqlArray(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = "'" + strings.ReplaceAll(w, "'", "''") + "'"
	}
	return "ARRAY[" + strings.Join(q, ",") + "]"
}

func maskPick(words []string, col string, salt string) string {
	return fmt.Sprintf("(%s)[1 + %s %% %d]", sqlArray(words), maskHash(col+" || '"+salt+"'"), len(words))
}

// maskExpr is the SQL expression that masks column col (quoted) with a
// strategy. $1 is the fork's masking key. NULL stays NULL. A column with a
// unique index gets fake names and addresses made unique.
func maskExpr(strategy, col, typ string, nullable, unique bool) (string, bool) {
	class := maskClass(typ)
	if !maskFits(strategy, class) {
		return "", false
	}
	cast := ""
	if class == "text" {
		cast = "::" + typ
	}
	var e string
	switch strategy {
	case maskKeep:
		return col, true
	case maskNull:
		if !nullable {
			return "", false
		}
		return "NULL", true
	case maskEmail:
		e = fmt.Sprintf("('user.' || substr(md5($1::text || %s::text), 1, 16) || '@example.com')", col)
	case maskFirstName:
		e = maskPick(maskFirstNames, col, "f")
	case maskLastName:
		e = maskPick(maskLastNames, col, "l")
	case maskFullName:
		e = maskPick(maskFirstNames, col, "f") + " || ' ' || " + maskPick(maskLastNames, col, "l")
	case maskAddress:
		e = fmt.Sprintf("((1 + %s %% 9000)::text || ' ' || %s)", maskHash(col+" || 'n'"), maskPick(maskStreets, col, "s"))
	case maskCity:
		e = maskPick(maskCities, col, "c")
	case maskFormat:
		// Digits stay digits, letters stay letters (same case), the rest
		// stays: phone numbers, IDs and tokens keep their shape.
		e = fmt.Sprintf(`(SELECT string_agg(CASE
			WHEN ch ~ '[0-9]' THEN (('x' || substr(md5($1::text || %[1]s::text || i::text), 1, 8))::bit(32)::bigint %% 10)::text
			WHEN ch ~ '[a-z]' THEN chr(97 + (('x' || substr(md5($1::text || %[1]s::text || i::text), 1, 8))::bit(32)::bigint %% 26)::int)
			WHEN ch ~ '[A-Z]' THEN chr(65 + (('x' || substr(md5($1::text || %[1]s::text || i::text), 1, 8))::bit(32)::bigint %% 26)::int)
			ELSE ch END, '' ORDER BY i)
			FROM unnest(string_to_array(%[1]s::text, NULL)) WITH ORDINALITY AS t(ch, i))`, col)
	case maskIP:
		ip := fmt.Sprintf("('10.' || (%[1]s %% 256)::text || '.' || ((%[1]s / 256) %% 256)::text || '.' || ((%[1]s / 65536) %% 254 + 1)::text)", maskHash(col))
		if class == "inet" {
			return fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE %s::inet END", col, ip), true
		}
		e = ip
	case maskPassword:
		e = fmt.Sprintf("CASE WHEN %[1]s::text ~ '^\\$2[abxy]?\\$' THEN '%[2]s' ELSE md5($1::text || %[1]s::text) END", col, maskCopyPasswordHash)
	case maskLorem:
		e = fmt.Sprintf("left(repeat('Lorem ipsum dolor sit amet, consectetur adipiscing elit. ', 1 + length(%[1]s::text) / 50), greatest(length(%[1]s::text), 1))", col)
	case maskNoise:
		f := fmt.Sprintf("(0.9 + (%s %% 21) / 100.0)", maskHash(col))
		if class == "int" {
			return fmt.Sprintf("CASE WHEN %[1]s IS NULL THEN NULL ELSE round(%[1]s * %[2]s)::%[3]s END", col, f, typ), true
		}
		return fmt.Sprintf("CASE WHEN %[1]s IS NULL THEN NULL ELSE (%[1]s * %[2]s)::%[3]s END", col, f, typ), true
	case maskDateShift:
		return fmt.Sprintf("CASE WHEN %[1]s IS NULL THEN NULL ELSE (%[1]s + ((%[2]s %% 61) - 30) * interval '1 day')::%[3]s END", col, maskHash(col), typ), true
	case maskJSON:
		// JSON is masked by the masking engine of Guard's safe copies; here
		// the value is removed when it may be.
		if !nullable {
			return "", false
		}
		return "NULL", true
	default:
		return "", false
	}
	if unique && slices.Contains([]string{maskFirstName, maskLastName, maskFullName, maskAddress, maskCity, maskLorem}, strategy) {
		e = fmt.Sprintf("(%s || ' ' || substr(md5($1::text || %s::text), 1, 8))", e, col)
	}
	return fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL ELSE left(%s, %s)%s END", col, e, maskMaxLen(typ, col), cast), true
}

// maskMaxLen keeps a fake value within a varchar(n) or char(n).
func maskMaxLen(typ, col string) string {
	t := strings.ToLower(typ)
	if i := strings.Index(t, "("); i >= 0 && strings.HasSuffix(t, ")") {
		return t[i+1 : len(t)-1]
	}
	return "greatest(length(" + col + "::text), 200)"
}

type maskCol struct {
	table, column, typ string
	nullable           bool
}

// maskFork masks every database of the fork (reached at t).
func (a *Agent) maskFork(ctx context.Context, t pginspect.Target, m protocol.ForkMasking, tl *taskLog) (protocol.ForkMaskReport, error) {
	report := protocol.ForkMaskReport{Strategies: map[string]int{}}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return report, err
	}
	key := hex.EncodeToString(keyBytes)
	defer clear(keyBytes)
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return report, err
	}
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname`)
	var dbs []string
	if err == nil {
		dbs, err = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	closeConn(ctx, conn)
	if err != nil {
		return report, err
	}
	rules := map[string]string{}
	for _, r := range m.Rules {
		rules[r.DB+"\x00"+r.Table+"\x00"+r.Column] = r.Strategy
	}
	used := map[string]bool{}
	tables := map[string]bool{}
	for _, dbname := range dbs {
		if err := a.maskForkDatabase(ctx, t, dbname, key, m, rules, used, tables, &report, tl); err != nil {
			return report, fmt.Errorf("database %s: %w", dbname, err)
		}
	}
	for _, r := range m.Rules {
		if !used[r.DB+"\x00"+r.Table+"\x00"+r.Column] {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: %s.%s (the column isn't in the fork)", r.DB, r.Table, r.Column))
		}
	}
	report.Tables = len(tables)
	sort.Strings(report.Masked)
	tl.Printf("%s", forkMaskSummary(report))
	return report, nil
}

func (a *Agent) maskForkDatabase(ctx context.Context, t pginspect.Target, dbname, key string, m protocol.ForkMasking, rules map[string]string,
	used, tables map[string]bool, report *protocol.ForkMaskReport, tl *taskLog) error {
	conn, err := t.Connect(ctx, dbname)
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	rows, err := conn.Query(ctx, `
		SELECT CASE WHEN c.relkind = 'p' THEN '' ELSE 'ONLY ' END || quote_ident(n.nspname) || '.' || quote_ident(c.relname),
		       n.nspname || '.' || c.relname, a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
		       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisunique AND a.attnum = ANY(i.indkey::int2[]))
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')
		ORDER BY 2, a.attnum`)
	if err != nil {
		return err
	}
	type tableCols struct {
		quoted string
		cols   []maskCol
		exprs  []string
	}
	byTable := map[string]*tableCols{}
	var order []string
	for rows.Next() {
		var quoted, table, column, typ string
		var nullable, unique bool
		if err := rows.Scan(&quoted, &table, &column, &typ, &nullable, &unique); err != nil {
			rows.Close()
			return err
		}
		k := dbname + "\x00" + table + "\x00" + column
		strategy, ruled := rules[k]
		if ruled {
			used[k] = true
		} else if m.Suggest {
			strategy = maskSuggest(table, column, typ)
		}
		if strategy == "" || strategy == maskKeep {
			continue
		}
		qcol := pgx.Identifier{column}.Sanitize()
		expr, ok := maskExpr(strategy, qcol, typ, nullable, unique)
		if !ok && strategy == maskNull {
			// A NOT NULL column can't be emptied: keep its shape instead.
			strategy = maskLorem
			expr, ok = maskExpr(strategy, qcol, typ, nullable, unique)
		}
		if !ok {
			if ruled {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%s: %s.%s (%s doesn't fit a %s column)", dbname, table, column, strategy, typ))
			}
			continue
		}
		tc := byTable[table]
		if tc == nil {
			tc = &tableCols{quoted: quoted}
			byTable[table] = tc
			order = append(order, table)
		}
		tc.cols = append(tc.cols, maskCol{table: table, column: column, typ: typ, nullable: nullable})
		tc.exprs = append(tc.exprs, qcol+" = "+expr)
		report.Strategies[strategy]++
		report.Masked = append(report.Masked, fmt.Sprintf("%s: %s.%s (%s)", dbname, table, column, strategy))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, table := range order {
		tc := byTable[table]
		tl.Printf("masking %s: %s", table, strings.Join(func() []string {
			var out []string
			for _, c := range tc.cols {
				out = append(out, c.column)
			}
			return out
		}(), ", "))
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		// User triggers (audit logs, webhooks) don't fire: nothing but the
		// masked values change.
		if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		tag, err := tx.Exec(ctx, "UPDATE "+tc.quoted+" SET "+strings.Join(tc.exprs, ", "), key)
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("masking %s: %w", table, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		report.Rows += tag.RowsAffected()
		report.Columns += len(tc.cols)
		tables[dbname+"\x00"+table] = true
		// Rewrite the table so the old values don't stay in its files.
		if _, err := conn.Exec(ctx, "VACUUM (FULL, ANALYZE) "+strings.TrimPrefix(tc.quoted, "ONLY ")); err != nil {
			return fmt.Errorf("rewriting %s: %w", table, err)
		}
	}
	if len(order) == 0 {
		return nil
	}
	// Materialized views keep their own copy of the data.
	mvs, err := conn.Query(ctx, `SELECT quote_ident(schemaname) || '.' || quote_ident(matviewname) FROM pg_matviews WHERE ispopulated`)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(mvs, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, mv := range names {
		if _, err := conn.Exec(ctx, "REFRESH MATERIALIZED VIEW "+mv); err != nil {
			tl.Printf("refreshing %s: %v", mv, err)
		}
	}
	// Query statistics can hold values typed into queries.
	_, _ = conn.Exec(ctx, `SELECT pg_stat_statements_reset() WHERE EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`)
	_, _ = conn.Exec(ctx, "CHECKPOINT")
	return nil
}

// forkMaskSummary is masking's result in plain words.
func forkMaskSummary(r protocol.ForkMaskReport) string {
	if r.Columns == 0 {
		s := "Masking found no personal data to mask."
		if len(r.Skipped) > 0 {
			s += fmt.Sprintf(" %s skipped.", countNoun(len(r.Skipped), "rule was", "rules were"))
		}
		return s
	}
	s := fmt.Sprintf("Masked %s in %s (%s rows).", countNoun(r.Columns, "column", "columns"), countNoun(r.Tables, "table", "tables"),
		formatCount(r.Rows))
	if len(r.Skipped) > 0 {
		s += fmt.Sprintf(" %s skipped.", countNoun(len(r.Skipped), "rule was", "rules were"))
	}
	return s
}

// formatCount prints 1204 as "1,204".
func formatCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
