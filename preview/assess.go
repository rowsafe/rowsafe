package preview

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Thresholds for the verdict. The copy runs at low priority with a small
// cache, so timings are an estimate of production's, not a promise.
const (
	carefulLockMs   = 1_000          // a write-blocking lock held this long is noticeable
	dangerousLockMs = 10_000         // requests start timing out
	dangerousBytes  = 1 << 30        // rewriting 1 GiB takes a while anywhere
	carefulRows     = 100_000        // rows changed in one statement
	dangerousRows   = 5_000_000      // rows changed in one statement
	bigTableBytes   = 10 * (1 << 20) // index builds on tables below this are quick
)

func rank(risk string) int {
	switch risk {
	case protocol.PreviewCareful:
		return 1
	case protocol.PreviewDangerous:
		return 2
	case protocol.PreviewFailed:
		return 3
	}
	return 0
}

func worse(a, b string) string {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Assess fills in each statement's Risk and Impact, the findings, the
// verdict and the summary from what the migration did on the copy. texts
// are the full statements, in the same order as res.Statements.
func Assess(res *protocol.PreviewResult, texts []string) {
	res.Findings = nil
	verdict := protocol.PreviewSafe
	lockTimeoutSet := false
	noTimeoutReported := false
	type impact struct {
		n    int
		risk string
		text string
	}
	var worst impact
	for i := range res.Statements {
		s := &res.Statements[i]
		text := ""
		if i < len(texts) {
			text = texts[i]
		}
		if SetsLockTimeout(text) {
			lockTimeoutSet = true
		}
		s.Risk, s.Impact = protocol.PreviewSafe, ""
		if !s.Ran {
			continue
		}
		if s.Error != "" {
			s.Risk = protocol.PreviewFailed
			verdict = protocol.PreviewFailed
			continue
		}
		add := func(severity, rule, title, detail, suggestion string) {
			s.Risk = worse(s.Risk, severity)
			res.Findings = append(res.Findings, protocol.PreviewFinding{Rule: rule, Severity: severity, Statement: s.N,
				Title: title, Detail: detail, Suggestion: suggestion})
		}
		var parts []string
		command := Command(text)

		// Tables rewritten, emptied or dropped.
		for _, r := range s.Rewrites {
			if r.SizeBytes <= 0 {
				continue
			}
			if command == "TRUNCATE" {
				parts = append(parts, fmt.Sprintf("empties %s (%s)", r.Name, humanBytes(r.SizeBytes)))
				add(protocol.PreviewDangerous, "truncate", fmt.Sprintf("TRUNCATE deletes every row of %s", r.Name),
					fmt.Sprintf("%s held %s%s.", r.Name, humanBytes(r.SizeBytes), rowsNote(r.Rows)),
					"Make sure this is meant, and save a Mark right before (rowsafe mark) so you can bring the rows back.")
				continue
			}
			parts = append(parts, fmt.Sprintf("rewrites %s (%s)", r.Name, humanBytes(r.SizeBytes)))
			sev := protocol.PreviewCareful
			if r.SizeBytes >= dangerousBytes || s.DurationMs >= dangerousLockMs {
				sev = protocol.PreviewDangerous
			}
			add(sev, "table_rewrite", fmt.Sprintf("%s rewrites %s (%s)", command, r.Name, humanBytes(r.SizeBytes)),
				fmt.Sprintf("The whole table is copied to new files%s, under a lock that blocks reads and writes.", rowsNote(r.Rows)),
				rewriteSuggestion(text))
		}
		for _, r := range s.Dropped {
			if r.SizeBytes <= 16384 && r.Rows <= 0 {
				continue // an empty table
			}
			parts = append(parts, fmt.Sprintf("drops %s (%s)", r.Name, humanBytes(r.SizeBytes)))
			add(protocol.PreviewDangerous, "drop_table", fmt.Sprintf("Drops %s and its data", r.Name),
				fmt.Sprintf("%s held %s%s; it is gone for good once this runs.", r.Name, humanBytes(r.SizeBytes), rowsNote(r.Rows)),
				"Deploy code that no longer uses it first, and save a Mark right before (rowsafe mark) so Rewind can bring it back.")
		}
		for _, ix := range s.IndexBuilds {
			rewritten := slices.ContainsFunc(s.Rewrites, func(r protocol.PreviewRelation) bool { return r.Name == ix.Table })
			if ix.Table != "" && ix.SizeBytes >= bigTableBytes && !rewritten {
				parts = append(parts, fmt.Sprintf("builds %s on %s (%s)", ix.Name, ix.Table, humanBytes(ix.SizeBytes)))
			}
		}

		// Locks that block production's queries.
		var block *protocol.PreviewLock
		for j := range s.Locks {
			l := &s.Locks[j]
			if l.Blocks != "reads and writes" && l.Blocks != "writes" {
				continue
			}
			if block == nil || l.HeldMs > block.HeldMs || (l.HeldMs == block.HeldMs && Stronger(l.Mode, block.Mode)) {
				block = l
			}
		}
		if block != nil {
			held := humanDuration(block.HeldMs)
			until := ""
			if res.Mode == protocol.PreviewInTransaction && block.HeldMs > s.DurationMs+500 {
				until = " (the lock lasts until the migration commits)"
			}
			parts = append([]string{fmt.Sprintf("blocks %s on %s for %s%s", block.Blocks, block.Relation, held, until)}, parts...)
			// A rewrite finding already explains the lock and how to avoid it.
			rewrite := slices.IndexFunc(res.Findings, func(f protocol.PreviewFinding) bool { return f.Statement == s.N && f.Rule == "table_rewrite" })
			switch {
			case rewrite >= 0:
				f := &res.Findings[rewrite]
				f.Detail += fmt.Sprintf(" On production, %s on %s wait for %s.", block.Blocks, block.Relation, held)
				if block.HeldMs >= dangerousLockMs {
					f.Severity = protocol.PreviewDangerous
					s.Risk = worse(s.Risk, protocol.PreviewDangerous)
				}
			case block.HeldMs >= dangerousLockMs:
				add(protocol.PreviewDangerous, "long_lock", fmt.Sprintf("%s is blocked for %s", block.Relation, held),
					fmt.Sprintf("While %s holds %s, production's %s on %s wait: requests pile up and time out.", command, block.Mode, block.Blocks, block.Relation),
					lockSuggestion(res.Mode, text))
			case block.HeldMs >= carefulLockMs:
				add(protocol.PreviewCareful, "lock", fmt.Sprintf("%s is blocked for %s", block.Relation, held),
					fmt.Sprintf("Production's %s on %s wait while %s runs.", block.Blocks, block.Relation, command), lockSuggestion(res.Mode, text))
			}
			if !lockTimeoutSet && !noTimeoutReported && block.Mode == "AccessExclusiveLock" {
				noTimeoutReported = true
				add(protocol.PreviewCareful, "no_lock_timeout", "No lock_timeout before taking an exclusive lock",
					fmt.Sprintf("On production, %s first waits for every running query on %s, and all new queries queue behind it, even if the change itself is instant.", command, block.Relation),
					"Start the migration with SET lock_timeout = '5s' (and retry if it times out), so a busy table can't stall your app.")
			}
		}

		// Rows changed.
		if s.Rows != nil && (command == "UPDATE" || command == "DELETE" || command == "INSERT") {
			switch n := *s.Rows; {
			case n >= dangerousRows:
				add(protocol.PreviewDangerous, "large_data_change", fmt.Sprintf("%s changes %s rows in one go", command, humanCount(n)),
					"Large changes hold row locks, bloat the table and delay replicas until they commit.",
					"Change the rows in batches of a few thousand, outside the schema migration.")
			case n >= carefulRows:
				add(protocol.PreviewCareful, "large_data_change", fmt.Sprintf("%s changes %s rows in one go", command, humanCount(n)),
					"Rows stay locked until the migration commits.", "Consider batches of a few thousand rows, outside the schema migration.")
			}
			if *s.Rows >= carefulRows {
				parts = append(parts, fmt.Sprintf("changes %s rows", humanCount(*s.Rows)))
			}
		}

		// Recognised from the statement's text.
		for _, r := range staticFindings(text, len(s.Locks) > 0) {
			if r.id == "create_index_blocks_writes" && biggestTable(s) < bigTableBytes && (block == nil || block.HeldMs < carefulLockMs) {
				continue // a small table: the build is over in a moment
			}
			if slices.ContainsFunc(res.Findings, func(f protocol.PreviewFinding) bool { return f.Statement == s.N && f.Rule == r.id }) {
				continue
			}
			add(r.severity, r.id, r.title, "", r.suggestion)
		}

		if len(parts) > 0 {
			s.Impact = upperFirst(strings.Join(parts, ", ")) + "."
			if s.Risk == protocol.PreviewSafe {
				// Worth saying, not worth worrying about.
				s.Impact = upperFirst(strings.Join(parts, ", ")) + "; quick enough to be safe."
			}
		}
		verdict = worse(verdict, s.Risk)
		if rank(s.Risk) > rank(worst.risk) && s.Impact != "" {
			worst = impact{n: s.N, risk: s.Risk, text: strings.TrimSuffix(s.Impact, ".")}
		}
	}
	slices.SortStableFunc(res.Findings, func(a, b protocol.PreviewFinding) int {
		if c := cmp.Compare(rank(b.Severity), rank(a.Severity)); c != 0 {
			return c
		}
		return cmp.Compare(a.Statement, b.Statement)
	})
	if res.Error != nil {
		verdict = protocol.PreviewFailed
	}
	res.Verdict = verdict
	res.Summary = summary(res, worst.n, worst.text)
}

func summary(res *protocol.PreviewResult, worstN int, worstImpact string) string {
	ran := 0
	for _, s := range res.Statements {
		if s.Ran && s.Error == "" {
			ran++
		}
	}
	where := "a copy"
	if res.DB != "" {
		where = "a copy of " + res.DB
	}
	switch res.Verdict {
	case protocol.PreviewFailed:
		if e := res.Error; e != nil {
			return fmt.Sprintf("The migration fails at statement %d (line %d): %s. Nothing was changed on production.", e.Statement, e.Line, e.Message)
		}
		return "The migration fails on the copy. Nothing was changed on production."
	case protocol.PreviewSafe:
		return fmt.Sprintf("Safe: %d %s ran in %s on %s, with no long locks, table rewrites or data loss.",
			ran, plural(ran, "statement", "statements"), humanDuration(res.DurationMs), where)
	}
	title := "Careful"
	if res.Verdict == protocol.PreviewDangerous {
		title = "Dangerous"
	}
	var top protocol.PreviewFinding
	if len(res.Findings) > 0 {
		top = res.Findings[0]
	}
	msg := title + ": "
	switch {
	case worstImpact != "" && worstN > 0:
		cmd := ""
		if worstN <= len(res.Statements) && res.Statements[worstN-1].Command != "" {
			cmd = " (" + res.Statements[worstN-1].Command + ")"
		}
		msg += fmt.Sprintf("on production, statement %d%s %s.", worstN, cmd, lowerFirst(worstImpact))
	case top.Title != "":
		msg += top.Title + "."
	default:
		msg += "review the findings."
	}
	if top.Suggestion != "" {
		msg += " " + top.Suggestion
	}
	return msg
}

func lockSuggestion(mode, text string) string {
	if rewriteLikely(text) {
		return rewriteSuggestion(text)
	}
	for _, r := range staticFindings(text, true) {
		if r.suggestion != "" {
			return r.suggestion
		}
	}
	if mode == protocol.PreviewInTransaction {
		return "Split the migration so slow steps don't run in the same transaction as statements that lock busy tables, and set lock_timeout."
	}
	return "Run it when traffic is low, and set lock_timeout so it gives up instead of stalling the app."
}

func rewriteLikely(text string) bool {
	n := Normalize(text)
	return alterTypeRE.MatchString(n) || (addColumnRE.MatchString(n) && defaultRE.MatchString(n))
}

func biggestTable(s *protocol.PreviewStatement) int64 {
	var n int64
	for _, l := range s.Locks {
		n = max(n, l.SizeBytes)
	}
	for _, ix := range s.IndexBuilds {
		n = max(n, ix.SizeBytes)
	}
	return n
}

func rowsNote(rows int64) string {
	if rows <= 0 {
		return ""
	}
	return fmt.Sprintf(", about %s rows", humanCount(rows))
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// humanDuration: "under a second", "about 3 s", "about 2 min", "about 1 h 5 min".
func humanDuration(ms int64) string {
	switch {
	case ms < 1000:
		return "under a second"
	case ms < 60_000:
		return fmt.Sprintf("about %d s", (ms+500)/1000)
	case ms < 3_600_000:
		return fmt.Sprintf("about %d min", (ms+30_000)/60_000)
	}
	h, m := ms/3_600_000, (ms%3_600_000+30_000)/60_000
	if m == 0 || m == 60 {
		return fmt.Sprintf("about %d h", h+m/60)
	}
	return fmt.Sprintf("about %d h %d min", h, m)
}

// HumanDuration is humanDuration for other packages.
func HumanDuration(ms int64) string { return humanDuration(ms) }

// humanBytes: "3.1 GB", "640 MB", "12 kB" (decimal-looking units over
// binary sizes, like the dashboard).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	if v >= 999.5 && exp < 5 {
		v /= unit
		exp++
	}
	if v >= 10 {
		return fmt.Sprintf("%.0f %cB", v, "kMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %cB", v, "kMGTPE"[exp])
}

// HumanBytes is humanBytes for other packages.
func HumanBytes(n int64) string { return humanBytes(n) }

// humanCount: 1,204 or 3.1 million.
func humanCount(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f billion", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	}
	s := fmt.Sprint(n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
