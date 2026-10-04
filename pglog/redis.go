package pglog

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// ---- Redis and Valkey: the server's log file ----
//
// "<pid>:<role> <dd Mon yyyy hh:mm:ss.mmm> <level> <message>", role X
// (Sentinel), C (a child: saving), S (replica) or M (primary), level "."
// debug, "-" verbose, "*" notice, "#" warning. Valkey writes the same
// (log-format legacy, its default), with log-timestamp-format legacy,
// iso8601 or milliseconds.
//
// Redis and Valkey rarely log data, but the server's log also holds what
// Lua scripts write with redis.log() and what modules write: lines that
// aren't one of the server's own messages keep only their plain words
// (quoted text, numbers, names with ":", "@", "/"... are hidden), like
// PostgreSQL's RAISE messages. A crash report (which can quote the
// command being run) stays on the server: only that it crashed, and why,
// is sent.

var (
	redisLineRE = regexp.MustCompile(`^(\d+):([XCSM]) (\d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}T\S+|\d{13}) ([.\-*#]) (.*)$`)
	redisAddrRE = regexp.MustCompile(`(?:addr=|Accepted |[Rr]eplica (?:\(\w+\) )?|from )(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\]):\d+`)
	redisUserRE = regexp.MustCompile(`\buser=(\S+)`)
	// redisPlainWordRE: a word Lua and module lines keep.
	redisPlainWordRE = regexp.MustCompile(`^(?:[(\[]?[A-Za-z][A-Za-z'-]*[.,;:!?)\]]*|<[A-Za-z][\w-]*>)$`)
)

// The server's own messages, by kind. A line containing one of these is
// Redis's (or Valkey's) own; Redis and Valkey say their name in some.
var (
	redisServerMsgs = []string{
		"is starting oO0OoO0OoO0Oo", " version=", "Configuration loaded", "Server initialized", "Ready to accept connections",
		"User requested shutdown", "Received SIGTERM", "Received SIGINT", "scheduling shutdown", "is now ready to exit",
		"Removing the pid file", "DB loaded from disk", "DB loaded from append only file", "Done loading RDB", "Loading RDB produced by",
		"RDB age ", "RDB memory usage when created", "Reading RDB base file", "Running mode=", "monotonic clock",
		"Saving the final RDB snapshot", "Calling fsync() on the AOF file", "Increased maximum number of open files",
		"You requested maxclients", "no config file specified", "Module '", "Shutdown", "Lazy loading", "Server started",
		"ready to exit", "Errors trying to shut down", "Waiting for replicas before shutting down",
	}
	redisSaveMsgs = []string{
		"Background saving started", "Background saving terminated", "DB saved on disk", "seconds. Saving...", "Fork CoW",
		"Background append only file rewriting", "Background AOF", "AOF rewrite", "Residual parent diff", "Starting automatic rewriting of AOF",
		"Successfully renamed the temporary AOF", "Removing the history file", "Creating AOF incr file", "Creating AOF base file",
		"Successfully created the temporary AOF", "BGSAVE",
		"Background saving error", "Can't save in background", "Failed opening the temp RDB file", "Failed opening the RDB file",
		"Write error saving DB on disk", "Write error writing append only file", "MISCONF", "Error moving temp DB file",
		"Error trying to save the DB", "Asynchronous AOF fsync is taking too long",
	}
	redisConnMsgs = []string{
		"Accepted ", "Client closed connection", "Error accepting a client connection", "for overcoming of output buffer limits",
		"Connection with replica", "Connection with master lost", "Connection with primary lost", "Client id=",
	}
	redisReplMsgs = []string{
		"Replica ", "replica ", "REPLICA sync", "Connecting to MASTER", "Connecting to PRIMARY", "MASTER aborted", "Master replied",
		"Master accepted", "Primary accepted", "Partial resynchronization", "Full resync", "Starting BGSAVE for SYNC", "Diskless",
		"Streamed RDB", "Synchronization with replica", "Waiting for end of BGSAVE", "Discarding previously cached",
		"Trying a partial resynchronization", "Successful partial resynchronization", "Before turning into a replica",
		"Setting secondary replication ID", "MASTER MODE enabled", "PRIMARY MODE enabled", "REPLICAOF", "Caching the disconnected",
		"Replication backlog", "Non blocking connect for SYNC", "Loading DB in memory", "Flushing old data", "Retrying with SYNC",
		"Unable to partial resync", "MASTER timeout", "PRIMARY timeout", "Timeout connecting to the", "Error condition on socket for SYNC",
		"Done loading", "Discarding", "Primary replied", "rdb channel", "rdbchannel", "Master is currently unable to PSYNC", "Primary is currently unable to PSYNC", "PSYNC",
	}
	redisOtherMsgs = []string{
		"WARNING", "Possible SECURITY ATTACK detected", "ASSERTION FAILED", "Short read", "Bad file format", "Fatal error loading",
		"Out Of Memory allocating", "Unrecoverable error", "Can't handle RDB format", "Unexpected EOF reading RDB file", "Wrong signature",
		"Lua slow script detected", "Slow script detected", "Memory overcommit", "Transparent Huge Pages", "TCP backlog",
		"Error accepting", "Failed listening on port", "Could not create server TCP listening socket", "Opening Unix socket",
		"Unable to set the max number of files", "Server can't set maximum open files",
	}
	redisErrorWords = []string{"error", "Error", "can't", "Can't", "cannot", "Cannot", "failed", "Failed", "Short read", "Bad file format",
		"Out Of Memory", "Unrecoverable", "MISCONF", "corrupt", "Unable", "unable", "crashed", "Crashed", "Fatal", "ASSERTION"}
)

func containsAny(s string, list []string) bool {
	for _, x := range list {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func (p *engineParser) redis(line string) {
	m := redisLineRE.FindStringSubmatch(line)
	if m == nil {
		return // the startup logo, blank lines: nothing to keep
	}
	t, ok := parseRedisTime(m[3])
	if !ok {
		return
	}
	msg := strings.TrimSpace(m[5])
	if p.redisCrash {
		switch {
		case strings.Contains(msg, "BUG REPORT END") || strings.Contains(msg, "is starting oO0OoO0OoO0Oo"):
			p.redisCrash = false
			p.flush()
			if strings.Contains(msg, "BUG REPORT END") {
				return
			}
		case p.cur != nil && (strings.Contains(msg, "crashed by signal") || strings.HasPrefix(msg, "Guru Meditation")) && len(p.cur.Detail) < 500:
			p.cur.Detail = strings.TrimSpace(p.cur.Detail + "\n" + msg)
			return
		default:
			return // the report's details (the command, memory, stack) stay on the server
		}
	}
	e := Entry{Time: t, PID: atoi(m[1]), Message: msg}
	switch m[4] {
	case "#":
		e.Severity = "WARNING"
	case "*":
		e.Severity = "LOG"
	default:
		e.Severity = "DEBUG"
	}
	if strings.Contains(msg, "BUG REPORT START") {
		p.flush()
		p.redisCrash = true
		e.Severity, e.Kind = "FATAL", protocol.LogKindError
		e.Message = "The server crashed (its crash report stays in the log on the server)"
		p.cur = &e
		return
	}
	switch {
	case containsAny(msg, redisConnMsgs):
		e.Kind = protocol.LogKindConnection
	case containsAny(msg, redisSaveMsgs):
		e.Kind = protocol.LogKindCheckpoint
	case containsAny(msg, redisServerMsgs):
		e.Kind = protocol.LogKindServer
	case containsAny(msg, redisReplMsgs) || containsAny(msg, redisOtherMsgs):
		e.Kind = protocol.LogKindOther
	default:
		// A Lua script's redis.log() or a module: anything may be in it.
		e.Message, e.Redacted = redactRedisUnknown(msg)
		e.Kind = protocol.LogKindOther
		if strings.HasPrefix(msg, "<") {
			if mod, _, ok := strings.Cut(msg[1:], ">"); ok && !strings.ContainsAny(mod, " \t") {
				e.Application = mod // a module's name
			}
		}
	}
	// The server says "#" for warnings and errors alike.
	if e.Severity == "WARNING" && !strings.HasPrefix(msg, "WARNING") && containsAny(msg, redisErrorWords) {
		e.Severity = "ERROR"
	}
	if e.Kind != protocol.LogKindConnection && e.Kind != protocol.LogKindServer && IsError(e.Severity) {
		e.Kind = protocol.LogKindError
	}
	if a := redisAddrRE.FindStringSubmatch(msg); a != nil {
		e.Client = strings.Trim(a[1], "[]")
	}
	if u := redisUserRE.FindStringSubmatch(msg); u != nil && !strings.HasPrefix(u[1], "*") {
		e.User = u[1]
	}
	if e.Kind == protocol.LogKindConnection && (strings.Contains(msg, "name=rowsafe-agent ") || strings.Contains(msg, "name=rowsafe-link ")) {
		return // the agent's own connections (loglevel verbose)
	}
	if strings.Contains(msg, "rowsafe-agent") {
		e.Application = "rowsafe-agent" // Rowsafe's own replication link
	}
	p.out = append(p.out, e)
}

// redactRedisUnknown keeps only a line's plain words.
func redactRedisUnknown(msg string) (string, bool) {
	f := strings.Fields(msg)
	changed := false
	for i, w := range f {
		if !redisPlainWordRE.MatchString(w) {
			f[i] = Hidden
			changed = true
		}
	}
	return strings.Join(f, " "), changed
}

// parseRedisTime reads the server's timestamps (its local time).
func parseRedisTime(s string) (time.Time, bool) {
	if len(s) == 13 && s[0] >= '1' && s[0] <= '9' && !strings.Contains(s, " ") {
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.UnixMilli(ms), true
		}
	}
	for _, layout := range []string{"02 Jan 2006 15:04:05.000", "2 Jan 2006 15:04:05.000", "02 Jan 2006 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999Z0700", "2006-01-02T15:04:05.999"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ParseEngineLog parses a piece of an engine's log the way the collector
// does (Format*): classified and redacted, every entry complete. For tests
// against real servers and for checking a log by hand.
func ParseEngineLog(format, text string) []Entry {
	p := newEngineParser(format)
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		p.Add(l)
	}
	out := p.Take(true)
	for i := range out {
		Classify(&out[i])
		Redact(&out[i], false)
	}
	return out
}
