package pglog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Target is a PostgreSQL cluster reachable over its local Unix socket.
type Target struct {
	SocketDir string
	Port      int
	User      string
}

func (t Target) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host = t.SocketDir
	cfg.Port = uint16(t.Port)
	cfg.User = t.User
	cfg.Database = "postgres"
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["application_name"] = "rowsafe-agent-logs"
	cfg.RuntimeParams["statement_timeout"] = "3000"
	return pgx.ConnectConfig(ctx, cfg)
}

// Settings reads are what the source status reports (and the logging fix
// decides from).
var reportedSettings = []string{
	"logging_collector", "log_destination", "log_directory", "log_filename", "log_line_prefix", "log_timezone",
	"lc_messages", "log_min_duration_statement", "log_lock_waits", "log_temp_files", "log_autovacuum_min_duration",
	"log_checkpoints", "log_connections", "log_disconnections", "log_statement", "log_min_messages",
	"log_min_error_statement", "log_error_verbosity", "server_version_num", "data_directory",
}

// Source is where a cluster's log is read.
type Source struct {
	Status   protocol.LogSource
	Format   string // protocol.LogFormat*
	Path     string // file, or systemd unit for journald
	Prefix   string // log_line_prefix
	Location *time.Location
}

// sameAs reports whether two discoveries read the same log the same way.
func (s Source) sameAs(o Source) bool {
	return s.Format == o.Format && s.Path == o.Path && s.Prefix == o.Prefix && s.Status.Readable == o.Status.Readable &&
		s.Status.Problem == o.Status.Problem && s.Status.Detail == o.Status.Detail && mapsEqual(s.Status.Settings, o.Status.Settings)
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// discoverer finds a cluster's log. Tests replace its hooks.
type discoverer struct {
	procRoot   string
	sidecar    bool
	journalctl string
	// journalReadable checks that the agent's user may read the unit's
	// journal (nil: run journalctl).
	journalReadable func(ctx context.Context, unit string) error
}

// discover reads PostgreSQL's logging settings and finds the log.
func (d discoverer) discover(ctx context.Context, t Target, now time.Time) Source {
	src := Source{Status: protocol.LogSource{CheckedAt: now.UTC()}}
	fail := func(problem, detail string) Source {
		src.Status.Readable, src.Status.Problem, src.Status.Detail = false, problem, detail
		src.Format, src.Path = "", ""
		return src
	}
	conn, err := t.connect(ctx)
	if err != nil {
		return fail(protocol.LogProblemNotConnecting, fmt.Sprintf("Rowsafe couldn't connect to PostgreSQL on port %d: %v", t.Port, err))
	}
	defer conn.Close(context.WithoutCancel(ctx))
	rows, err := conn.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name = ANY($1)`, reportedSettings)
	if err != nil {
		return fail(protocol.LogProblemNoAccess, "Rowsafe couldn't read PostgreSQL's log settings: "+err.Error())
	}
	settings := map[string]string{}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return fail(protocol.LogProblemNoAccess, "Rowsafe couldn't read PostgreSQL's log settings: "+err.Error())
		}
		settings[n] = v
	}
	rows.Close()
	if rows.Err() != nil {
		return fail(protocol.LogProblemNoAccess, "Rowsafe couldn't read PostgreSQL's log settings: "+rows.Err().Error())
	}
	dataDir := settings["data_directory"]
	delete(settings, "data_directory")
	src.Status.Settings = settings
	src.Prefix = settings["log_line_prefix"]
	src.Location = time.UTC
	if tz := settings["log_timezone"]; tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			src.Location = loc
		}
	}
	if dataDir == "" {
		return fail(protocol.LogProblemNoAccess, "Rowsafe can't see PostgreSQL's data directory, so it can't find the log. "+
			"The agent's database role needs to be a superuser or have pg_read_all_settings.")
	}
	dests := splitList(settings["log_destination"])
	if settings["logging_collector"] == "on" {
		format := ""
		for _, f := range []string{protocol.LogFormatJSON, protocol.LogFormatCSV, protocol.LogFormatStderr} {
			if slices.Contains(dests, f) {
				format = f
				break
			}
		}
		if format == "" {
			return fail(protocol.LogProblemSyslog, "PostgreSQL sends its log to "+settings["log_destination"]+
				" only, which Rowsafe doesn't read. Add stderr (or csvlog or jsonlog) to log_destination.")
		}
		var current *string
		_ = conn.QueryRow(ctx, `SELECT pg_current_logfile($1)`, format).Scan(&current)
		path := ""
		if current != nil && *current != "" {
			path = *current
		} else {
			dir := settings["log_directory"]
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(dataDir, dir)
			}
			path = newestLogFile(dir, format)
		}
		if path == "" {
			return fail(protocol.LogProblemNotFound, "PostgreSQL writes its log to "+settings["log_directory"]+
				", but Rowsafe found no log file there yet.")
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dataDir, path)
		}
		return d.file(src, format, path)
	}
	if !slices.Contains(dests, protocol.LogFormatStderr) {
		return fail(protocol.LogProblemSyslog, "PostgreSQL sends its log to "+settings["log_destination"]+
			" only, which Rowsafe doesn't read. Add stderr to log_destination.")
	}
	if d.sidecar {
		return fail(protocol.LogProblemDockerStdout, "PostgreSQL writes its log to the container's output, which the Rowsafe "+
			"sidecar can't read. Turn on logging_collector so PostgreSQL also writes log files in its data directory.")
	}
	// Where does the postmaster's stderr go?
	target, err := d.stderrTarget(dataDir)
	switch {
	case err == nil && strings.HasPrefix(target, "/") && target != "/dev/null" && !strings.HasPrefix(target, "/dev/pts/"):
		return d.file(src, protocol.LogFormatStderr, target)
	case err == nil && strings.HasPrefix(target, "socket:"):
		unit := d.unitOf(dataDir)
		if unit == "" {
			return fail(protocol.LogProblemJournal, "PostgreSQL's log goes to the system journal, but Rowsafe couldn't tell which service it belongs to.")
		}
		src.Status.Path, src.Path, src.Format = unit, unit, protocol.LogFormatJournald
		src.Status.Format = protocol.LogFormatJournald
		check := d.journalReadable
		if check == nil {
			check = d.checkJournal
		}
		if err := check(ctx, unit); err != nil {
			return fail(protocol.LogProblemJournal, "PostgreSQL's log goes to the system journal ("+unit+"), which the agent's user "+
				"may not read: "+err.Error())
		}
		src.Status.Readable = true
		return src
	case err == nil && target == "/dev/null":
		return fail(protocol.LogProblemNotFound, "PostgreSQL's log output is thrown away (/dev/null). Turn on logging_collector so it writes log files.")
	case err == nil:
		return fail(protocol.LogProblemUnsupported, "PostgreSQL's log goes to "+target+", which Rowsafe can't read. Turn on logging_collector so it writes log files.")
	}
	// No /proc access: the Debian layout's log file.
	if p := debianLogFile(dataDir); p != "" {
		return d.file(src, protocol.LogFormatStderr, p)
	}
	return fail(protocol.LogProblemNotFound, "Rowsafe couldn't tell where PostgreSQL writes its log. Turn on logging_collector so it writes log files in its data directory.")
}

// file checks a log file and fills the source.
func (d discoverer) file(src Source, format, path string) Source {
	src.Format, src.Path = format, path
	src.Status.Format, src.Status.Path = format, path
	f, err := os.Open(path)
	if err != nil {
		src.Status.Readable = false
		src.Format = ""
		switch {
		case errors.Is(err, fs.ErrPermission):
			src.Status.Problem = protocol.LogProblemPermission
			src.Status.Detail = "The agent's user can't read " + path + ". Make it readable by the postgres user."
		case errors.Is(err, fs.ErrNotExist) && d.sidecar:
			src.Status.Problem = protocol.LogProblemNotFound
			src.Status.Detail = path + " isn't visible to the Rowsafe sidecar: mount PostgreSQL's data volume at the same path in both containers."
		default:
			src.Status.Problem = protocol.LogProblemNotFound
			src.Status.Detail = "Rowsafe can't open " + path + ": " + err.Error()
		}
		return src
	}
	f.Close()
	src.Status.Readable = true
	return src
}

// stderrTarget is where the postmaster's standard error goes, from
// /proc/<pid>/fd/2 (the postmaster's PID is the first line of
// postmaster.pid).
func (d discoverer) stderrTarget(dataDir string) (string, error) {
	pid, err := postmasterPID(dataDir)
	if err != nil {
		return "", err
	}
	return os.Readlink(filepath.Join(d.procRoot, strconv.Itoa(pid), "fd", "2"))
}

func postmasterPID(dataDir string) (int, error) {
	f, err := os.Open(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, errors.New("empty postmaster.pid")
	}
	return strconv.Atoi(strings.TrimSpace(sc.Text()))
}

// unitOf is the systemd service the postmaster runs in.
func (d discoverer) unitOf(dataDir string) string {
	pid, err := postmasterPID(dataDir)
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(d.procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		parts := strings.Split(l, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], ".service") {
				return parts[i]
			}
		}
	}
	return ""
}

// checkJournal reads the newest entry of a unit's journal.
func (d discoverer) checkJournal(ctx context.Context, unit string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.journalctl, "-u", unit, "-n", "1", "-o", "json", "--no-pager")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("journalctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	s := string(out)
	if strings.Contains(s, "insufficient permissions") || strings.Contains(s, "not seeing messages from other users") {
		return errors.New("add the postgres user to the systemd-journal group")
	}
	return nil
}

var debianDataDirRE = regexp.MustCompile(`^/var/lib/postgresql/([0-9.]+)/([^/]+)/?$`)

// debianLogFile is the log file pg_ctlcluster writes for a Debian-layout
// cluster, when it exists.
func debianLogFile(dataDir string) string {
	m := debianDataDirRE.FindStringSubmatch(dataDir)
	if m == nil {
		return ""
	}
	p := fmt.Sprintf("/var/log/postgresql/postgresql-%s-%s.log", m[1], m[2])
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// newestLogFile is the most recently modified log file of a format in dir.
func newestLogFile(dir, format string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best, bestAt := "", time.Time{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		switch format {
		case protocol.LogFormatJSON:
			if ext != ".json" {
				continue
			}
		case protocol.LogFormatCSV:
			if ext != ".csv" {
				continue
			}
		default:
			if ext == ".json" || ext == ".csv" {
				continue
			}
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestAt) {
			best, bestAt = filepath.Join(dir, e.Name()), info.ModTime()
		}
	}
	return best
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
