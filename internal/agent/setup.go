package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Setup is `rowsafe-agent setup`: the installer, run by root on the database
// host, uses it (as the agent user, with agent.env) to find the local
// PostgreSQL, register it, show the plan and turn on backups with the
// agent's own credentials. It never asks questions: the installer does.
type Setup struct {
	cfg    Config
	client *controlClient
	Out    io.Writer // plan and progress, for the person at the terminal
	Notes  io.Writer // side remarks (skipped clusters)
	Poll   time.Duration
}

// Exit codes of the setup commands (documented in rowsafe-agent's usage).
const (
	SetupTimedOut       = 2  // wait: not finished yet (Rowsafe finishes on its own)
	SetupRefused        = 3  // another archiver is set up; apply --force replaces it
	SetupPlanLimit      = 4  // the organization's plan has no room for another database
	SetupAlreadyDone    = 5  // already protected (or being checked)
	SetupNameTaken      = 7  // another database in the organization has this name
	SetupRestartNeeded  = 10 // settings applied; PostgreSQL needs a restart
	defaultSetupPoll    = 2 * time.Second
	setupSocketTimeouts = 15 * time.Second
)

// ExitError carries a setup command's exit code. Err, when set, is printed.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

func (e *ExitError) Unwrap() error { return e.Err }

// NewSetup loads the agent's identity (written when the agent enrolled).
func NewSetup(cfg Config, out, notes io.Writer) (*Setup, error) {
	data, err := os.ReadFile(filepath.Join(cfg.StateDir, "agent.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this server is not connected to Rowsafe yet: the agent connects when it first starts " +
			"(check it with: systemctl status rowsafe-agent)")
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil || st.AgentToken == "" {
		return nil, fmt.Errorf("reading %s: the agent's identity is unreadable", filepath.Join(cfg.StateDir, "agent.json"))
	}
	return &Setup{cfg: cfg, client: newControlClient(cfg.ControlURL, st.AgentToken), Out: out, Notes: notes, Poll: defaultSetupPoll}, nil
}

// serverMessage is the control plane's own message for an HTTP error.
func serverMessage(err error) string {
	var he *httpError
	if errors.As(err, &he) && he.Msg != "" {
		return he.Msg
	}
	return err.Error()
}

func httpStatus(err error) int {
	var he *httpError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// ---- names

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

// ValidName reports whether name is a valid database name in Rowsafe:
// lowercase letters, digits and dashes, starting with a letter, 2-40
// characters (the control plane's rule).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// NameRule explains ValidName to a person.
const NameRule = "use 2-40 lowercase letters, digits and dashes, starting with a letter"

// SanitizeName turns s into a valid name, or "" when nothing usable is left.
func SanitizeName(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out != "" && (out[0] < 'a' || out[0] > 'z') {
		out = "db-" + out
	}
	if len(out) > 40 {
		out = strings.TrimRight(out[:40], "-")
	}
	if !ValidName(out) {
		return ""
	}
	return out
}

var systemDatabases = []string{"postgres", "template0", "template1"}

// userDatabases are a cluster's databases without the system ones.
func userDatabases(dbs []protocol.DatabaseSize) []string {
	var out []string
	for _, d := range dbs {
		if !slices.Contains(systemDatabases, d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// suggestName: the only user database's name, else the host's short name.
func suggestName(userDBs []string, hostname string) string {
	if len(userDBs) == 1 {
		if n := SanitizeName(userDBs[0]); n != "" {
			return n
		}
	}
	short, _, _ := strings.Cut(hostname, ".")
	if n := SanitizeName(short); n != "" {
		return n
	}
	return "postgres"
}

// ---- discovery

// Cluster is a local PostgreSQL cluster the agent can reach.
type Cluster struct {
	Port       int
	SocketDir  string
	Major      int
	Version    string
	Name       string // Debian cluster name (pg_lsclusters), "" elsewhere
	DataDir    string
	SizeBytes  int64
	Databases  []string // without postgres and the templates
	Suggested  string   // name to offer in Rowsafe (the registered name when registered)
	Unit       string   // systemd unit running it, "" when unknown
	Registered *protocol.SetupDatabase
}

// lsCluster is one line of pg_lsclusters.
type lsCluster struct {
	Major   int
	Name    string
	Port    int
	Status  string
	DataDir string
}

// Discovery sources (variables for tests).
var (
	socketDirs       = []string{"/var/run/postgresql", "/run/postgresql", "/tmp"}
	lsclusters       = runLsclusters
	summarizeCluster = pginspect.Summarize
)

func runLsclusters(ctx context.Context) ([]byte, error) {
	if _, err := exec.LookPath("pg_lsclusters"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, setupSocketTimeouts)
	defer cancel()
	return exec.CommandContext(ctx, "pg_lsclusters", "--no-header").Output()
}

// parseLsclusters reads `pg_lsclusters --no-header`:
// Ver Cluster Port Status Owner Data-directory Log-file.
func parseLsclusters(out []byte) []lsCluster {
	var cs []lsCluster
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		major, err1 := strconv.Atoi(f[0])
		port, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		cs = append(cs, lsCluster{Major: major, Name: f[1], Port: port, Status: f[3], DataDir: f[5]})
	}
	return cs
}

var socketRE = regexp.MustCompile(`^\.s\.PGSQL\.(\d{1,5})$`)

// findSockets maps each port with a PostgreSQL Unix socket to the first
// directory holding it (directories that are the same place count once).
func findSockets(dirs []string) (map[int]string, []int) {
	sockets := map[int]string{}
	var ports []int
	seen := map[string]bool{}
	for _, dir := range dirs {
		real, err := filepath.EvalSymlinks(dir)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			m := socketRE.FindStringSubmatch(e.Name())
			if m == nil || e.Type()&os.ModeSocket == 0 {
				continue
			}
			port, _ := strconv.Atoi(m[1])
			if _, ok := sockets[port]; !ok && port > 0 {
				sockets[port] = dir
				ports = append(ports, port)
			}
		}
	}
	slices.Sort(ports)
	return sockets, ports
}

// Discover finds the running local clusters the agent can connect to, and
// which of them are already in Rowsafe. Clusters it skips are explained on
// Notes.
func (s *Setup) Discover(ctx context.Context) ([]Cluster, error) {
	registered, err := s.client.setupList(ctx)
	if err != nil {
		return nil, fmt.Errorf("asking Rowsafe which databases this server has: %s", serverMessage(err))
	}
	hostname, _ := os.Hostname()

	byPort := map[int]lsCluster{}
	sockets, ports := findSockets(socketDirs)
	if out, err := lsclusters(ctx); err == nil {
		for _, c := range parseLsclusters(out) {
			byPort[c.Port] = c
			if !strings.HasPrefix(c.Status, "online") {
				fmt.Fprintf(s.Notes, "PostgreSQL %d (%s) on port %d is not running; skipped.\n", c.Major, c.Name, c.Port)
			} else if _, ok := sockets[c.Port]; !ok {
				fmt.Fprintf(s.Notes, "PostgreSQL %d (%s) on port %d: no socket in %s; skipped.\n", c.Major, c.Name, c.Port, strings.Join(socketDirs, ", "))
			}
		}
	}

	var out []Cluster
	for _, port := range ports {
		t := pginspect.Target{SocketDir: sockets[port], Port: port, User: s.cfg.PGUser}
		sum, err := summarizeCluster(ctx, t)
		if err != nil {
			fmt.Fprintf(s.Notes, "PostgreSQL on port %d: can't connect as %s over %s (%v); skipped.\n", port, s.cfg.PGUser, sockets[port], firstLineOf(err.Error()))
			continue
		}
		if sum.InRecovery {
			fmt.Fprintf(s.Notes, "PostgreSQL %d on port %d is a replica (standby); skipped. Set up backups on its primary server instead.\n", sum.Major(), port)
			continue
		}
		c := Cluster{Port: port, SocketDir: sockets[port], Major: sum.Major(), Version: sum.ServerVersion,
			DataDir: sum.DataDirectory, SizeBytes: sum.TotalSizeBytes, Databases: userDatabases(sum.Databases)}
		if ls, ok := byPort[port]; ok && ls.Major == c.Major {
			c.Name = ls.Name
		}
		c.Unit = SystemdUnit(c.DataDir, c.Major, c.Name)
		for i := range registered {
			if registered[i].Port == port {
				c.Registered = &registered[i]
			}
		}
		if c.Registered != nil {
			c.Suggested = c.Registered.Name
		} else {
			c.Suggested = suggestName(c.Databases, hostname)
		}
		out = append(out, c)
	}
	// Two new clusters suggesting the same name: tell them apart by port.
	count := map[string]int{}
	for _, c := range out {
		count[c.Suggested]++
	}
	for i, c := range out {
		if c.Registered == nil && count[c.Suggested] > 1 {
			out[i].Suggested = SanitizeName(fmt.Sprintf("%s-%d", c.Suggested, c.Port))
		}
	}
	return out, nil
}

// WriteClusters prints one tab-separated line per cluster:
//
//	port socket_dir major cluster data_dir size_bytes name registered status databases size unit database_id
//
// Empty values are "-"; registered is yes or no; databases are
// comma-separated; size is human-readable (it contains a space).
func WriteClusters(w io.Writer, cs []Cluster) {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, c := range cs {
		reg, status, id := "no", "", ""
		if c.Registered != nil {
			reg, status, id = "yes", c.Registered.Status, c.Registered.ID
		}
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Port, c.SocketDir, c.Major, dash(c.Name), dash(c.DataDir), c.SizeBytes, c.Suggested, reg, dash(status),
			dash(strings.Join(c.Databases, ",")), humanBytes(c.SizeBytes), dash(c.Unit), dash(id))
	}
}

func firstLineOf(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// ---- plan, apply, wait

// Plan registers the cluster on port (idempotent), waits for the agent's
// read-only plan and prints it in plain language. The database ID goes to
// idFile when given.
func (s *Setup) Plan(ctx context.Context, name string, port int, socketDir, idFile string, timeout time.Duration) error {
	if !ValidName(name) {
		return fmt.Errorf("%q can't be a name in Rowsafe: %s", name, NameRule)
	}
	d, err := s.client.setupRegister(ctx, protocol.SetupRegisterRequest{Name: name, Port: port, SocketDir: socketDir})
	switch httpStatus(err) {
	case 0:
	case http.StatusConflict:
		return &ExitError{Code: SetupNameTaken, Err: errors.New(serverMessage(err))}
	case http.StatusPaymentRequired:
		return &ExitError{Code: SetupPlanLimit, Err: errors.New(serverMessage(err))}
	}
	if err != nil {
		return fmt.Errorf("adding %s to Rowsafe: %s", name, serverMessage(err))
	}
	if idFile != "" {
		if err := os.WriteFile(idFile, []byte(d.ID+"\n"), 0o600); err != nil {
			return err
		}
	}
	if done := s.alreadySetUp(d); done != nil {
		return done
	}
	d, err = s.waitTask(ctx, d, timeout)
	if err != nil {
		return err
	}
	if done := s.alreadySetUp(d); done != nil {
		return done
	}
	if d.PlanTaskStatus == protocol.StatusFailed {
		return s.planFailed(d, "Rowsafe couldn't prepare a plan")
	}
	if d.Plan == nil {
		return errors.New("the plan finished without a result; see the task in the dashboard")
	}
	PrintPlan(s.Out, *d.Plan)
	return nil
}

// alreadySetUp handles a database past the plan: nil while it is pending.
func (s *Setup) alreadySetUp(d protocol.SetupDatabase) error {
	switch d.Status {
	case protocol.DBActive:
		fmt.Fprintf(s.Out, "%s is already protected by Rowsafe.\n", d.Name)
		return &ExitError{Code: SetupAlreadyDone}
	case protocol.DBVerifying:
		fmt.Fprintf(s.Out, "Backups are on for %s; Rowsafe is checking that changes reach your storage.\n", d.Name)
		return &ExitError{Code: SetupAlreadyDone}
	case protocol.DBAwaitingRestart:
		fmt.Fprintf(s.Out, "Backups are set up for %s; PostgreSQL needs a restart to start them.\n", d.Name)
		return &ExitError{Code: SetupRestartNeeded}
	}
	return nil
}

// waitTask polls until the adopt task queued with d (or a later one) has
// finished, or the database has moved past the plan.
func (s *Setup) waitTask(ctx context.Context, d protocol.SetupDatabase, timeout time.Duration) (protocol.SetupDatabase, error) {
	want := d.PlanTaskID
	deadline := time.Now().Add(timeout)
	for {
		finished := d.PlanTaskStatus == protocol.StatusSucceeded || d.PlanTaskStatus == protocol.StatusFailed
		if finished && (want == "" || d.PlanTaskID == want) {
			return d, nil
		}
		if d.Status != protocol.DBPendingAdopt && d.Status != "" && want == "" {
			return d, nil
		}
		if time.Now().After(deadline) {
			return d, fmt.Errorf("the Rowsafe agent hasn't finished after %s. Is it running? Check with: systemctl status rowsafe-agent", timeout)
		}
		select {
		case <-ctx.Done():
			return d, ctx.Err()
		case <-time.After(s.Poll):
		}
		next, err := s.client.setupGet(ctx, d.ID)
		if err != nil {
			if st := httpStatus(err); st >= 400 && st < 500 {
				return d, errors.New(serverMessage(err))
			}
			continue // a blip; try again
		}
		d = next
	}
}

// foreignArchiver reports whether the adopt task failed because another
// archiver is set up (the agent's plan says "re-run with force").
func foreignArchiver(d protocol.SetupDatabase) bool {
	return strings.Contains(d.PlanError, "re-run with force")
}

func (s *Setup) planFailed(d protocol.SetupDatabase, what string) error {
	if !foreignArchiver(d) {
		return fmt.Errorf("%s: %s", what, d.PlanError)
	}
	current := ""
	if d.Plan != nil {
		current = d.Plan.Inspect.ArchiveCommand
		if l := d.Plan.Inspect.ArchiveLibrary; l != "" {
			current = "archive_library = " + l
		} else if current != "" {
			current = "archive_command = " + current
		}
	}
	w := s.Out
	fmt.Fprintln(w, "Something else already copies PostgreSQL's changes somewhere: another backup tool is set up.")
	if current != "" {
		fmt.Fprintf(w, "  (%s)\n", current)
	}
	fmt.Fprintln(w, "Rowsafe can take its place. Only do that if you no longer use that tool: it stops")
	fmt.Fprintln(w, "receiving PostgreSQL's changes from then on.")
	fmt.Fprintf(w, "To replace it: rowsafe-agent setup apply --database %s --force (the installer asks you).\n", d.ID)
	return &ExitError{Code: SetupRefused}
}

// Apply turns on backups (the adopt settings) and waits for the result.
func (s *Setup) Apply(ctx context.Context, id string, force bool, timeout time.Duration) error {
	d, err := s.client.setupApply(ctx, id, protocol.SetupApplyRequest{Force: force})
	if err != nil {
		return errors.New(serverMessage(err))
	}
	d, err = s.waitTask(ctx, d, timeout)
	if err != nil {
		return err
	}
	if d.PlanTaskStatus == protocol.StatusFailed {
		return s.planFailed(d, "Turning on backups failed")
	}
	if d.Status == protocol.DBAwaitingRestart || d.Plan != nil && d.Plan.Applied && d.Plan.RestartRequired {
		fmt.Fprintln(s.Out, "Done: the backup settings are in place.")
		return &ExitError{Code: SetupRestartNeeded}
	}
	fmt.Fprintln(s.Out, "Done: the backup settings are in place and active.")
	return nil
}

// Wait prints progress until the database is protected and its first full
// backup has started, or timeout passes (ExitError SetupTimedOut).
func (s *Setup) Wait(ctx context.Context, id string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := ""
	say := func(phase, msg string) {
		if phase != last {
			last = phase
			fmt.Fprintln(s.Out, msg)
		}
	}
	for {
		d, err := s.client.setupGet(ctx, id)
		if err != nil {
			if st := httpStatus(err); st >= 400 && st < 500 {
				return errors.New(serverMessage(err))
			}
		} else {
			switch d.Status {
			case protocol.DBPendingAdopt:
				say("pending", "Waiting for the backup settings to be applied...")
			case protocol.DBAwaitingRestart:
				say("restart", "Waiting for PostgreSQL to restart...")
			case protocol.DBVerifying:
				say("verifying", "Checking that changes reach your storage...")
			case protocol.DBActive:
				check := "ok"
				if utf8Locale() {
					check = "✓"
				}
				switch {
				case d.BackupRunning:
					fmt.Fprintf(s.Out, "%s %s is protected. The first full backup is running.\n", check, d.Name)
					return nil
				case d.LastBackupAt != nil:
					fmt.Fprintf(s.Out, "%s %s is protected. The first full backup is done.\n", check, d.Name)
					return nil
				}
				say("active", "Protected. Starting the first full backup...")
			}
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(s.Out, "Not finished after %s. Rowsafe keeps going on its own; nothing else to do.\n", timeout)
			return &ExitError{Code: SetupTimedOut}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.Poll):
		}
	}
}

// Status prints one tab-separated line: id name status backup dashboard_url,
// where backup is none, running or done and a missing URL is "-".
func (s *Setup) Status(ctx context.Context, id string) error {
	d, err := s.client.setupGet(ctx, id)
	if err != nil {
		return errors.New(serverMessage(err))
	}
	backup := "none"
	if d.BackupRunning {
		backup = "running"
	} else if d.LastBackupAt != nil {
		backup = "done"
	}
	url := d.DashboardURL
	if url == "" {
		url = "-"
	}
	fmt.Fprintf(s.Out, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.Status, backup, url)
	return nil
}

// ---- the plan in plain language

func utf8Locale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

// PrintPlan explains an adopt plan for someone who isn't a PostgreSQL
// expert: what gets written, which settings change, whether a restart is
// needed and how big the database is. Setting names are kept in brackets
// for those who want them.
func PrintPlan(w io.Writer, r protocol.AdoptResult) {
	arrow := "->"
	if utf8Locale() {
		arrow = "→"
	}
	in := r.Inspect
	if in.ServerVersion != "" {
		var names []string
		for _, d := range in.Databases {
			if !slices.Contains(systemDatabases, d.Name) {
				names = append(names, d.Name)
			}
		}
		what := "no databases of your own yet"
		switch len(names) {
		case 0:
		case 1:
			what = "1 database (" + names[0] + ")"
		default:
			what = fmt.Sprintf("%d databases (%s)", len(names), strings.Join(names, ", "))
		}
		fmt.Fprintf(w, "PostgreSQL %s on port %d: %s, %s.\n\n", strings.Fields(in.ServerVersion + " ")[0], in.Port, humanBytes(in.TotalSizeBytes), what)
	}
	if r.Applied {
		fmt.Fprintln(w, "What Rowsafe changed:")
	} else {
		fmt.Fprintln(w, "What Rowsafe will change:")
	}
	for _, c := range r.Plan {
		fmt.Fprintf(w, "  - %s\n", describeChange(c, arrow))
	}
	for _, warn := range r.Warnings {
		if strings.HasPrefix(warn, RestartWarningPrefix) {
			continue // said below, in plain words
		}
		fmt.Fprintf(w, "  ! %s\n", warn)
	}
	fmt.Fprintln(w)
	if r.RestartRequired {
		fmt.Fprintln(w, "Restart: PostgreSQL needs one quick restart (a few seconds) before backups start.")
		fmt.Fprintln(w, "         It only restarts if you say so.")
	} else {
		fmt.Fprintln(w, "No downtime: PostgreSQL does not need a restart.")
	}
}

func describeChange(c protocol.Change, arrow string) string {
	restart := ""
	if c.Restart {
		restart = ", needs a restart"
	}
	fromTo := func(from, to string) string {
		if from == "" {
			from = "not set"
		}
		if to == "" {
			to = "not set"
		}
		return from + " " + arrow + " " + to
	}
	switch c.Kind {
	case "file":
		if i := strings.LastIndex(c.Description, " to "); strings.Contains(c.Description, "pgBackRest config") && i >= 0 {
			return "Save the backup settings in " + c.Description[i+4:] + " (only postgres can read it: it holds your storage key)"
		}
		if strings.Contains(c.Description, "spool") {
			return "Create the folder where PostgreSQL hands its changes to the Rowsafe container"
		}
	case "command":
		if strings.Contains(c.Description, "stanza-create") {
			return "Prepare your bucket for this database"
		}
	case "setting":
		switch c.Setting {
		case "wal_level":
			return fmt.Sprintf("Keep enough detail in PostgreSQL's change log to restore from it (wal_level: %s%s)", fromTo(c.From, c.To), restart)
		case "archive_mode":
			return fmt.Sprintf("Turn on copying of every change to your bucket (archive_mode: %s%s)", fromTo(c.From, c.To), restart)
		case "archive_command":
			if c.From == "" || c.From == "(disabled)" {
				return "Copy the changes with Rowsafe (archive_command" + restart + ")"
			}
			return "Copy the changes with Rowsafe instead of the current command (archive_command" + restart + ")"
		case "archive_library":
			return fmt.Sprintf("Turn off the other archiver (archive_library: %s%s)", fromTo(c.From, c.To), restart)
		case "archive_timeout":
			every := c.To + " seconds"
			if n, err := strconv.Atoi(c.To); err == nil && n%60 == 0 {
				every = fmt.Sprintf("%d minutes", n/60)
			}
			return fmt.Sprintf("Send changes at least every %s, even when the database is quiet (archive_timeout: %s%s)", every, fromTo(c.From, c.To), restart)
		default:
			return fmt.Sprintf("Change %s: %s%s", c.Setting, fromTo(c.From, c.To), restart)
		}
	}
	return c.Description
}
