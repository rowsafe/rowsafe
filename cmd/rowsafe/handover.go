package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/internal/localcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// Connecting a server that runs Rowsafe without an account to one: `sudo
// rowsafe login` on it. After the usual login, with a yes:
//
//  1. agent.env and the agent's identity (agent.json) are set aside, and
//     agent.env points at the account with a one-time enrollment token;
//  2. the agent restarts (PostgreSQL doesn't: it keeps archiving its WAL
//     with pgBackRest by itself, so backups never stop) and enrolls;
//  3. each database is registered in the account under the same name; its
//     plan must find Rowsafe's archiving already in place (the same bucket,
//     folder and stanza: no setting, no restart), its history (backups,
//     Proofs, Marks) is imported, and the plan is applied until it is
//     active.
//
// If anything fails, everything is put back: agent.env, the identity, the
// agent restarted on its own control plane, and what was half made in the
// account removed. The login is saved only once the server is connected,
// so `rowsafe` on this server always talks to where its agent is.

// Seams for tests: the agent's files and how it restarts.
var (
	agentEnvPath = "/etc/rowsafe/agent.env"
	restartAgent = func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "systemctl", "restart", "rowsafe-agent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart rowsafe-agent: %v: %s", err, bytes.TrimSpace(out))
		}
		return nil
	}
	isRoot = func() bool { return os.Geteuid() == 0 }
	// How long each step may take.
	handoverEnroll = 3 * time.Minute
	handoverPlan   = 5 * time.Minute
	handoverActive = 10 * time.Minute
	handoverBack   = 2 * time.Minute
	handoverPoll   = 2 * time.Second
)

// Files set aside while connecting.
const (
	asideSuffix     = ".no-account"
	connectedSuffix = ".connected" // the control plane's state, kept after connecting
)

// noAccount is this server, when its agent runs without an account.
type noAccount struct {
	envPath  string
	env      []byte // agent.env as it was
	envInfo  os.FileInfo
	stateDir string // the agent's (agent.json)
	ctlDir   string // its control plane's (the socket, local-control.json)
	socket   string
	x        localcp.Export
}

// findNoAccount returns this server if its agent runs without an account
// (nil if it doesn't, or if there is no agent here). Only root can tell:
// agent.env is root's.
func findNoAccount() (*noAccount, error) {
	data, err := os.ReadFile(agentEnvPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sock, ok := protocol.LocalSocket(envValue(data, "ROWSAFE_URL"))
	if !ok {
		return nil, nil
	}
	fi, err := os.Stat(agentEnvPath)
	if err != nil {
		return nil, err
	}
	n := &noAccount{envPath: agentEnvPath, env: data, envInfo: fi, stateDir: envValue(data, "ROWSAFE_STATE_DIR"),
		ctlDir: filepath.Dir(sock), socket: sock}
	if n.stateDir == "" {
		n.stateDir = "/var/lib/rowsafe"
	}
	n.x, err = localcp.ReadExport(filepath.Join(n.ctlDir, localcp.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		err = nil // the agent hasn't started yet: nothing to hand over
	}
	if err != nil {
		return nil, fmt.Errorf("reading what this server keeps on its own: %w", err)
	}
	return n, nil
}

// ready says what must happen before connecting, if anything.
func (n *noAccount) ready() error {
	for _, d := range n.x.Databases {
		if d.Status != protocol.DBActive {
			return fmt.Errorf("%s isn't protected yet (%s): finish its setup first (run the installer again), then connect", d.Name, strings.ReplaceAll(d.Status, "_", " "))
		}
	}
	if len(n.x.Open) > 0 {
		t := n.x.Open[0]
		return fmt.Errorf("%s: a %s is %s. Connecting restarts the agent, which would cut it short: try again once it is done (sudo rowsafe tasks)",
			t.DatabaseName, strings.ReplaceAll(t.Type, "_", " "), t.Status)
	}
	return nil
}

// what is "N databases (a, b)".
func (n *noAccount) what() string {
	names := make([]string, 0, len(n.x.Databases))
	for _, d := range n.x.Databases {
		names = append(names, d.Name)
	}
	switch len(names) {
	case 0:
		return "no databases yet"
	case 1:
		return "1 database: " + names[0]
	}
	return fmt.Sprintf("%d databases: %s", len(names), strings.Join(names, ", "))
}

func (n *noAccount) hostname() string {
	if n.x.Hostname != "" {
		return n.x.Hostname
	}
	h, _ := os.Hostname()
	return h
}

// answerYes reads the answer to a [Y/n] question: Enter is yes, but the
// end of the input without one (stdin from /dev/null, which looks like a
// terminal) is no.
func answerYes() bool {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := stdin.Read(buf)
		if n > 0 && buf[0] == '\n' {
			a := strings.ToLower(strings.TrimSpace(b.String()))
			return a == "" || a == "y" || a == "yes"
		}
		if n > 0 {
			b.WriteByte(buf[0])
		}
		if err != nil {
			a := strings.ToLower(strings.TrimSpace(b.String()))
			return a == "y" || a == "yes"
		}
	}
}

// handover is one connection attempt, with what it changed so far.
type handover struct {
	n       *noAccount
	cfg     config
	user    *client.Client // the person, with the new login
	out     io.Writer
	aside   bool     // agent.env and agent.json are set aside
	restart bool     // the agent was restarted on the account
	hostID  string   // the host in the account, once enrolled
	made    []string // databases registered in the account
	history []protocol.ImportCounts
}

// connect connects this server to cfg's account, or puts it back.
func (n *noAccount) connect(ctx context.Context, cfg config, out io.Writer) error {
	h := &handover{n: n, cfg: cfg, user: client.New(cfg.URL, cfg.APIKey), out: out}
	if err := h.precheck(ctx); err != nil {
		return err // nothing changed
	}
	tok, err := h.user.CreateEnrollmentToken(ctx, time.Hour)
	if err != nil {
		return fmt.Errorf("getting a one-time enrollment token from %s: %w", h.org(), err)
	}
	if err := h.run(ctx, tok.Token); err != nil {
		return h.putBack(err)
	}
	h.finish()
	return nil
}

func (h *handover) org() string {
	if h.cfg.Org != nil && h.cfg.Org.Name != "" {
		return h.cfg.Org.Name
	}
	return "the account"
}

func (h *handover) say(format string, args ...any) { fmt.Fprintf(h.out, format+"\n", args...) }

// precheck refuses before changing anything: a name the account already
// uses, or an address the agent can't use.
func (h *handover) precheck(ctx context.Context) error {
	if u := h.cfg.URL; !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://localhost") && !strings.HasPrefix(u, "http://127.0.0.1") {
		return fmt.Errorf("the agent connects over https only, and %s isn't: nothing was changed", u)
	}
	dbs, err := h.user.Databases(ctx)
	if err != nil {
		return fmt.Errorf("listing %s's databases: %w", h.org(), err)
	}
	for _, d := range h.n.x.Databases {
		if slices.ContainsFunc(dbs, func(a protocol.Database) bool { return a.Name == d.Name }) {
			return fmt.Errorf("%s already has a database named %s, and this server's keeps its name (it is its backups' folder). "+
				"Rename or remove the one in %s, then run sudo rowsafe login again: nothing was changed", h.org(), d.Name, h.org())
		}
	}
	return nil
}

func (h *handover) run(ctx context.Context, token string) error {
	n := h.n
	// 1. Set aside, then point the agent at the account.
	if err := writeLike(n.envPath+asideSuffix, n.env, n.envInfo); err != nil {
		return fmt.Errorf("keeping a copy of %s: %w", n.envPath, err)
	}
	id := filepath.Join(n.stateDir, "agent.json")
	if err := os.Rename(id, id+asideSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("setting the agent's identity aside: %w", err)
	}
	h.aside = true
	env := setEnv(setEnv(n.env, "ROWSAFE_URL", h.cfg.URL), "ROWSAFE_ENROLL_TOKEN", token)
	if err := writeLike(n.envPath, env, n.envInfo); err != nil {
		return fmt.Errorf("writing %s: %w", n.envPath, err)
	}

	// 2. Restart the agent; it enrolls in the account.
	h.say("Restarting the Rowsafe agent (not PostgreSQL, which keeps sending its changes to storage)...")
	h.restart = true
	if err := restartAgent(ctx); err != nil {
		return err
	}
	var st struct {
		HostID     string `json:"host_id"`
		AgentToken string `json:"agent_token"`
	}
	err := waitFor(ctx, handoverEnroll, func() (bool, error) {
		data, err := os.ReadFile(id)
		if err != nil {
			return false, nil
		}
		return json.Unmarshal(data, &st) == nil && st.AgentToken != "", nil
	})
	if err != nil {
		return fmt.Errorf("the agent didn't connect to %s within %s (journalctl -u rowsafe-agent says why)", h.org(), handoverEnroll)
	}
	h.hostID = st.HostID
	h.say("The agent is connected to %s.", h.org())
	// The token is used up.
	if err := writeLike(n.envPath, setEnv(env, "ROWSAFE_ENROLL_TOKEN", ""), n.envInfo); err != nil {
		return fmt.Errorf("writing %s: %w", n.envPath, err)
	}

	// 3. The databases, under the same names. First every plan (nothing
	// changes), then the history and the apply.
	agent := client.New(h.cfg.URL, st.AgentToken)
	ids := map[string]string{}
	for _, d := range n.x.Databases {
		sd, err := agent.SetupRegister(ctx, protocol.SetupRegisterRequest{Name: d.Name, Port: d.Port, SocketDir: d.SocketDir, Engine: d.Engine})
		if err != nil {
			return fmt.Errorf("adding %s to %s: %w", d.Name, h.org(), err)
		}
		h.made = append(h.made, d.Name)
		ids[d.Name] = sd.ID
		if sd, err = h.waitPlan(ctx, agent, sd); err != nil {
			return err
		}
		switch p := sd.Plan; {
		case p.RestartRequired:
			return fmt.Errorf("%s: %s's setup says PostgreSQL needs a restart, which a database already backing up shouldn't. Nothing was applied", d.Name, h.org())
		case !p.AlreadySetUp:
			return fmt.Errorf("%s: %s's setup doesn't find Rowsafe's backups set up on it (an agent older than this rowsafe CLI? Update it with the installer). Nothing was applied", d.Name, h.org())
		}
	}
	for _, hist := range n.x.History.Databases {
		res, err := agent.Import(ctx, protocol.ImportRequest{Databases: []protocol.ImportDatabase{hist}})
		if err != nil {
			return fmt.Errorf("bringing %s's backups, Proofs and Marks to %s: %w", hist.Name, h.org(), err)
		}
		h.history = append(h.history, res.Databases...)
	}
	for _, d := range n.x.Databases {
		if _, err := agent.SetupApply(ctx, ids[d.Name], protocol.SetupApplyRequest{}); err != nil {
			return fmt.Errorf("setting up %s in %s: %w", d.Name, h.org(), err)
		}
		if err := h.waitActive(ctx, agent, ids[d.Name], d.Name); err != nil {
			return err
		}
		h.say("%s is protected in %s.", d.Name, h.org())
	}
	return nil
}

// waitPlan waits for a registered database's plan.
func (h *handover) waitPlan(ctx context.Context, agent *client.Client, sd protocol.SetupDatabase) (protocol.SetupDatabase, error) {
	err := waitFor(ctx, handoverPlan, func() (bool, error) {
		var err error
		if sd, err = agent.SetupDatabase(ctx, sd.ID); err != nil {
			return false, nil // asked again: a control plane away for a moment
		}
		switch sd.PlanTaskStatus {
		case protocol.StatusSucceeded:
			return sd.Plan != nil, nil
		case protocol.StatusFailed, protocol.StatusLost, protocol.StatusCancelled:
			return false, fmt.Errorf("%s: %s's plan failed: %s", sd.Name, h.org(), sd.PlanError)
		}
		return false, nil
	})
	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("%s: %s's plan didn't come within %s", sd.Name, h.org(), handoverPlan)
	}
	return sd, err
}

// waitActive waits for a database whose plan was applied to be protected
// (archiving checked).
func (h *handover) waitActive(ctx context.Context, agent *client.Client, id, name string) error {
	err := waitFor(ctx, handoverActive, func() (bool, error) {
		sd, err := agent.SetupDatabase(ctx, id)
		if err != nil {
			return false, nil
		}
		switch {
		case sd.Status == protocol.DBActive:
			return true, nil
		case sd.Status == protocol.DBAwaitingRestart:
			return false, fmt.Errorf("%s: after the setup in %s, PostgreSQL waits for a restart", name, h.org())
		case sd.PlanTaskStatus == protocol.StatusFailed || sd.PlanTaskStatus == protocol.StatusLost:
			return false, fmt.Errorf("%s: the setup in %s failed: %s", name, h.org(), sd.PlanError)
		}
		return false, nil
	})
	if errors.Is(err, context.DeadlineExceeded) {
		// Verifying archiving takes a WAL segment's trip to storage.
		err = fmt.Errorf("%s: %s didn't confirm its backups within %s (rowsafe status %s in the account says why)", name, h.org(), handoverActive, name)
	}
	return err
}

// waitFor polls ok until it says done, fails, or within ends
// (context.DeadlineExceeded).
func waitFor(ctx context.Context, within time.Duration, ok func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	for {
		done, err := ok()
		if err != nil || done {
			return err
		}
		if err := sleepCtx(ctx, handoverPoll); err != nil {
			return context.DeadlineExceeded
		}
	}
}

// finish tidies up once connected: the control plane's state stays aside
// (history, no secret), the copies made for going back go.
func (h *handover) finish() {
	n := h.n
	state := filepath.Join(n.ctlDir, localcp.StateFile)
	if err := os.Rename(state, state+connectedSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		h.say("Note: could not set %s aside (%v); the agent doesn't use it any more.", state, err)
	}
	_ = os.Remove(n.socket)
	_ = os.Remove(n.envPath + asideSuffix) // a copy of agent.env, with the storage keys
	_ = os.Remove(filepath.Join(n.stateDir, "agent.json") + asideSuffix)
	for _, c := range h.history {
		h.say("Brought over for %s: %s, %s and %s.", c.Name, count(c.Backups, "backup"), count(c.Drills, "Proof"), count(c.RestorePoints, "Mark"))
	}
}

// count is "1 backup", "3 backups".
func count(n int, what string) string { return fmt.Sprintf("%d %s", n, plural(n, what, what+"s")) }

// putBack undoes a failed attempt: this server goes on without an
// account, as before, and what was half made in the account goes.
func (h *handover) putBack(cause error) error {
	n := h.n
	ctx, cancel := context.WithTimeout(context.Background(), handoverBack+time.Minute)
	defer cancel()
	msg := []string{fmt.Sprintf("Connecting %s to %s stopped: %v.", n.hostname(), h.org(), cause)}
	if !h.aside {
		return errors.New(msg[0] + " Nothing was changed.")
	}
	var errs []error
	if err := writeLike(n.envPath, n.env, n.envInfo); err != nil {
		errs = append(errs, err)
	}
	id := filepath.Join(n.stateDir, "agent.json")
	if err := os.Remove(id); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := os.Rename(id+asideSuffix, id); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if h.restart && len(errs) == 0 {
		if err := restartAgent(ctx); err != nil {
			errs = append(errs, err)
		} else if err := waitFor(ctx, handoverBack, func() (bool, error) {
			fi, err := os.Stat(n.socket)
			return err == nil && fi.Mode()&os.ModeSocket != 0, nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("the agent didn't come back on this server within %s", handoverBack))
		}
	}
	if len(errs) > 0 {
		msg = append(msg, fmt.Sprintf("Putting this server back on its own failed too (%v). Do it yourself:\n"+
			"  sudo cp %[2]s%[3]s %[2]s\n  sudo mv %[4]s%[3]s %[4]s   (if it is there)\n  sudo systemctl restart rowsafe-agent",
			errors.Join(errs...), n.envPath, asideSuffix, id))
		return errors.New(strings.Join(msg, "\n"))
	}
	_ = os.Remove(n.envPath + asideSuffix)
	msg = append(msg, "Put back as it was: the agent runs on its own again, with its databases, backups, Proofs and Marks. "+
		"Backups never stopped (PostgreSQL sends its changes to storage by itself).")

	// What the account got of this attempt: records only (the backups
	// stay in storage, and archiving stays on).
	var left []string
	for _, name := range h.made {
		if err := h.user.DeleteDatabase(ctx, name, true); err != nil && !notFound(err) {
			left = append(left, name)
		}
	}
	if h.hostID != "" && len(left) == 0 {
		if err := h.user.DeleteHost(ctx, h.hostID); err != nil && !notFound(err) {
			left = append(left, "the server "+n.hostname())
		}
	}
	switch {
	case len(left) > 0:
		msg = append(msg, fmt.Sprintf("Remove %s from %s in the dashboard before trying again (it couldn't be removed from here).", strings.Join(left, ", "), h.org()))
	case h.hostID != "":
		msg = append(msg, fmt.Sprintf("Removed what this attempt had added to %s.", h.org()))
	}
	return errors.New(strings.Join(msg, "\n"))
}

func notFound(err error) bool {
	var ae *client.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// ---- agent.env ----

// envValue is KEY's value in an environment file (the last line wins, as
// for the shell; quotes removed).
func envValue(data []byte, key string) string {
	v := ""
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), key+"="); ok {
			v = unquote(rest)
		}
	}
	return v
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// setEnv sets KEY in an environment file the way the installer does: in
// place of its first line (or its commented-out default), quoted; ""
// removes it. Other lines stay as they are.
func setEnv(data []byte, key, value string) []byte {
	var out strings.Builder
	done := false
	for line := range strings.Lines(string(data)) {
		l := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(l, key+"=") || (value != "" && strings.HasPrefix(l, "#"+key+"=")) {
			if !done && value != "" {
				out.WriteString(key + "='" + value + "'\n")
			}
			done = true
			continue
		}
		out.WriteString(l + "\n")
	}
	if !done && value != "" {
		out.WriteString(key + "='" + value + "'\n")
	}
	return []byte(out.String())
}

// writeLike writes data to path atomically with like's mode and owner.
func writeLike(path string, data []byte, like os.FileInfo) error {
	tmp := path + ".rowsafe-new"
	if err := os.WriteFile(tmp, data, like.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chmod(tmp, like.Mode().Perm()); err != nil { // the umask
		os.Remove(tmp)
		return err
	}
	if uid, gid, ok := fileOwner(like); ok && isRoot() {
		if err := os.Chown(tmp, uid, gid); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, path)
}
