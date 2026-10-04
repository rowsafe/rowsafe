package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The firewall. Rowsafe can let only chosen addresses reach PostgreSQL's
// port, but only where root allowed it for that port when installing the
// agent (--allow-firewall). The agent, which runs unprivileged, hands the
// request to a root helper (rowsafe-firewall, started by a path unit),
// exactly like restarts:
//
//	/etc/rowsafe/firewall-allowed         root, 0644: one "PORT" per line
//	<state dir>/firewall/addresses        written by the agent: one CIDR per line
//	<state dir>/firewall/request          written by the agent: "ID ACTION PORT"
//	<state dir>/firewall/confirm          written by the agent: "ID"
//	/run/rowsafe-firewall/result          written by the helper: key=value lines
//	/run/rowsafe-firewall/port-PORT       the rule in place: addresses, applied_at, loaded
//
// The helper never writes or removes anything in the agent's directory: the
// agent removes its request once it has the answer. The helper also checks
// on its own that the port is at least 1024, isn't SSH's, and that
// PostgreSQL (the postgres user) listens on it.
//
// The helper changes one nftables table of its own (inet rowsafe) that only
// matches the PostgreSQL port: SSH and every other port are never touched.
// After applying a rule it answers phase=pending and waits for the agent to
// confirm, which the agent does only once it has reached the control plane
// and PostgreSQL again; without that confirmation the helper puts the
// previous rules back.

// Firewall helper actions.
const (
	fwApply  = "apply"
	fwRemove = "remove"
	fwStatus = "status"
)

// firewallMu keeps one request to the helper at a time (a fix, or the
// scan's status check).
var firewallMu sync.Mutex

// firewallStatusWait bounds the scan's wait for a status answer.
var firewallStatusWait = 10 * time.Second

// Firewall paths (variables for tests; the environment can move them).
var (
	firewallAllowFile = envOr("ROWSAFE_FIREWALL_ALLOW_FILE", "/etc/rowsafe/firewall-allowed")
	firewallResultDir = envOr("ROWSAFE_FIREWALL_RESULT_DIR", "/run/rowsafe-firewall")
	firewallDirEnv    = os.Getenv("ROWSAFE_FIREWALL_DIR")
	// firewallTimeout bounds each wait for the helper (it waits up to 60
	// seconds for the confirmation itself).
	firewallTimeout = 120 * time.Second
)

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func (a *Agent) firewallDir() string {
	if firewallDirEnv != "" {
		return firewallDirEnv
	}
	return filepath.Join(a.cfg.StateDir, "firewall")
}

// firewallAllowedPorts reads the allow list; a missing file means off.
func firewallAllowedPorts() (map[int]bool, error) {
	ports, _, err := firewallAllowList()
	return ports, err
}

// firewallAllowList reads the allow list: the ports, and whether the line
// "ssh" is there (servers Rowsafe creates, installer --firewall-ssh: SSH's
// allow list is Rowsafe's too).
func firewallAllowList() (map[int]bool, bool, error) {
	f, err := os.Open(firewallAllowFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[int]bool{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	out := map[int]bool{}
	ssh := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[0] == "ssh" {
			ssh = true
		} else if p, err := strconv.Atoi(fields[0]); err == nil && p > 0 && p < 65536 {
			out[p] = true
		}
	}
	return out, ssh, sc.Err()
}

// firewallState is what Rowsafe may do with the firewall for port.
func (a *Agent) firewallState(port int) protocol.FirewallState {
	if a.cfg.Sidecar() {
		return protocol.FirewallState{Reason: "PostgreSQL runs in Docker: Docker's published ports bypass the server's firewall, so limit them in your compose file instead."}
	}
	ports, err := firewallAllowedPorts()
	if err != nil || !ports[port] {
		return protocol.FirewallState{Reason: "Root didn't allow Rowsafe to manage the firewall for this port when installing the agent."}
	}
	st := protocol.FirewallState{Allowed: true}
	if _, err := os.Stat(a.firewallDir()); err != nil {
		st.Allowed, st.Reason = false, "The firewall helper is not set up on this server: root allows it with "+AllowHint(protocol.PermFirewall)+"."
		return st
	}
	data, err := os.ReadFile(filepath.Join(firewallResultDir, "port-"+strconv.Itoa(port)))
	if err != nil {
		return st
	}
	// The helper checks nftables really holds the rule (someone may have
	// flushed the firewall since).
	if fresh, ok := a.firewallRefresh(port); ok {
		data = fresh
	}
	kv := parseKeyValues(string(data))
	if kv["loaded"] == "0" {
		st.Reason = "Rowsafe's firewall rule for this port is no longer loaded (was the firewall reloaded?): apply it again."
		return st
	}
	if addrs := strings.TrimSpace(kv["addresses"]); addrs != "" {
		st.Active = true
		st.Addresses = strings.Split(addrs, ",")
		if n, err := strconv.ParseInt(kv["applied_at"], 10, 64); err == nil && n > 0 {
			t := time.Unix(n, 0).UTC()
			st.AppliedAt = &t
		}
	}
	return st
}

func (a *Agent) firewall(ctx context.Context, db protocol.DatabaseSpec, p protocol.SecurityFixParams, res *protocol.SecurityFixResult, tl *taskLog) error {
	st := a.firewallState(db.Port)
	if !st.Allowed {
		return errors.New(st.Reason + " To allow it, root runs " + AllowHint(protocol.PermFirewall) + " on this server.")
	}
	action := fwRemove
	var addrs []string
	if p.Action == protocol.SecFirewall {
		action = fwApply
		allowed, err := parseAllowed(p.AllowedAddresses)
		if err != nil {
			return err
		}
		for _, a := range allowed {
			addrs = append(addrs, a.String())
		}
	}
	files := map[string][]string{}
	if action == fwApply {
		files["addresses"] = addrs
	}
	tl.Printf("asking the firewall helper to %s the rule for port %d", action, db.Port)
	firewallMu.Lock()
	defer firewallMu.Unlock()
	err := a.firewallRequest(ctx, action, db.Port, files, func(ctx context.Context) error {
		// The rule is in place: confirm only if Rowsafe and PostgreSQL are
		// still reachable, else the helper rolls it back by itself.
		tl.Printf("rule in place; checking the agent still reaches Rowsafe and %s", protocol.EngineDisplayName(db.Engine))
		if err := a.reachesControlPlane(ctx); err != nil {
			return err
		}
		return a.databaseReachable(ctx, db)
	}, tl)
	if err != nil {
		return err
	}
	if action == fwApply {
		res.Summary = fmt.Sprintf("The firewall lets only %s reach %s's port %d now. SSH and other ports are unchanged.", strings.Join(addrs, ", "),
			protocol.EngineDisplayName(db.Engine), db.Port)
	} else {
		res.Summary = fmt.Sprintf("Rowsafe's firewall rule for port %d is removed.", db.Port)
	}
	tl.Printf("%s", res.Summary)
	return nil
}

// firewallRequest hands one request to the helper and waits for its final
// answer. files (name -> lines) are written next to the request first.
// When the helper answers phase=pending (the new rules are loaded), the
// agent confirms only if check passes; otherwise the helper puts the
// previous rules back by itself. The caller holds firewallMu.
func (a *Agent) firewallRequest(ctx context.Context, action string, port int, files map[string][]string,
	check func(context.Context) error, tl *taskLog) error {
	id := newFirewallID()
	dir := a.firewallDir()
	defer a.firewallDone()
	for name, lines := range files {
		data := []byte{}
		if len(lines) > 0 {
			data = []byte(strings.Join(lines, "\n") + "\n")
		}
		if err := writeFileAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(dir, "confirm"))
	if err := writeFileAtomic(filepath.Join(dir, "request"), fmt.Appendf(nil, "%s %s %d\n", id, action, port), 0o600); err != nil {
		return err
	}
	resPath := filepath.Join(firewallResultDir, "result")
	r, err := waitHelper(ctx, resPath, func(kv map[string]string) bool { return kv["id"] == id })
	if err != nil {
		_ = os.Remove(filepath.Join(dir, "request"))
		return fmt.Errorf("the firewall helper did not answer: %w (check `systemctl status rowsafe-firewall.path`)", err)
	}
	if r["phase"] == "pending" {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := check(cctx)
		cancel()
		if err != nil {
			tl.Printf("not confirming (%v): the helper puts the previous rules back", err)
		} else if err := writeFileAtomic(filepath.Join(dir, "confirm"), []byte(id+"\n"), 0o600); err != nil {
			return err
		}
		r, err = waitHelper(ctx, resPath, func(kv map[string]string) bool { return kv["id"] == id && kv["phase"] != "pending" })
		if err != nil {
			return fmt.Errorf("the firewall helper did not finish: %w", err)
		}
	}
	if r["ok"] != "1" {
		msg := r["error"]
		if msg == "" {
			msg = "unknown error"
		}
		return fmt.Errorf("changing the firewall failed: %s", msg)
	}
	return nil
}

// reachesControlPlane checks the agent still reaches the control plane (an
// empty security report: answered, changes nothing).
func (a *Agent) reachesControlPlane(ctx context.Context) error {
	return a.client.post(ctx, "/v1/agent/security", protocol.SecurityReportBatch{}, &protocol.SecurityAck{})
}

// waitHelper waits for a helper answer that matches.
func waitHelper(ctx context.Context, path string, match func(map[string]string) bool) (map[string]string, error) {
	deadline := time.Now().Add(firewallTimeout)
	for {
		if data, err := os.ReadFile(path); err == nil {
			if kv := parseKeyValues(string(data)); match(kv) {
				return kv, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no answer within %s", firewallTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(restartPoll):
		}
	}
}

func newFirewallID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// firewallDone removes the agent's request files: the helper never does.
func (a *Agent) firewallDone() {
	for _, f := range []string{"request", "addresses", "ssh-addresses", "confirm"} {
		_ = os.Remove(filepath.Join(a.firewallDir(), f))
	}
}

// firewallRefresh asks the helper to check its rules are still loaded and
// returns the fresh port-PORT file (ok false when the helper didn't answer).
func (a *Agent) firewallRefresh(port int) ([]byte, bool) {
	if !firewallMu.TryLock() {
		return nil, false // a change is on its way
	}
	defer firewallMu.Unlock()
	defer a.firewallDone()
	id := newFirewallID()
	if err := writeFileAtomic(filepath.Join(a.firewallDir(), "request"), fmt.Appendf(nil, "%s %s %d\n", id, fwStatus, port), 0o600); err != nil {
		return nil, false
	}
	deadline := time.Now().Add(firewallStatusWait)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(filepath.Join(firewallResultDir, "result")); err == nil && parseKeyValues(string(data))["id"] == id {
			fresh, err := os.ReadFile(filepath.Join(firewallResultDir, "port-"+strconv.Itoa(port)))
			if err != nil {
				return []byte("loaded=0\n"), true
			}
			return fresh, true
		}
		time.Sleep(restartPoll)
	}
	return nil, false
}

// databaseReachable checks the agent still reaches the database: a
// connection for PostgreSQL, a monitoring sample for the other engines.
func (a *Agent) databaseReachable(ctx context.Context, db protocol.DatabaseSpec) error {
	if isPostgres(db) {
		c, err := a.securityTarget(db).Connect(ctx, "postgres")
		if err == nil {
			_ = c.Close(ctx)
		}
		return err
	}
	name := protocol.NormalizeEngine(db.Engine)
	e := engineFor(name)
	if e == nil {
		return unsupportedEngine(name)
	}
	_, err := e.Monitor(ctx, a.engineEnv(name), db)
	return err
}
