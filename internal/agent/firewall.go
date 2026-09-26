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
	f, err := os.Open(firewallAllowFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[int]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if p, err := strconv.Atoi(fields[0]); err == nil && p > 0 && p < 65536 {
			out[p] = true
		}
	}
	return out, sc.Err()
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
		st.Allowed, st.Reason = false, "The firewall helper is not set up on this server: run the installer again with --allow-firewall."
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
		return errors.New(st.Reason + " To allow it, run the Rowsafe installer on this server again with --allow-firewall.")
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
	firewallMu.Lock()
	defer firewallMu.Unlock()
	id := newFirewallID()
	dir := a.firewallDir()
	defer a.firewallDone()
	if action == fwApply {
		if err := writeFileAtomic(filepath.Join(dir, "addresses"), []byte(strings.Join(addrs, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(dir, "confirm"))
	tl.Printf("asking the firewall helper to %s the rule for port %d", action, db.Port)
	if err := writeFileAtomic(filepath.Join(dir, "request"), fmt.Appendf(nil, "%s %s %d\n", id, action, db.Port), 0o600); err != nil {
		return err
	}
	resPath := filepath.Join(firewallResultDir, "result")
	r, err := waitHelper(ctx, resPath, func(kv map[string]string) bool { return kv["id"] == id })
	if err != nil {
		_ = os.Remove(filepath.Join(dir, "request"))
		return fmt.Errorf("the firewall helper did not answer: %w (check `systemctl status rowsafe-firewall.path`)", err)
	}
	if r["phase"] == "pending" {
		// The rule is in place: confirm only if Rowsafe and PostgreSQL are
		// still reachable, else the helper rolls it back by itself.
		tl.Printf("rule in place; checking the agent still reaches Rowsafe and PostgreSQL")
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.client.post(cctx, "/v1/agent/security", protocol.SecurityReportBatch{}, &protocol.SecurityAck{})
		if err == nil {
			var c interface{ Close(context.Context) error }
			if c, err = a.securityTarget(db).Connect(cctx, "postgres"); err == nil {
				_ = c.Close(cctx)
			}
		}
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
	if action == fwApply {
		res.Summary = fmt.Sprintf("The firewall lets only %s reach PostgreSQL's port %d now. SSH and other ports are unchanged.", strings.Join(addrs, ", "), db.Port)
	} else {
		res.Summary = fmt.Sprintf("Rowsafe's firewall rule for port %d is removed.", db.Port)
	}
	tl.Printf("%s", res.Summary)
	return nil
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
	for _, f := range []string{"request", "addresses", "confirm"} {
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
