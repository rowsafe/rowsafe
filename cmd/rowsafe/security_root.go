package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Security fixes by finding, and root's yes on the server itself.
//
// What touches the server and not only the database (the firewall, the
// restart listen_local needs) runs only when root allowed it on that server
// (sudo rowsafe-allow NAME). On the server, `sudo rowsafe` runs as root: when
// a fix waits for root's yes, root at this terminal is asked, and saying yes
// runs rowsafe-allow, so the allow files stay the one place that says what
// Rowsafe may do there (and `sudo rowsafe-allow --remove NAME` takes it
// back). --yes never answers this question.

// allowCommand is root's command that changes what Rowsafe may do here.
var allowCommand = "/usr/local/sbin/rowsafe-allow"

// allowSettle is how long the agent may take to see root's yes.
var allowSettle = 2 * time.Minute

var allowRE = regexp.MustCompile(`sudo rowsafe-allow ([a-z-]+)`)

// isFindingID reports whether s names a security finding (security_tls_off).
func isFindingID(s string) bool { return strings.HasPrefix(s, "security_") }

// findingAction is the security action that fixes f, and whether it needs
// TLS required: its own fix, else the first step for who may connect.
func findingAction(f protocol.Finding) (string, bool) {
	for _, fx := range f.Fixes {
		if fx.Kind != protocol.FixSecurity {
			continue
		}
		var p protocol.SecurityFixParams
		if json.Unmarshal(fx.Params, &p) == nil && p.Action != "" {
			return p.Action, p.RequireTLS
		}
	}
	switch f.ID {
	case "security_trust_open", "security_open_internet", "security_open_rules":
		return protocol.SecRestrictAccess, false
	case "security_md5_passwords":
		return protocol.SecSetPassword, false
	}
	return "", false
}

// allowAsRoot handles an action that can't run now: when what stands in the
// way is a permission root hasn't given and this is root on the server, it
// asks, allows it with rowsafe-allow and waits until the agent sees it. It
// returns the fresh view, or why the action can't run.
func allowAsRoot(ctx context.Context, c *client.Client, name, action, reason string, asJSON bool) (protocol.SecurityView, error) {
	cant := fmt.Errorf("%s can't run now: %s", action, orText(reason, "Rowsafe didn't say why"))
	m := allowRE.FindStringSubmatch(reason)
	if m == nil || !onServer {
		return protocol.SecurityView{}, cant
	}
	perm := m[1]
	if !protocol.IsPermission(perm) {
		return protocol.SecurityView{}, cant
	}
	if !isRoot() {
		return protocol.SecurityView{}, fmt.Errorf("%w\nRun it as root to be asked: sudo rowsafe security fix %s %s", cant, name, action)
	}
	if st, err := os.Stat(allowCommand); err != nil || !st.Mode().IsRegular() {
		return protocol.SecurityView{}, fmt.Errorf("%w\n%s isn't installed here; the Rowsafe installer allows it with --allow-%s", cant, allowCommand, perm)
	}
	out := msgOut(asJSON)
	fmt.Fprintf(out, "%s\nYou are root on this server. Allow it now? It stays allowed until root takes it back (sudo rowsafe-allow --remove %s).\n", reason, perm)
	if err := confirmTypedAs(false, perm, fmt.Sprintf("Type %s to allow it: ", perm)); err != nil {
		if errors.Is(err, errNoTerminal) {
			return protocol.SecurityView{}, fmt.Errorf("%w\n(only root at a terminal can allow it; --yes doesn't)", cant)
		}
		return protocol.SecurityView{}, err
	}
	cmd := exec.CommandContext(ctx, allowCommand, perm)
	cmd.Stdout, cmd.Stderr = out, os.Stderr
	if err := cmd.Run(); err != nil {
		return protocol.SecurityView{}, fmt.Errorf("rowsafe-allow %s failed (%v); nothing else changed", perm, err)
	}
	fmt.Fprintf(out, "Allowed. Waiting for the agent to see it...\n")
	deadline := time.Now().Add(allowSettle)
	for {
		// A fresh scan: the agent reads root's allow files as it goes.
		if resp, err := c.CheckSecurity(ctx, name); err == nil && resp.Task != nil {
			if _, err := waitTasks(ctx, c, []protocol.TaskView{*resp.Task}, true); err != nil {
				return protocol.SecurityView{}, err
			}
		}
		v, err := c.Security(ctx, name)
		if err != nil {
			return v, apiErr(err)
		}
		i := slices.IndexFunc(v.Actions, func(a protocol.SecurityActionState) bool { return a.Action == action })
		if i >= 0 && v.Actions[i].Available {
			return v, nil
		}
		if time.Now().After(deadline) {
			why := reason
			if i >= 0 {
				why = v.Actions[i].Reason
			}
			return v, fmt.Errorf("root allowed %s, but %s still can't run: %s", perm, action, orText(why, "Rowsafe didn't say why"))
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
