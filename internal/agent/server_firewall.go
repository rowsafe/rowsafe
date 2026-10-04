package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// The server's own firewall (protocol.TaskServerFirewall), on servers
// Rowsafe created where the cloud's firewall can't be used. Root allowed it
// at install (--allow-firewall --firewall-ssh: the line "ssh" in
// /etc/rowsafe/firewall-allowed); the agent hands both allow lists to the
// root helper, which sets them in one nftables transaction:
//
//	<state dir>/firewall/addresses       PostgreSQL's allow list, one CIDR per line (may be empty)
//	<state dir>/firewall/ssh-addresses   SSH's allow list (may be empty)
//	<state dir>/firewall/request         "ID server PORT"
//	/run/rowsafe-firewall/ssh            what SSH's rule lets through: addresses, ports, applied_at, loaded
//
// The agent never cuts itself off: it only dials out (to the control plane
// and the backup storage), and the helper always lets loopback and replies
// to connections already made through. The helper keeps the new rules only
// once the agent confirmed it still reaches the control plane.

// fwServer is the helper's action for both allow lists.
const fwServer = "server"

// serverFirewallTask decodes and runs a server_firewall task.
func (a *Agent) serverFirewallTask(ctx context.Context, task *protocol.Task, tl *taskLog) (any, error) {
	var p protocol.ServerFirewallParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
	}
	res, err := a.serverFirewall(ctx, p, tl)
	if res == nil {
		return nil, err
	}
	return res, err
}

func (a *Agent) serverFirewall(ctx context.Context, p protocol.ServerFirewallParams, tl *taskLog) (*protocol.ServerFirewallResult, error) {
	if a.cfg.Sidecar() {
		return nil, errors.New("this agent runs in Docker, where the server's firewall isn't Rowsafe's to set")
	}
	pg, err := parseFirewallSources("PostgreSQL", p.Postgres)
	if err != nil {
		return nil, err
	}
	ssh, err := parseFirewallSources("SSH", p.SSH)
	if err != nil {
		return nil, err
	}
	ports, sshAllowed, err := firewallAllowList()
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", firewallAllowFile, err)
	}
	if !sshAllowed {
		return nil, errors.New("root didn't let Rowsafe set who may reach SSH on this server (the installer's --firewall-ssh, used only on servers Rowsafe creates)")
	}
	port := p.Port
	if port == 0 {
		if len(ports) != 1 {
			return nil, fmt.Errorf("root's firewall allow list (%s) has %d PostgreSQL ports: say which one", firewallAllowFile, len(ports))
		}
		for port = range ports {
		}
	}
	if !ports[port] {
		return nil, fmt.Errorf("port %d is not in root's firewall allow list (%s)", port, firewallAllowFile)
	}
	if _, err := os.Stat(a.firewallDir()); err != nil {
		return nil, errors.New("the firewall helper is not set up on this server: root sets it up with the installer's --allow-firewall --firewall-ssh")
	}
	tl.Printf("asking the firewall helper to let %s reach PostgreSQL (port %d) and %s reach SSH",
		sourcesLog(pg), port, sourcesLog(ssh))
	firewallMu.Lock()
	defer firewallMu.Unlock()
	err = a.firewallRequest(ctx, fwServer, port, map[string][]string{"addresses": pg, "ssh-addresses": ssh},
		func(ctx context.Context) error {
			tl.Printf("rules in place; checking the agent still reaches Rowsafe")
			return a.reachesControlPlane(ctx)
		}, tl)
	if err != nil {
		return nil, err
	}
	res := &protocol.ServerFirewallResult{Port: port, Postgres: pg, SSH: ssh}
	if data, err := os.ReadFile(filepath.Join(firewallResultDir, "ssh")); err == nil {
		for _, f := range strings.Split(parseKeyValues(string(data))["ports"], ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n > 0 && n < 65536 {
				res.SSHPorts = append(res.SSHPorts, n)
			}
		}
	}
	res.Summary = serverFirewallSummary(res)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// parseFirewallSources checks an allow list: IPv4/IPv6 addresses (made /32
// or /128) and networks, masked and deduplicated. "0.0.0.0/0" and "::/0"
// mean everyone; other networks wider than /8 (IPv4) or /16 (IPv6) are
// refused, like the helper does.
func parseFirewallSources(what string, in []string) ([]string, error) {
	if len(in) > protocol.MaxServerFirewallSources {
		return nil, fmt.Errorf("too many addresses for %s (%d, at most %d): use networks such as 203.0.113.0/24",
			what, len(in), protocol.MaxServerFirewallSources)
	}
	out := []string{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		var pfx netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			pfx, err = netip.ParsePrefix(s)
		} else {
			var addr netip.Addr
			if addr, err = netip.ParseAddr(s); err == nil {
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if err != nil || !pfx.IsValid() || strings.Contains(s, "%") {
			return nil, fmt.Errorf("%q is not an IP address or network (like 203.0.113.4 or 203.0.113.0/24)", raw)
		}
		pfx = pfx.Masked()
		if pfx.Addr().Is4In6() {
			bits := pfx.Bits() - 96
			if bits < 0 {
				bits = 0
			}
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), bits)
		}
		wide := pfx.Addr().Is4() && pfx.Bits() < 8 || pfx.Addr().Is6() && pfx.Bits() < 16
		if wide && pfx.Bits() != 0 {
			return nil, fmt.Errorf("%s is too wide for %s: use 0.0.0.0/0 (or ::/0) for everyone, or a network of /8 (IPv4) or /16 (IPv6) or narrower", pfx, what)
		}
		if v := pfx.String(); !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return !strings.Contains(out[i], ":") && strings.Contains(out[j], ":") })
	return out, nil
}

func sourcesLog(s []string) string {
	if len(s) == 0 {
		return "no one"
	}
	return strings.Join(s, ", ")
}

// everyone reports whether the list opens the port to every IPv4 and IPv6
// address.
func everyone(s []string) bool {
	return slices.Contains(s, "0.0.0.0/0") && slices.Contains(s, "::/0")
}

func serverFirewallSummary(r *protocol.ServerFirewallResult) string {
	sshPort := "SSH"
	switch len(r.SSHPorts) {
	case 0:
	case 1:
		sshPort = fmt.Sprintf("SSH (port %d)", r.SSHPorts[0])
	default:
		ps := make([]string, len(r.SSHPorts))
		for i, p := range r.SSHPorts {
			ps[i] = strconv.Itoa(p)
		}
		sshPort = "SSH (ports " + strings.Join(ps, ", ") + ")"
	}
	part := func(list []string, what string) string {
		switch {
		case len(list) == 0:
			return "no one but this server can reach " + what
		case everyone(list):
			return "anyone can reach " + what
		default:
			return "only " + strings.Join(list, ", ") + " can reach " + what
		}
	}
	s := part(r.Postgres, fmt.Sprintf("PostgreSQL (port %d)", r.Port)) + ", and " + part(r.SSH, sshPort) +
		". Other ports and outgoing connections are unchanged."
	return strings.ToUpper(s[:1]) + s[1:]
}
