package main

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe security: who can reach a database and how they log in (Pulse,
// Security), and the dashboard's security actions. A new password is made
// here and only its SCRAM verifier is sent; a password the server makes
// (Redis, Valkey) is sealed to this terminal. Rowsafe never sees either.

var securitySubs = map[string]subcommand{
	"check": securityCheckCmd,
	"set":   securitySetCmd,
	"fix":   securityFixCmd,
}

func securityCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := securitySubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return securityShowCmd(ctx, c, args)
}

// securityActionText is each action in plain words, and what it needs.
var securityActionText = map[string]string{
	protocol.SecRestrictAccess:         "let only --allow addresses log in (pg_hba; --require-tls too)",
	protocol.SecUndoRestrictAccess:     "put back the login rules from before restrict_access",
	protocol.SecEnableTLS:              "turn on encrypted connections (TLS)",
	protocol.SecRenewCertificate:       "renew the self-signed TLS certificate",
	protocol.SecScramPasswords:         "store new passwords as SCRAM-SHA-256",
	protocol.SecSetPassword:            "a new password for --role (made here; Rowsafe never sees it)",
	protocol.SecRevokePublicCreate:     "stop every user creating objects in schema public",
	protocol.SecListenLocal:            "listen on this server only (takes effect at a restart)",
	protocol.SecFirewall:               "let only --allow addresses reach the port (server firewall)",
	protocol.SecFirewallOff:            "remove Rowsafe's firewall rule for the port",
	protocol.SecDropAnonymous:          "remove anonymous accounts (MySQL)",
	protocol.SecDropTestDatabase:       "remove the empty sample test database (MySQL)",
	protocol.SecSQLiteModes:            "close the database files to other users (SQLite)",
	protocol.SecRedisProtectedMode:     "turn protected mode on",
	protocol.SecRedisRequirePassword:   "a new password for the default user (shown here once)",
	protocol.SecRedisDangerousCommands: "take dangerous commands away from --role",
	protocol.SecRedisNoScripts:         "take scripts away from --role",
}

func securityShowCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("security", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	v, err := c.Security(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(v)
	}
	printSecurity(v)
	return nil
}

func printSecurity(v protocol.SecurityView) {
	if !v.Available {
		fmt.Printf("%s: no security check yet. %s\n", v.Database, v.Reason)
		return
	}
	fmt.Printf("%s on %s: security %s (%d/100)", v.Database, v.Host, orDash(v.Grade), v.Score)
	if v.Summary != "" {
		fmt.Printf(", %s", v.Summary)
	}
	fmt.Println()
	if v.ReportedAt != nil {
		fmt.Printf("Checked %s. ", ago(v.ReportedAt))
	}
	fmt.Printf("Checks from the internet: %s\n", map[bool]string{true: "on", false: "off"}[v.OutsideEnabled])
	if len(v.Checks) > 0 {
		fmt.Println()
		t := newTable("STATUS", "CHECK", "DETAIL")
		for _, ck := range v.Checks {
			t.row(ck.Status, ck.Label, firstLine(ck.Detail, 90))
		}
		t.flush()
	}
	for _, o := range v.Outside {
		fmt.Printf("\nFrom the internet, %s: %s", o.Address, strings.ReplaceAll(o.State, "_", " "))
		if o.Detail != "" {
			fmt.Printf(" (%s)", o.Detail)
		}
	}
	if len(v.Outside) > 0 {
		fmt.Println()
	}
	if all := append(slices.Clone(v.Findings), v.Related...); len(all) > 0 {
		fmt.Println("\nFindings:")
		for _, f := range all {
			mark := map[string]string{protocol.SeverityCritical: "!!", protocol.SeverityWarning: "! "}[f.Severity]
			fmt.Printf("  %s %s  (%s)\n", orText(mark, "- "), f.Title, f.ID)
			if f.Action != "" {
				fmt.Printf("     %s\n", f.Action)
			}
		}
	}
	var can, cannot []protocol.SecurityActionState
	for _, a := range v.Actions {
		if a.Available {
			can = append(can, a)
		} else {
			cannot = append(cannot, a)
		}
	}
	if len(can) > 0 {
		fmt.Printf("\nWhat Rowsafe can do now (rowsafe security fix %s ACTION):\n", v.Database)
		for _, a := range can {
			fmt.Printf("  %-26s %s\n", a.Action, securityActionText[a.Action])
		}
	}
	if len(cannot) > 0 && len(can) == 0 {
		fmt.Println("\nNo security action can run now:")
		for _, a := range cannot {
			fmt.Printf("  %-26s %s\n", a.Action, orText(a.Reason, "not available"))
		}
	}
	var seen []string
	for _, s := range v.Suggestions {
		label := s.Address
		if s.Label != "" {
			label += " (" + s.Label + ")"
		}
		seen = append(seen, label)
	}
	if len(seen) > 0 {
		fmt.Printf("\nAddresses to allow: %s\n", strings.Join(seen, ", "))
	}
}

// securityCheckCmd: rowsafe security check [NAME] [--no-wait] [--json]
func securityCheckCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("security check", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once the check is queued")
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	resp, err := c.CheckSecurity(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if resp.Task != nil && !*noWait {
		done, err := waitTasks(ctx, c, []protocol.TaskView{*resp.Task}, *asJSON)
		if err != nil {
			return err
		}
		if t := done[len(done)-1]; t.Status != protocol.StatusSucceeded {
			if *asJSON {
				_ = printJSON(t)
			} else {
				reportTasks(done)
			}
			return exitError(1)
		}
	}
	if *noWait {
		if *asJSON {
			return printJSON(resp)
		}
		if resp.Task != nil {
			fmt.Printf("Checking %s (task %s).", name, resp.Task.ID)
		}
		if resp.OutsideStarted {
			fmt.Print(" A check from the internet started too.")
		}
		fmt.Printf(" See the result with rowsafe security %s\n", name)
		return nil
	}
	v, err := c.Security(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(v)
	}
	printSecurity(v)
	if resp.OutsideStarted {
		fmt.Println("\nA check from the internet is on its way; it shows here in a minute.")
	}
	return nil
}

// securitySetCmd: rowsafe security set [NAME] --outside-check on|off [--json]
func securitySetCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("security set", flag.ContinueOnError)
	outside := fs.String("outside-check", "", "on or off: Rowsafe checks the database's port from the internet")
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *outside == "" {
		return errors.New("nothing to change: pass --outside-check on|off")
	}
	on, err := onOff("outside-check", *outside)
	if err != nil {
		return err
	}
	v, err := c.UpdateSecuritySettings(ctx, name, protocol.UpdateSecuritySettingsRequest{OutsideCheck: &on})
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(v)
	}
	fmt.Printf("%s: checks from the internet are %s.\n", name, map[bool]string{true: "on", false: "off"}[v.OutsideEnabled])
	return nil
}

// securityFixResult is rowsafe security fix --json's output.
type securityFixResult struct {
	Tasks []protocol.TaskView `json:"tasks"`
	// Role and Password: set_password with a password made here.
	Role     string `json:"role,omitempty"`
	Password string `json:"password,omitempty"`
	// Secret: redis_require_password, opened here.
	Secret *protocol.DBSecret `json:"secret,omitempty"`
}

// securityFixCmd: rowsafe security fix [NAME] ACTION [--allow ADDR]...
// [--require-tls] [--role USER] [--password-env VAR] [--yes] [--no-wait] [--json]
func securityFixCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("security fix", flag.ContinueOnError)
	var allow stringList
	fs.Var(&allow, "allow", "restrict_access, firewall: an address or network that may connect (me, IP or CIDR; repeat or comma-separate)")
	requireTLS := fs.Bool("require-tls", false, "restrict_access, enable_tls: remote logins must use TLS")
	role := fs.String("role", "", "set_password, redis_*: the user")
	passwordEnv := fs.String("password-env", "", "set_password: read the new password from this environment variable (default: make one here)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	noWait := fs.Bool("no-wait", false, "return once the change is queued")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var explicit, action string
	switch len(pos) {
	case 0:
	case 1:
		if _, ok := securityActionText[pos[0]]; ok {
			action = pos[0]
		} else {
			explicit = pos[0]
		}
	case 2:
		explicit, action = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe security fix [NAME] ACTION")
	}
	name, err := resolveDatabase(ctx, c, explicit)
	if err != nil {
		return err
	}
	v, err := c.Security(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if action == "" {
		if *asJSON {
			return printJSON(v.Actions)
		}
		if len(v.Actions) == 0 {
			fmt.Printf("%s: no security actions here. %s\n", name, v.Reason)
			return nil
		}
		t := newTable("ACTION", "NOW", "WHAT IT DOES")
		for _, a := range v.Actions {
			now := "yes"
			if !a.Available {
				now = "no: " + firstLine(orText(a.Reason, "not available"), 60)
			}
			t.row(a.Action, now, securityActionText[a.Action])
		}
		t.flush()
		fmt.Printf("\nRun one: rowsafe security fix %s ACTION\n", name)
		return nil
	}
	i := slices.IndexFunc(v.Actions, func(a protocol.SecurityActionState) bool { return a.Action == action })
	if i < 0 {
		var names []string
		for _, a := range v.Actions {
			names = append(names, a.Action)
		}
		return fmt.Errorf("%s has no security action %q; its actions: %s", name, action, orText(strings.Join(names, ", "), "none"))
	}
	if st := v.Actions[i]; !st.Available {
		return fmt.Errorf("%s can't run now: %s", action, orText(st.Reason, "Rowsafe didn't say why"))
	}

	req := protocol.SecurityActionRequest{Action: action, RequireTLS: *requireTLS, Role: *role, Confirm: name}
	out := msgOut(*asJSON)
	var password string
	switch action {
	case protocol.SecRestrictAccess, protocol.SecFirewall:
		if len(allow) == 0 {
			var seen []string
			for _, s := range v.Suggestions {
				seen = append(seen, s.Address)
			}
			hint := ""
			if len(seen) > 0 {
				hint = " (seen recently: " + strings.Join(seen, ", ") + ")"
			}
			return fmt.Errorf("say who may connect: --allow ADDRESS (me, an IP or a CIDR; repeat it)%s", hint)
		}
		var items []string
		for _, a := range allow {
			items = append(items, strings.Split(a, ",")...)
		}
		if req.AllowedAddresses, err = expandAddresses(ctx, c.BaseURL, items); err != nil {
			return err
		}
		if len(req.AllowedAddresses) == 0 {
			return errors.New("--allow names nobody: give at least one address that may connect")
		}
		fmt.Fprintf(out, "%s: only %s may connect afterwards. Anyone else is cut off.\n", name, strings.Join(req.AllowedAddresses, ", "))
	case protocol.SecSetPassword:
		if *role == "" {
			return errors.New("say whose password: --role USER")
		}
		if *passwordEnv != "" {
			if password, err = readSecret(*passwordEnv, ""); err != nil {
				return err
			}
			if req.Verifier, err = client.CopyVerifier(protocol.EnginePostgreSQL, password); err != nil {
				return err
			}
			password = "" // the person's own: never printed
		} else if password, req.Verifier, err = client.NewCopyPasswordFor(protocol.EnginePostgreSQL); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: a new password for %s. Apps that log in as %s need it afterwards.\n", name, *role, *role)
	default:
		fmt.Fprintf(out, "%s: %s.\n", name, orText(securityActionText[action], action))
	}
	var key *ecdh.PrivateKey
	if action == protocol.SecRedisRequirePassword {
		if key, err = newSealKey(); err != nil {
			return err
		}
		req.PublicKey = protocol.EncodeSealKey(key.PublicKey())
	}
	if err := confirmTyped(*yes, name); err != nil {
		return err
	}
	resp, err := c.SecurityAction(ctx, name, req)
	if err != nil {
		return fmt.Errorf("not changed: %w", apiErr(err))
	}
	if *noWait {
		if password != "" || key != nil {
			return errors.New("queued, but a new password needs the command to wait for it: run it again without --no-wait")
		}
		return finishTasks(ctx, c, resp.Tasks, true, *asJSON)
	}
	if password == "" && key == nil {
		return finishTasks(ctx, c, resp.Tasks, false, *asJSON)
	}
	done, err := waitTasks(ctx, c, resp.Tasks, *asJSON)
	if err != nil {
		return err
	}
	res := securityFixResult{Tasks: done}
	last := done[len(done)-1]
	ok := last.Status == protocol.StatusSucceeded
	if ok && password != "" {
		res.Role, res.Password = *role, password
	}
	if ok && key != nil {
		if res.Secret, err = securitySecret(ctx, c, name, last, key); err != nil {
			return err
		}
	}
	if *asJSON {
		if err := printJSON(res); err != nil {
			return err
		}
	} else {
		reportTasks(done)
		if res.Password != "" {
			fmt.Printf("\nThe new password of %s (save it now: Rowsafe doesn't keep it and can't show it again):\n  %s\n", res.Role, res.Password)
		}
		printSecret(res.Secret)
	}
	if !ok {
		return exitError(1)
	}
	return nil
}

// securitySecret fetches and opens the password a security fix made on the
// server, sealed to key.
func securitySecret(ctx context.Context, c *client.Client, name string, t protocol.TaskView, key *ecdh.PrivateKey) (*protocol.DBSecret, error) {
	sealed, err := c.DBAdminSecret(ctx, name, t.ID)
	if err != nil {
		return nil, fmt.Errorf("the password was set, but fetching it failed (%w); run the fix again for a new one", apiErr(err))
	}
	plain, err := protocol.Open(key, []byte(t.ID), &sealed)
	if err != nil {
		return nil, err
	}
	var s protocol.DBSecret
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ---- the server: security updates and a reboot ----

// securityUpdatesCmd: rowsafe security-updates [NAME] [--yes] [--no-wait] [--json]
func securityUpdatesCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("security-updates", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	noWait := fs.Bool("no-wait", false, "return once the updates are queued")
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	out := msgOut(*asJSON)
	if info.SecurityReason != "" {
		return fmt.Errorf("Rowsafe can't install security updates on %s now: %s", orText(info.Host, name), info.SecurityReason)
	}
	if info.SecurityUpdates == 0 {
		if *asJSON {
			return printJSON([]protocol.TaskView{})
		}
		fmt.Printf("%s: no security updates waiting.\n", orText(info.Host, name))
		return nil
	}
	fmt.Fprintf(out, "Install %d security %s on %s: Rowsafe saves a Mark first; services keep running and %s isn't restarted\n",
		info.SecurityUpdates, plural(info.SecurityUpdates, "update", "updates"), orText(info.Host, name), protocol.EngineDisplayName(info.Engine))
	fmt.Fprintln(out, "(its own packages wait for rowsafe update).")
	if err := confirmTyped(*yes, name); err != nil {
		return err
	}
	resp, err := c.InstallSecurityUpdates(ctx, name, name)
	if err != nil {
		return fmt.Errorf("not installed: %w", apiErr(err))
	}
	return finishTasks(ctx, c, resp.Tasks, *noWait, *asJSON)
}

// rebootCmd: rowsafe reboot [NAME] [--yes] [--no-wait] [--json]
func rebootCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("reboot", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the server's name")
	noWait := fs.Bool("no-wait", false, "return once the reboot is queued")
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	host := info.Host
	if host == "" {
		d, err := c.Database(ctx, name)
		if err != nil {
			return apiErr(err)
		}
		host = d.Hostname
	}
	if info.RebootReason != "" {
		return fmt.Errorf("Rowsafe can't reboot %s now: %s", host, info.RebootReason)
	}
	out := msgOut(*asJSON)
	fmt.Fprintf(out, "Reboot %s: everything on it stops for a minute or two, %s included. Rowsafe saves a Mark first.\n",
		host, protocol.EngineDisplayName(info.Engine))
	if !info.RebootRequired {
		fmt.Fprintln(out, "Nothing on it asks for a reboot right now.")
	}
	if err := confirmTyped(*yes, host); err != nil {
		return err
	}
	resp, err := c.RebootServer(ctx, name, host)
	if err != nil {
		return fmt.Errorf("not rebooted: %w", apiErr(err))
	}
	return finishTasks(ctx, c, resp.Tasks, *noWait, *asJSON)
}
