package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// A server set up without an account, from this computer, over SSH:
// `rowsafe add shop ssh://root@db1.example.com` saves the server's
// database by name (no connection string: it stays on the server), and
// then status, mark, backups, restore, rewind, proof, alerts, channels and
// mcp reach the agent's own control plane through the person's own ssh
// (client/ssh.go). pulse, fix and the other direct commands run on the
// server with its rowsafe CLI. Nothing listens on the network.

// sshVia is the saved server this command runs on, if any.
var sshVia *savedDB

// sshValueFlags are the flags that take a value, so the value isn't
// mistaken for a saved server's name.
var sshValueFlags = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(`access add address after allow at auto check cloud column connect-host cpus database day db
		delete-after diff-schedule disk dismiss engine engine-version exclude expires extension extensions f fail-on file fingerprint
		folder for format fresh from from-env full-schedule full-text group host hour hours i id identity index into into-port keep-days
		key keys kind kinds label limit listen locale mark max-client-conn max-data-loss memory method min-rows min-severity mode name
		new-owner note on outside-check owner p password-env path pool-size port postgres proof-schedule query reason reassign-to region
		remove restore retention-full role schema search secret-env send set severity since site size socket-dir sort source source-env
		server ssh status table template token topic api-key bot-token chat-id routing-key threshold timeout timezone to ttl type url user username version width workload
		as endpoint bucket uri-style path-prefix ca-file primary grep every snapshot turso d1`) {
		m[f] = true
	}
	return m
}()

// sshNoNameCommands don't take a database: the saved server's name only
// says where they run, and is dropped from their arguments.
var sshNoNameCommands = map[string]bool{"alerts": true, "channels": true, "task": true, "whoami": true, "hosts": true, "mcp": true, "ls": true}

// sshForwarded run on the server with its own rowsafe CLI: they work on
// the database's connection string, which never leaves the server.
func sshForwarded(cmd string) bool {
	_, direct := localCommands[cmd]
	return (direct && cmd != "mcp") || cmd == "schema" || cmd == "explain"
}

// sshNameArg is the index in args of a saved server's name, or -1.
func sshNameArg(args []string, servers []savedDB) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return -1
		}
		if strings.HasPrefix(a, "-") {
			if n := strings.TrimLeft(a, "-"); !strings.Contains(n, "=") && sshValueFlags[n] {
				i++
			}
			continue
		}
		if _, ok := findSaved(servers, a); ok {
			return i
		}
	}
	return -1
}

// sshRoute finds the saved server a command runs on: its name among the
// arguments (replaced by the database's name on the server, or dropped),
// else the project's database when it is a saved server. Logged in, an
// account database by the same name wins, as for saved connection strings.
// explicit is false when the name came from the project.
func sshRoute(cmd string, args []string, loggedIn bool) (s *savedDB, rest []string, explicit, ok bool, err error) {
	dbs, err := loadSaved()
	if err != nil {
		return nil, nil, false, false, nil // the command says it, if it needs them
	}
	servers := slices.DeleteFunc(dbs, func(d savedDB) bool { return d.SSH == nil })
	if len(servers) == 0 {
		return nil, args, false, false, nil
	}
	if i := sshNameArg(args, servers); i >= 0 {
		found, _ := findSaved(servers, args[i])
		if loggedIn && accountHas(found.Name) {
			return nil, args, false, false, nil
		}
		rest = append([]string{}, args[:i]...)
		if !sshNoNameCommands[cmd] {
			rest = append(rest, found.serverDB())
		}
		return &found, append(rest, args[i+1:]...), true, true, nil
	}
	if name, _ := projectDatabase(); name != "" {
		if found, ok := findSaved(servers, name); ok && (!loggedIn || !accountHas(name)) {
			return &found, args, false, true, nil
		}
	}
	return nil, args, false, false, nil
}

// serverDB is the saved server's database name on the server.
func (s savedDB) serverDB() string { return cmp.Or(s.Server, s.Name) }

// runOverSSH runs a command on a saved server.
func runOverSSH(ctx context.Context, s *savedDB, cmd string, args []string, explicit bool, cfg config) error {
	sshVia = s
	if cmd == "preview" {
		return fmt.Errorf("rowsafe preview reads the migration file on this computer, so it doesn't run over SSH yet: "+
			"copy the file to %s and run sudo rowsafe preview %s FILE there", s.SSH.Host, s.serverDB())
	}
	if sshForwarded(cmd) {
		if !explicit {
			at := 0
			if cmd == "settings" && len(args) > 0 && (args[0] == "set" || args[0] == "undo") {
				at = 1
			}
			args = slices.Insert(slices.Clone(args), at, s.serverDB())
		}
		return sshForward(ctx, s, cmd, args)
	}
	c := client.NewSSH(*s.SSH, client.SSHOptions{Interactive: stdinIsTerminal() && cmd != "mcp"})
	defer c.HTTP.CloseIdleConnections()
	onServer = true // the server's own control plane, as with sudo rowsafe there
	return runCommand(ctx, c, cfg, cmd, args)
}

// sshForward runs `rowsafe CMD ARGS...` on the server as root, with this
// terminal (ssh -t) when there is one.
func sshForward(ctx context.Context, s *savedDB, cmd string, args []string) error {
	tty := stdinIsTerminal() && term.IsTerminal(int(os.Stdout.Fd())) && !jsonMode
	sudo := "-n" // nothing may ask without a terminal
	if tty {
		sudo = "" // sudo may ask for the password on this terminal
	}
	remote := client.RemoteCommand(sudo, client.RemoteCLI, append([]string{cmd}, args...)...)
	argv, err := client.SSHArgs(*s.SSH, client.SSHOptions{Interactive: stdinIsTerminal(), TTY: tty}, remote)
	if err != nil {
		return err
	}
	run := exec.CommandContext(ctx, argv[0], argv[1:]...)
	run.Stdin, run.Stderr = os.Stdin, os.Stderr
	run.Stdout = os.Stdout
	if jsonMode {
		run.Stdout = jsonWriter() // the server's rowsafe prints the JSON
	}
	err = run.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee) && ee.ExitCode() == 255:
		return fmt.Errorf("ssh %s failed (above); check that `ssh %s` works from this computer", s.SSH.Dest(), s.SSH.Dest())
	case errors.As(err, &ee) && ee.ExitCode() > 0:
		return exitError(ee.ExitCode()) // the server's rowsafe said what happened
	case err != nil:
		return fmt.Errorf("running ssh: %w", err)
	}
	return nil
}

// sshAdd saves a database on a server reached over SSH: rowsafe add NAME
// ssh://USER@HOST [--database DB]. It checks that the server's agent
// protects that database (read-only), unless --no-check.
func sshAdd(ctx context.Context, name, addr, database string, noCheck, yes, asJSON bool) error {
	if name == "" {
		return newUsageError("usage: rowsafe add NAME ssh://USER@HOST")
	}
	t, err := client.ParseSSHTarget(addr)
	if err != nil {
		return newUsageError(err.Error())
	}
	s := savedDB{Name: name, SSH: &t, Server: cmp.Or(database, name), Added: time.Now().UTC().Truncate(time.Second)}
	res := savedAddResult{savedView: viewSaved(s)}
	if !noCheck {
		say(asJSON, "Connecting to %s over SSH (read-only)...\n", t.Dest())
		c := client.NewSSH(t, client.SSHOptions{Interactive: stdinIsTerminal()})
		defer c.HTTP.CloseIdleConnections()
		sshVia = &s // for explain's words
		dbs, err := c.Databases(ctx)
		sshVia = nil
		if err != nil {
			return fmt.Errorf("%s\nNot saved", explain(err))
		}
		d, err := pickServerDatabase(dbs, name, database, t)
		if err != nil {
			return err
		}
		s.Server = d.Name
		res.savedView = viewSaved(s)
		res.Server = &serverProtection{Name: d.Name, Status: d.Status}
		res.Version = d.EngineVersion
	}
	dbs, err := loadSaved()
	if err != nil {
		return err
	}
	if old, found := findSaved(dbs, name); found && (old.SSH == nil || *old.SSH != t || old.serverDB() != s.Server) {
		if err := confirmChange(yes, fmt.Sprintf("%s is already saved (%s). Replace it?", name, viewSaved(old).describe())); err != nil {
			return err
		}
	}
	dbs = slices.DeleteFunc(dbs, func(d savedDB) bool { return d.Name == name })
	if res.File, err = storeSaved(append(dbs, s)); err != nil {
		return err
	}
	if asJSON {
		return printJSON(res)
	}
	status := ""
	if res.Server != nil {
		status = " Rowsafe protects it there (" + res.Server.Status + ")."
	}
	fmt.Printf("%s %s.%s\n", green("Saved "+name+":"), res.describe(), status)
	fmt.Printf("Only the server's address is saved here (%s); the connection string stays on the server.\n", res.File)
	fmt.Printf("\n%s %s   %s\n", bold("Next:"), cyan("rowsafe status "+name),
		dim("(then: rowsafe mark "+name+" LABEL, rowsafe restore "+name+" --to TIME, rowsafe mcp "+name+" for AI agents)"))
	return nil
}

// pickServerDatabase is the server's database rowsafe add saves: the one
// --database names, the one named like the saved name, or the only one.
func pickServerDatabase(dbs []protocol.Database, name, want string, t client.SSHTarget) (protocol.Database, error) {
	if len(dbs) == 0 {
		return protocol.Database{}, fmt.Errorf("Rowsafe on %s doesn't protect a database yet. On the server, save it once so Rowsafe protects it:\n"+
			"  ssh -t %s sudo rowsafe add %s postgresql:///DBNAME\nthen run this again. Not saved", t.Host, t.Dest(), name)
	}
	for _, d := range dbs {
		if d.Name == cmp.Or(want, name) || (want != "" && d.ID == want) {
			return d, nil
		}
	}
	if want == "" && len(dbs) == 1 {
		return dbs[0], nil
	}
	names := make([]string, len(dbs))
	for i, d := range dbs {
		names[i] = d.Name
	}
	if want != "" {
		return protocol.Database{}, fmt.Errorf("Rowsafe on %s has no database named %s (it has %s). Not saved", t.Host, want, strings.Join(names, ", "))
	}
	return protocol.Database{}, usageErrorf("Rowsafe on %s protects %d databases: %s. Say which one: rowsafe add %s %s --database %s",
		t.Host, len(dbs), strings.Join(names, ", "), name, t.String(), names[0])
}

// sshProjectServer is the project's database when it is a saved server
// (and, logged in, not also one of the account's).
func sshProjectServer(name string, loggedIn bool) *savedDB {
	if name == "" {
		return nil
	}
	dbs, _ := loadSaved()
	s, ok := findSaved(dbs, name)
	if !ok || s.SSH == nil || (loggedIn && accountHas(name)) {
		return nil
	}
	return &s
}
