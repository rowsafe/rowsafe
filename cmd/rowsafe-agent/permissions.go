package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/protocol"
)

const permissionsUsage = `rowsafe-agent permissions - who may change this server's permissions from the dashboard

Usage (as root; root's copy is /usr/local/lib/rowsafe/rowsafe-permissions):
  permissions pair              pair a passkey: open the link it prints, then compare codes
  permissions owners            list the paired passkeys
  permissions remove-owner FP   remove the passkey with fingerprint FP
  permissions apply             apply a signed change the agent received
                                (run by rowsafe-permissions.service)
`

// permissionsCmd runs `rowsafe-agent permissions ...`, or root's copy of
// this binary installed as rowsafe-permissions (its argv[0]).
func permissionsCmd(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, permissionsUsage)
		return 2
	}
	if args[0] == "read-as-agent" { // internal: the helper's reader, as the agent user
		return readAsAgent(args[1:])
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(permissionsUsage)
		return 0
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: run this as root (sudo): only root decides what Rowsafe may do on this server")
		return 1
	}
	var err error
	switch args[0] {
	case "pair":
		err = trustedSelf()
		if err == nil {
			err = permissionsPair(ctx)
		}
	case "owners":
		err = permissionsOwners()
	case "remove-owner":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: permissions remove-owner FINGERPRINT")
			return 2
		}
		err = trustedSelf()
		if err == nil {
			err = permissionsRemoveOwner(args[1])
		}
	case "apply":
		err = permissionsApply(ctx)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], permissionsUsage)
		return 2
	}
	if errors.Is(err, permissions.ErrNotPaired) {
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// trustedSelf: root only runs a binary root owns. The agent's own copy in
// /opt/rowsafe belongs to the agent user (it updates itself there), so root
// uses its copy in /usr/local/lib/rowsafe instead.
func trustedSelf() error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	if err := permissions.CheckRootOwned(exe, false); err != nil {
		return fmt.Errorf("refusing to run as root from a binary only root should change (%v); use %s, which the installer keeps",
			err, permissions.DefaultHelper)
	}
	return nil
}

func envFile() map[string]string {
	data, err := permissions.ReadSmallFile(permissions.AgentEnvFile, 1<<20, false)
	if err != nil {
		return map[string]string{}
	}
	return permissions.ParseEnvFile(data)
}

func permissionsPair(ctx context.Context) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("pairing must be confirmed by a person at this server: run it on a terminal (for example over ssh)")
	}
	defer tty.Close()
	env := envFile()
	rpID, origin, err := permissions.RPFromEnv(env)
	if err != nil {
		return err
	}
	controlURL := strings.TrimRight(env["ROWSAFE_URL"], "/")
	if controlURL == "" {
		controlURL = protocol.DefaultAPIURL
	}
	if !strings.HasPrefix(controlURL, "https://") && !strings.HasPrefix(controlURL, "http://127.0.0.1") &&
		!strings.HasPrefix(controlURL, "http://localhost") {
		return errors.New("ROWSAFE_URL must use https")
	}
	stateDir := env["ROWSAFE_STATE_DIR"]
	if stateDir == "" {
		stateDir = "/var/lib/rowsafe"
	}
	data, err := permissions.ReadSmallFile(filepath.Join(stateDir, "agent.json"), 64<<10, false)
	if err != nil {
		return errors.New("this server isn't connected to Rowsafe yet (the agent connects when it first starts)")
	}
	var st struct {
		HostID     string `json:"host_id"`
		AgentToken string `json:"agent_token"`
	}
	if json.Unmarshal(data, &st) != nil || st.HostID == "" || st.AgentToken == "" {
		return errors.New("the agent's identity is unreadable")
	}
	p := &permissions.Pairer{
		ControlURL: controlURL, Token: st.AgentToken, HostID: st.HostID,
		RPID: rpID, Origin: origin, OwnersFile: permissions.OwnersFile,
		HTTP: &http.Client{Timeout: 30 * time.Second}, TTY: tty,
		Now: time.Now, Poll: 2 * time.Second, MaxWait: 15 * time.Minute,
	}
	_, err = p.Pair(ctx)
	return err
}

func permissionsOwners() error {
	owners, err := permissions.ReadOwners(permissions.OwnersFile, true)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		fmt.Println("No passkey is paired with this server: its permissions can only be changed here, as root.")
		return nil
	}
	fmt.Println("Passkeys that can change this server's permissions from the Rowsafe dashboard:")
	for _, o := range owners {
		fmt.Printf("  %s  %s  added %s\n", o.Fingerprint, o.Name, o.AddedAt.Local().Format("2006-01-02"))
	}
	return nil
}

func permissionsRemoveOwner(fp string) error {
	owners, err := permissions.ReadOwners(permissions.OwnersFile, true)
	if err != nil {
		return err
	}
	i := permissions.FindOwner(owners, fp)
	if i < 0 {
		return fmt.Errorf("no paired passkey has the fingerprint %s", fp)
	}
	o := owners[i]
	owners = append(owners[:i], owners[i+1:]...)
	if err := permissions.WriteOwners(permissions.OwnersFile, owners); err != nil {
		return err
	}
	fmt.Printf("Removed the passkey %s (%s): it can no longer change this server's permissions.\n", o.Fingerprint, o.Name)
	return nil
}

// permissionsApply is rowsafe-permissions.service's entry point.
func permissionsApply(ctx context.Context) error {
	if err := trustedSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "rowsafe-permissions: refused:", err)
		return err
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	read, err := permissions.ReadAsAgentFunc(getenv("ROWSAFE_AGENT_USER", "postgres"))
	if err != nil {
		return err
	}
	h := &permissions.Helper{
		RequestPath:  filepath.Join(getenv("ROWSAFE_PERMISSIONS_REQUEST_DIR", permissions.DefaultRequestDir), permissions.RequestName),
		AnswerDir:    getenv("RUNTIME_DIRECTORY", permissions.DefaultAnswerDir),
		StateDir:     getenv("STATE_DIRECTORY", permissions.DefaultStateDir),
		OwnersFile:   permissions.OwnersFile,
		AgentState:   getenv("ROWSAFE_AGENT_STATE", permissions.DefaultAgentState),
		Installer:    permissions.DefaultInstaller,
		Log:          os.Stderr,
		Now:          time.Now,
		ReadAsAgent:  read,
		RunInstaller: permissions.RunInstaller,
	}
	return h.Apply(ctx)
}

// readAsAgent: `read-as-agent [--max N] [--remove] -- PATH`, run by the
// helper with the agent user's privileges; prints the file.
func readAsAgent(args []string) int {
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "read-as-agent never runs as root")
		return 1
	}
	fs := flag.NewFlagSet("read-as-agent", flag.ContinueOnError)
	max := fs.Int64("max", permissions.MaxRequest, "")
	remove := fs.Bool("remove", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *max <= 0 || *max > 1<<20 {
		return 2
	}
	data, err := permissions.ReadSmallFile(fs.Arg(0), *max, *remove)
	if errors.Is(err, permissions.ErrNoFile) {
		return permissions.ExitNoFile
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, _ = os.Stdout.Write(data)
	return 0
}
