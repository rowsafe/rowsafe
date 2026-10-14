package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// defaultInstallerURL serves scripts/install.sh to curl. ROWSAFE_INSTALLER_URL
// points elsewhere (a self-hosted control plane, tests).
const defaultInstallerURL = "https://rowsafe.sh"

func installerURL() string {
	if u := strings.TrimSpace(os.Getenv("ROWSAFE_INSTALLER_URL")); u != "" {
		return u
	}
	return defaultInstallerURL
}

// installScript runs the agent installer as root with the enrollment token
// read from a file, so the token never appears in a command line (ps) or a
// shell history: sh -c SCRIPT rowsafe-install TOKEN_FILE [INSTALLER FLAGS...].
// The installer asks its questions on /dev/tty, like curl ... | sudo sh.
func installScript(apiURL string) string {
	env := ""
	if u := strings.TrimRight(apiURL, "/"); u != "" && u != protocol.DefaultAPIURL {
		env = "ROWSAFE_URL=" + shellQuote(u) + "; export ROWSAFE_URL; "
	}
	u := installerURL()
	proto := ""
	if strings.HasPrefix(u, "https://") {
		proto = "--proto '=https' "
	}
	return `f=$1; shift; ROWSAFE_ENROLL_TOKEN=$(cat "$f") || exit 1; rm -f "$f"; export ROWSAFE_ENROLL_TOKEN; ` + env +
		`curl -fsSL ` + proto + shellQuote(u) + ` | sh -s -- "$@"`
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%_+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// rootCommand is the command line that runs installScript as root: directly
// for root, with sudo otherwise (sudo asks for a password on the terminal).
func rootCommand(uid int, apiURL, tokenFile string, installerArgs []string) []string {
	cmd := []string{"sh", "-c", installScript(apiURL), "rowsafe-install", tokenFile}
	cmd = append(cmd, installerArgs...)
	if uid != 0 {
		cmd = append([]string{"sudo"}, cmd...)
	}
	return cmd
}

// sshTarget is where `rowsafe hosts add` connects.
type sshTarget struct {
	dest     string // [USER@]HOST, or a Host from ~/.ssh/config
	port     int
	identity string
	ctlPath  string // the multiplexed connection, so a password is asked once
}

func (s sshTarget) args(tty bool, remote ...string) []string {
	a := []string{"-o", "ControlPath=" + s.ctlPath}
	if s.port != 0 {
		a = append(a, "-p", strconv.Itoa(s.port))
	}
	if s.identity != "" {
		a = append(a, "-i", s.identity)
	}
	if tty {
		a = append(a, "-t")
	}
	a = append(a, "--", s.dest)
	if len(remote) > 0 {
		q := make([]string, len(remote))
		for i, r := range remote {
			q[i] = shellQuote(r)
		}
		a = append(a, strings.Join(q, " "))
	}
	return a
}

func sshBinary() string {
	if b := os.Getenv("ROWSAFE_SSH"); b != "" { // tests
		return b
	}
	return "ssh"
}

// hostsAdd installs the agent on a server: over SSH from this computer, or
// on this Linux server when no server is given. It runs the same installer
// as curl -fsSL https://rowsafe.sh | sudo sh, with a one-time enrollment
// token made for it, so nothing needs approving in the browser.
func hostsAdd(ctx context.Context, c *client.Client, cfg config, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	port := fs.Int("port", 0, "SSH port")
	fs.IntVar(port, "p", 0, "SSH port")
	identity := fs.String("identity", "", "SSH private key file")
	fs.StringVar(identity, "i", "", "SSH private key file")
	// Everything after -- goes to the installer, e.g. -- --storage rowsafe.
	var installerArgs []string
	for i, a := range args {
		if a == "--" {
			args, installerArgs = args[:i], args[i+1:]
			break
		}
	}
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: rowsafe hosts add [USER@]SERVER [-p PORT] [-i KEY] [-- INSTALLER OPTIONS]")
	}
	for _, a := range installerArgs {
		if strings.HasPrefix(a, "rse_") {
			return errors.New("don't pass an enrollment token: rowsafe hosts add makes one for this server")
		}
	}
	if len(pos) == 0 {
		return hostsAddHere(ctx, c, cfg, installerArgs)
	}
	dest := pos[0]
	if strings.HasPrefix(dest, "-") {
		return fmt.Errorf("%q isn't a server: give [USER@]SERVER, e.g. root@203.0.113.10", dest)
	}
	if _, err := exec.LookPath(sshBinary()); err != nil {
		return errors.New("ssh isn't installed on this computer; install OpenSSH, or run `rowsafe hosts enroll-token` and paste its command on the server")
	}

	// /tmp keeps the control socket's path under the 104-byte limit.
	dir, err := os.MkdirTemp("/tmp", "rowsafe-ssh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	t := sshTarget{dest: dest, port: *port, identity: *identity, ctlPath: filepath.Join(dir, "c")}

	// One connection for every step: the password or key passphrase, and a
	// new server's fingerprint, are asked once, here on this terminal.
	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", dest)
	master := exec.CommandContext(ctx, sshBinary(), append([]string{"-M", "-f", "-N", "-o", "ControlPersist=10m"}, t.args(false)...)...)
	master.Stdin, master.Stdout, master.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := master.Run(); err != nil {
		return fmt.Errorf("couldn't connect to %s with ssh: %w", dest, err)
	}
	defer func() {
		_ = exec.Command(sshBinary(), append([]string{"-O", "exit"}, t.args(false)...)...).Run()
	}()

	// What the server is, and who we are there.
	out, err := exec.CommandContext(ctx, sshBinary(), t.args(false, "sh", "-c",
		`printf '%s %s ' "$(uname -s)" "$(id -u)"; command -v curl >/dev/null 2>&1 && echo curl || echo nocurl`)...).Output()
	if err != nil {
		return fmt.Errorf("couldn't run a command on %s: %w", dest, err)
	}
	f := strings.Fields(string(out))
	if len(f) != 3 {
		return fmt.Errorf("unexpected answer from %s: %q", dest, strings.TrimSpace(string(out)))
	}
	if f[0] != "Linux" {
		return fmt.Errorf("%s runs %s: the Rowsafe agent runs on Linux servers", dest, f[0])
	}
	uid, err := strconv.Atoi(f[1])
	if err != nil {
		return fmt.Errorf("unexpected answer from %s: %q", dest, strings.TrimSpace(string(out)))
	}
	if f[2] != "curl" {
		return fmt.Errorf("curl isn't installed on %s; install it there first (e.g. sudo apt install curl)", dest)
	}

	tok, err := c.CreateEnrollmentToken(ctx, 30*time.Minute)
	if err != nil {
		return err
	}
	// The token goes over SSH's stdin into a file only this user can read;
	// the installer reads it and deletes it.
	put := exec.CommandContext(ctx, sshBinary(), t.args(false, "sh", "-c", `umask 077; f=$(mktemp) && cat > "$f" && echo "$f"`)...)
	put.Stdin = strings.NewReader(tok.Token + "\n")
	out, err = put.Output()
	if err != nil {
		return fmt.Errorf("couldn't prepare the install on %s: %w", dest, err)
	}
	tokenFile := strings.TrimSpace(string(out))
	if !strings.HasPrefix(tokenFile, "/") || strings.ContainsAny(tokenFile, " \n'\"") {
		return fmt.Errorf("unexpected answer from %s: %q", dest, tokenFile)
	}
	defer func() { // when the installer stopped before reading it
		_ = exec.Command(sshBinary(), t.args(false, "rm", "-f", tokenFile)...).Run()
	}()

	fmt.Fprintf(os.Stderr, "Installing the Rowsafe agent on %s. It asks before changing anything.\n\n", dest)
	run := exec.CommandContext(ctx, sshBinary(), t.args(true, rootCommand(uid, cfg.URL, tokenFile, installerArgs)...)...)
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := run.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("the installer on %s stopped (exit %d); run the same command again once it's fixed", dest, ee.ExitCode())
		}
		return err
	}
	return nil
}

// hostsAddHere runs the installer on this computer, which must be the Linux
// database server.
func hostsAddHere(ctx context.Context, c *client.Client, cfg config, installerArgs []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("give the server to install on, e.g. rowsafe hosts add root@203.0.113.10 (over SSH from this computer). The Rowsafe agent runs on Linux servers")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return errors.New("curl isn't installed here; install it first (e.g. sudo apt install curl)")
	}
	tok, err := c.CreateEnrollmentToken(ctx, 30*time.Minute)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "rowsafe-enroll-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(tok.Token + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	argv := rootCommand(os.Getuid(), cfg.URL, f.Name(), installerArgs)
	fmt.Fprintln(os.Stderr, "Installing the Rowsafe agent on this server. It asks before changing anything.")
	fmt.Fprintln(os.Stderr)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("the installer stopped (exit %d); run the same command again once it's fixed", ee.ExitCode())
		}
		return err
	}
	return nil
}
