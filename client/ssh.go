package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A server without an account, from another computer: each HTTP connection
// is one `ssh SERVER rowsafe-agent control-bridge` (as root, with sudo when
// the login isn't root), whose stdin and stdout carry HTTP to the agent's
// own control plane on its Unix socket. It uses the person's own ssh, with
// their config, keys and known hosts; nothing listens on the network.

// SSHTarget is a server reached over SSH: ssh://[USER@]HOST[:PORT], or
// [USER@]HOST (a Host alias from ~/.ssh/config works too).
type SSHTarget struct {
	User string `json:"user,omitempty"`
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

// ParseSSHTarget reads ssh://[USER@]HOST[:PORT] or [USER@]HOST.
func ParseSSHTarget(s string) (SSHTarget, error) {
	s = strings.TrimSpace(s)
	var t SSHTarget
	bad := fmt.Errorf("%q isn't an SSH address: use ssh://USER@HOST, ssh://USER@HOST:PORT or USER@HOST", s)
	if rest, ok := strings.CutPrefix(s, "ssh://"); ok {
		u, err := url.Parse("ssh://" + rest)
		if err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return t, bad
		}
		if _, set := u.User.Password(); set {
			return t, errors.New("no password in the SSH address: Rowsafe uses your SSH keys and config (ssh-agent, ~/.ssh/config)")
		}
		t.User, t.Host = u.User.Username(), u.Hostname()
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return t, bad
			}
			t.Port = n
		}
	} else {
		if i := strings.LastIndex(s, "@"); i >= 0 {
			t.User, s = s[:i], s[i+1:]
		}
		if v6, ok := strings.CutPrefix(s, "["); ok && strings.HasSuffix(v6, "]") {
			s = strings.TrimSuffix(v6, "]")
		} else if strings.ContainsAny(s, "/:") {
			return t, bad // a port: ssh://USER@HOST:PORT
		}
		t.Host = s
	}
	if !validSSHWord(t.Host) || (t.User != "" && !validSSHWord(t.User)) {
		return SSHTarget{}, bad
	}
	return t, nil
}

// validSSHWord keeps option-like and odd words away from ssh's command line.
func validSSHWord(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || strings.ContainsRune(`'"\$;&|<>(){}*?!#~`+"`", r) {
			return false
		}
	}
	return true
}

// String is the address as ssh://[USER@]HOST[:PORT].
func (t SSHTarget) String() string {
	u := url.URL{Scheme: "ssh", Host: t.Host}
	if strings.Contains(t.Host, ":") {
		u.Host = "[" + t.Host + "]"
	}
	if t.Port != 0 {
		u.Host += ":" + strconv.Itoa(t.Port)
	}
	if t.User != "" {
		u.User = url.User(t.User)
	}
	return u.String()
}

// Dest is the destination ssh takes: [USER@]HOST.
func (t SSHTarget) Dest() string {
	if t.User != "" {
		return t.User + "@" + t.Host
	}
	return t.Host
}

// SSHOptions say how ssh is run.
type SSHOptions struct {
	// Interactive lets ssh ask (a key's passphrase, a new host key) on
	// this terminal; otherwise it never asks (BatchMode).
	Interactive bool
	// TTY gives the remote command a terminal (ssh -t), for a command that
	// asks questions there.
	TTY bool
}

// SSHProgram is the ssh command: $ROWSAFE_SSH (a program and its
// arguments, split at spaces, like GIT_SSH_COMMAND without a shell), else
// ssh from PATH (ssh.exe on Windows).
func SSHProgram() ([]string, error) {
	if v := strings.Fields(os.Getenv("ROWSAFE_SSH")); len(v) > 0 {
		return v, nil
	}
	p, err := exec.LookPath("ssh")
	if err != nil {
		return nil, errors.New("ssh isn't installed on this computer: Rowsafe reaches the server with your own ssh (OpenSSH)")
	}
	return []string{p}, nil
}

// SSHArgs is ssh's command line for running remote (a command for the
// server's shell) on t.
func SSHArgs(t SSHTarget, o SSHOptions, remote string) ([]string, error) {
	prog, err := SSHProgram()
	if err != nil {
		return nil, err
	}
	args := append([]string{}, prog...)
	if o.TTY {
		args = append(args, "-t")
	} else {
		args = append(args, "-T")
	}
	args = append(args, "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3")
	if !o.Interactive {
		args = append(args, "-o", "BatchMode=yes")
	}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	return append(args, "--", t.Dest(), remote), nil
}

// Programs on the server: the agent (self-updating, always there when the
// agent runs) and the CLI the installer puts next to it.
const (
	RemoteAgent = "/opt/rowsafe/rowsafe-agent"
	RemoteCLI   = "/usr/local/bin/rowsafe"
)

// RemoteCommand is a command for the server's shell that runs prog (or the
// program of that name on PATH) with args as root: directly when the login
// is root, else through sudo (sudoFlags "-n" when nothing may ask for a
// password). It is wrapped in sh -c, so it works from any login shell.
func RemoteCommand(sudoFlags, prog string, args ...string) string {
	script := `p=` + prog + `; [ -x "$p" ] || p=$(command -v "${p##*/}") || ` +
		`{ echo "rowsafe: Rowsafe isn't installed on this server (no ${p##*/}): install it there, https://rowsafe.sh" >&2; exit 127; }; ` +
		`[ "$(id -u)" = 0 ] && exec "$p" "$@"; exec sudo ` + sudoFlags + ` "$p" "$@"`
	words := []string{"sh", "-c", ShellQuote(script), "rowsafe"}
	for _, a := range args {
		words = append(words, ShellQuote(a))
	}
	return strings.Join(words, " ")
}

// ShellQuote quotes s for a POSIX shell (and fish): 'it'\”s'.
func ShellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:,@%+") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BridgeHello is the bridge's first line (internal/localcp's BridgeHello).
const bridgeHello = "rowsafe-bridge 1"

// NewSSH returns a client for the control plane of the agent on t, through
// ssh. Connections close after two idle minutes; the next request opens
// another.
func NewSSH(t SSHTarget, o SSHOptions) *Client {
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return DialSSH(ctx, t, o) },
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     2 * time.Minute,
	}
	return &Client{BaseURL: "http://rowsafe.ssh", APIKey: "local", HTTP: &http.Client{Timeout: 2 * time.Minute, Transport: tr}}
}

// DialSSH starts the bridge on t and returns the connection once the
// bridge says it reached the agent.
func DialSSH(ctx context.Context, t SSHTarget, o SSHOptions) (net.Conn, error) {
	args, err := SSHArgs(t, o, RemoteCommand("-n", RemoteAgent, "control-bridge"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(args[0], args[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	c := &sshConn{target: t, cmd: cmd, w: stdin, stderr: &tailBuffer{max: 4096}, exited: make(chan struct{})}
	cmd.Stderr = c.stderr // ssh asks its questions on the terminal itself
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting ssh: %w", err)
	}
	go func() { c.waitErr = cmd.Wait(); close(c.exited) }()
	c.r = bufio.NewReader(stdout)

	hello := make(chan error, 1)
	go func() {
		line, err := c.r.ReadString('\n')
		switch {
		case err != nil:
			hello <- err
		case strings.TrimSpace(line) != bridgeHello:
			hello <- fmt.Errorf("unexpected answer %q", firstLine(line))
		default:
			hello <- nil
		}
	}()
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()
	select {
	case err = <-hello:
	case <-ctx.Done():
		err = ctx.Err()
	case <-timeout.C:
		err = errors.New("no answer after a minute")
	}
	if err != nil {
		_ = c.Close()
		return nil, c.failure(err)
	}
	return c, nil
}

// SSHError is why ssh or the bridge on the server failed, in plain words.
type SSHError struct{ Msg string }

func (e *SSHError) Error() string { return e.Msg }

// failure explains why the bridge didn't start, from what ssh, sudo and
// the server said.
func (c *sshConn) failure(err error) error {
	return &SSHError{Msg: c.reason(err).Error()}
}

func (c *sshConn) reason(err error) error {
	select {
	case <-c.exited:
	case <-time.After(3 * time.Second):
	}
	said := strings.TrimSpace(c.stderr.String())
	host := c.target.Dest()
	low := strings.ToLower(said)
	switch {
	case strings.Contains(low, "a password is required") || strings.Contains(low, "a terminal is required") ||
		strings.Contains(low, "askpass"):
		user := c.target.User
		if user == "" {
			user = "USER"
		}
		return fmt.Errorf("sudo on %s asks %s for a password, and Rowsafe can't type it. Either connect as root "+
			"(ssh://root@%s), or let %s run Rowsafe's bridge without a password, on the server:\n"+
			"  echo '%s ALL=(root) NOPASSWD: %s control-bridge' | sudo tee /etc/sudoers.d/rowsafe && sudo chmod 0440 /etc/sudoers.d/rowsafe",
			host, user, c.target.Host, user, user, RemoteAgent)
	case strings.Contains(low, "is not in the sudoers") || strings.Contains(low, "not allowed to execute"):
		return fmt.Errorf("%s may not run Rowsafe as root on %s (sudo said: %s). Connect as root, or as a user who may use sudo", c.target.User, c.target.Host, firstLine(said))
	case strings.Contains(low, "host key verification failed"):
		return fmt.Errorf("ssh doesn't know %s's host key yet, and Rowsafe never accepts one for you: connect once yourself (ssh %s) "+
			"and check the fingerprint, then try again", c.target.Host, host)
	case strings.Contains(low, "permission denied (publickey"):
		return fmt.Errorf("ssh couldn't log in to %s with your keys (%s). Check that ssh %s works; without a terminal, ssh can't ask "+
			"for a key's passphrase: load the key into ssh-agent (ssh-add)", c.target.Host, firstLine(said), host)
	case strings.Contains(said, `unknown command "control-bridge"`):
		return fmt.Errorf("the Rowsafe agent on %s is older than this CLI and can't be reached over SSH yet. It updates itself "+
			"(usually within a day); to update now, run the install command again on the server", c.target.Host)
	case strings.HasPrefix(firstLine(said), "rowsafe: "):
		return fmt.Errorf("on %s: %s", c.target.Host, strings.TrimPrefix(firstLine(said), "rowsafe: "))
	case said != "":
		return fmt.Errorf("ssh %s: %s", host, lastLines(said, 3))
	case c.waitErr != nil:
		return fmt.Errorf("ssh %s: %v", host, c.waitErr)
	}
	return fmt.Errorf("ssh %s: %v", host, err)
}

// sshConn is one bridge: a net.Conn over ssh's stdin and stdout.
type sshConn struct {
	target  SSHTarget
	cmd     *exec.Cmd
	r       *bufio.Reader
	w       io.WriteCloser
	stderr  *tailBuffer
	exited  chan struct{}
	waitErr error
	once    sync.Once
}

func (c *sshConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if errors.Is(err, io.EOF) && n == 0 {
		select {
		case <-c.exited:
			if c.waitErr != nil {
				if said := strings.TrimSpace(c.stderr.String()); said != "" {
					return 0, &SSHError{Msg: fmt.Sprintf("ssh %s: %s", c.target.Dest(), lastLines(said, 3))}
				}
			}
		case <-time.After(time.Second):
		}
	}
	return n, err
}

func (c *sshConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// Close ends the bridge: stdin closes, ssh ends; it is stopped if it
// lingers.
func (c *sshConn) Close() error {
	c.once.Do(func() {
		_ = c.w.Close()
		go func() {
			select {
			case <-c.exited:
			case <-time.After(5 * time.Second):
				_ = c.cmd.Process.Kill()
			}
		}()
	})
	return nil
}

type sshAddr string

func (a sshAddr) Network() string { return "ssh" }
func (a sshAddr) String() string  { return string(a) }

func (c *sshConn) LocalAddr() net.Addr                { return sshAddr("local") }
func (c *sshConn) RemoteAddr() net.Addr               { return sshAddr(c.target.String()) }
func (c *sshConn) SetDeadline(t time.Time) error      { return nil }
func (c *sshConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sshConn) SetWriteDeadline(t time.Time) error { return nil }

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// lastLines is the last n lines of s, joined by "; ".
func lastLines(s string, n int) string {
	lines := bytes.Split([]byte(strings.TrimSpace(s)), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l := strings.TrimSpace(string(l)); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "; ")
}
