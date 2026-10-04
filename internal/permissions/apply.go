package permissions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The one-click path. The agent (unprivileged) writes the signed change it
// received as a task to RequestDir/request; rowsafe-permissions.path starts
// rowsafe-permissions.service (root), which runs `rowsafe-permissions
// apply`: it reads the request with the agent user's privileges, verifies
// it against the passkeys in /etc/rowsafe/owners and this server's host ID,
// and only then runs root's own copy of the installer in its
// permissions-only mode. The answer goes to AnswerDir/result, root's
// directory, which the agent can read.
//
// A removal (protocol.TaskPermissionsRemove) takes the same path without a
// signature: it may only turn off what protocol.PermissionsRemovable lists,
// for this server, so it works before any passkey is paired.
const (
	DefaultRequestDir = "/var/lib/rowsafe/permissions" // the agent's, 0700
	DefaultAnswerDir  = "/run/rowsafe-permissions"     // root's (RuntimeDirectory), 0755
	DefaultStateDir   = "/var/lib/rowsafe-permissions" // root's (StateDirectory), 0700: used nonces
	DefaultInstaller  = "/usr/local/lib/rowsafe/install.sh"
	DefaultAgentState = "/var/lib/rowsafe/agent.json"
	DefaultHelper     = "/usr/local/lib/rowsafe/rowsafe-permissions"
	PathUnit          = "/etc/systemd/system/rowsafe-permissions.path"
	RequestName       = "request"
	AnswerName        = "result"
	MaxRequest        = 64 << 10
	InstallerTimeout  = 10 * time.Minute
)

// Request is what the agent hands the helper: a signed change, or a
// removal.
type Request struct {
	ID     string                          `json:"id"` // the task ID
	Signed protocol.SignedPermissionChange `json:"signed,omitzero"`
	Remove *protocol.PermissionRemoval     `json:"remove,omitempty"`
}

// Features is what `rowsafe-permissions features` prints, one per line:
// what this helper takes besides signed changes. The agent reports it
// (protocol.PermissionsReport.RemoveWithoutPasskey).
var Features = []string{FeatureRemove}

// FeatureRemove: the helper applies protocol.PermissionRemoval.
const FeatureRemove = "remove-without-passkey"

// Answer is the helper's answer for request ID.
type Answer struct {
	ID string `json:"id"`
	protocol.PermissionsResult
	FinishedAt time.Time `json:"finished_at"`
}

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Helper is the root side of a one-click change.
type Helper struct {
	RequestPath string
	AnswerDir   string
	StateDir    string
	OwnersFile  string
	AgentState  string
	Installer   string
	Log         io.Writer // the journal
	Now         func() time.Time
	// ReadAsAgent reads a file in the agent's directories with the agent
	// user's privileges (and removes it with remove).
	ReadAsAgent func(path string, max int64, remove bool) ([]byte, error)
	// RunInstaller runs the installer's permissions-only mode.
	RunInstaller func(ctx context.Context, installer string, args []string) ([]byte, error)
}

func (h *Helper) logf(format string, args ...any) {
	fmt.Fprintf(h.Log, "rowsafe-permissions: "+format+"\n", args...)
}

// Apply handles the pending request, if any: verify, run the installer,
// answer. Every decision goes to the journal.
func (h *Helper) Apply(ctx context.Context) error {
	raw, err := h.ReadAsAgent(h.RequestPath, MaxRequest, true)
	if errors.Is(err, ErrNoFile) {
		return nil
	}
	ans := Answer{}
	if err != nil {
		h.logf("refused: unreadable request: %v", err)
		ans.Refused = "the server couldn't read the request"
		return h.answer(ans)
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !requestIDRE.MatchString(req.ID) {
		if requestIDRE.MatchString(req.ID) {
			ans.ID = req.ID
		}
		h.logf("refused: malformed request")
		ans.Refused = "the request is malformed"
		return h.answer(ans)
	}
	ans.ID = req.ID
	var res protocol.PermissionsResult
	if req.Remove != nil {
		res = h.applyRemoval(ctx, req)
	} else {
		res = h.apply(ctx, req)
	}
	ans.PermissionsResult = res
	return h.answer(ans)
}

func (h *Helper) apply(ctx context.Context, req Request) protocol.PermissionsResult {
	refused := func(reason string) protocol.PermissionsResult {
		h.logf("request %s refused: %s", req.ID, reason)
		return protocol.PermissionsResult{Refused: reason}
	}
	owners, err := ReadOwners(h.OwnersFile, true)
	if err != nil {
		return refused("the list of paired passkeys can't be trusted: " + err.Error())
	}
	if len(owners) == 0 {
		return refused("no passkey is paired with this server yet: root pairs one at the server first")
	}
	hostID, err := h.hostID()
	if err != nil {
		return refused(err.Error())
	}
	change, owner, err := VerifyAssertion(req.Signed, owners, hostID, h.Now(), FileNonceStore{Dir: h.StateDir})
	if err != nil {
		return refused(err.Error())
	}
	h.logf("request %s: verified a change signed by %s (passkey %s), requested by %s: allow [%s], remove [%s]",
		req.ID, owner.Name, owner.Fingerprint, change.RequestedBy, strings.Join(change.Allow, " "), strings.Join(change.Remove, " "))
	return h.runInstaller(ctx, req.ID, InstallerArgs(change))
}

// applyRemoval turns off what a removal names: no passkey, but only
// protocol.PermissionsRemovable and only for this server.
func (h *Helper) applyRemoval(ctx context.Context, req Request) protocol.PermissionsResult {
	refused := func(reason string) protocol.PermissionsResult {
		h.logf("request %s refused: %s", req.ID, reason)
		return protocol.PermissionsResult{Refused: reason}
	}
	if len(req.Signed.ChangeJSON) > 0 {
		return refused("the request is malformed")
	}
	rm := *req.Remove
	if err := rm.Validate(); err != nil {
		return refused(err.Error())
	}
	hostID, err := h.hostID()
	if err != nil {
		return refused(err.Error())
	}
	if rm.HostID != hostID {
		return refused("the request is for another server")
	}
	h.logf("request %s: turn off [%s], requested by %s (no passkey needed to turn off)",
		req.ID, strings.Join(rm.Remove, " "), rm.RequestedBy)
	return h.runInstaller(ctx, req.ID, InstallerArgs(&protocol.PermissionChange{Remove: rm.Remove}))
}

// runInstaller runs root's copy of the installer's permissions-only mode
// with args, after checking it is root's.
func (h *Helper) runInstaller(ctx context.Context, id string, args []string) protocol.PermissionsResult {
	if err := CheckRootOwned(h.Installer, false); err != nil {
		reason := "root's copy of the Rowsafe installer can't be trusted: " + err.Error()
		if errors.Is(err, os.ErrNotExist) {
			reason = "root's copy of the Rowsafe installer (" + h.Installer + ") is missing, so this server can't change its permissions from the dashboard yet"
		}
		h.logf("request %s refused: %s", id, reason)
		return protocol.PermissionsResult{Refused: reason}
	}
	h.logf("request %s: running %s %s", id, h.Installer, strings.Join(args, " "))
	ictx, cancel := context.WithTimeout(ctx, InstallerTimeout)
	defer cancel()
	out, err := h.RunInstaller(ictx, h.Installer, args)
	tail := LastLines(out, 15, 2000)
	if err != nil {
		h.logf("request %s: the installer failed: %v; %s", id, err, strings.ReplaceAll(tail, "\n", " | "))
		return protocol.PermissionsResult{Refused: installerRefusal(err, out), Output: tail}
	}
	h.logf("request %s: applied", id)
	return protocol.PermissionsResult{Applied: true, Output: tail}
}

// installerRefusal says why the installer's --permissions mode didn't apply
// a change: exit 2 is a refusal with nothing changed, exit 1 a change that
// failed; either way its last "error: ..." line says why in plain words.
func installerRefusal(err error, out []byte) string {
	why := ""
	for _, line := range strings.Split(string(out), "\n") {
		if r, ok := strings.CutPrefix(strings.TrimSpace(line), "error: "); ok {
			why = r
		}
	}
	code := -1
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		code = ec.ExitCode()
	}
	switch {
	case code == 2 && why != "":
		return why
	case code == 1 && why != "":
		return "the change didn't complete: " + why
	case why != "":
		return why
	}
	return "the installer couldn't apply the change (" + err.Error() + ")"
}

// hostID reads this server's Rowsafe host ID from the agent's identity file
// (as the agent user).
func (h *Helper) hostID() (string, error) {
	data, err := h.ReadAsAgent(h.AgentState, 64<<10, false)
	if err != nil {
		return "", errors.New("this server's Rowsafe ID is unreadable, so it can't check the request is for it")
	}
	var st struct {
		HostID string `json:"host_id"`
	}
	if json.Unmarshal(data, &st) != nil || st.HostID == "" {
		return "", errors.New("this server's Rowsafe ID is unreadable, so it can't check the request is for it")
	}
	return st.HostID, nil
}

// answer writes the answer atomically into root's own directory.
func (h *Helper) answer(a Answer) error {
	if err := CheckRootOwned(h.AnswerDir, true); err != nil {
		h.logf("cannot answer: %v", err)
		return err
	}
	a.FinishedAt = h.Now().UTC()
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(h.AnswerDir, ".result.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(h.AnswerDir, AnswerName))
}

// InstallerArgs are the installer's flags for a change, in the order
// permissions are shown.
func InstallerArgs(c *protocol.PermissionChange) []string {
	args := []string{"--permissions", "--no-prompt"}
	for _, p := range protocol.Permissions {
		switch {
		case slices.Contains(c.Allow, p):
			args = append(args, "--allow-"+p)
		case slices.Contains(c.Remove, p):
			args = append(args, "--no-allow-"+p)
		}
	}
	return args
}

// LastLines keeps the last n lines of out, at most max bytes, without
// terminal escapes.
func LastLines(out []byte, n, max int) string {
	s := strings.TrimSpace(ansiRE.ReplaceAllString(string(out), ""))
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	s = strings.Join(lines, "\n")
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return strings.ToValidUTF8(s, "")
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// RunInstaller runs the installer with sh, a fixed environment, no input
// and its output capped.
func RunInstaller(ctx context.Context, installer string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", append([]string{installer}, args...)...)
	cmd.Dir = "/"
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root", "LANG=C.UTF-8", "NO_COLOR=1", "TERM=dumb",
	}
	out := &capped{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		err = fmt.Errorf("it took longer than %s", InstallerTimeout)
	}
	return out.buf.Bytes(), err
}

// capped keeps the last max bytes written.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	c.buf.Write(p)
	if c.buf.Len() > c.max {
		keep := bytes.Clone(c.buf.Bytes()[c.buf.Len()-c.max:])
		c.buf.Reset()
		c.buf.Write(keep)
	}
	return len(p), nil
}
