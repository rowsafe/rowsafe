package permissions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ExitNoFile is read-as-agent's exit status when nothing is at the path.
const ExitNoFile = 3

// ReadAsAgentFunc returns a reader that runs this same (root-owned) binary
// as agentUser (`rowsafe-permissions read-as-agent`), so root never opens,
// follows or removes anything in the agent's directories itself.
func ReadAsAgentFunc(agentUser string) (func(path string, max int64, remove bool) ([]byte, error), error) {
	u, err := user.Lookup(agentUser)
	if err != nil {
		return nil, fmt.Errorf("the agent user %q: %w", agentUser, err)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return nil, fmt.Errorf("the agent user %q can't be used", agentUser)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return func(path string, max int64, remove bool) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		args := []string{"rowsafe-permissions", "read-as-agent", "--max", strconv.FormatInt(max, 10)}
		if remove {
			args = append(args, "--remove")
		}
		cmd := exec.CommandContext(ctx, exe)
		cmd.Args = append(args, "--", path)
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
		stdout, stderr := &capped{max: int(max) + 1}, &capped{max: 2000}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == ExitNoFile {
			return nil, ErrNoFile
		}
		if err != nil {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.buf.String()))
		}
		if int64(stdout.buf.Len()) > max {
			return nil, fmt.Errorf("%s is too large", path)
		}
		return stdout.buf.Bytes(), nil
	}, nil
}
