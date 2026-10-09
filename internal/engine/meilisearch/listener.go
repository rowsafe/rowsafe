package meilisearch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Before the agent opens a connection to Meilisearch on this machine (and
// so before it sends a key), it checks who listens on the port: any user
// can listen on a free port above 1024, for instance while Meilisearch
// restarts, or between the moment the agent picks a port for a temporary
// Meilisearch and the moment that Meilisearch takes it.
//   - Production (prodCheck): every socket listening on the port belongs to
//     root, the meilisearch user, the user systemd runs the instance's unit
//     as, or the owner of its data folder (a path root's installer gave).
//   - A temporary Meilisearch the agent started (scratchCheck): the agent's
//     own user only.

// listenerCheck vets the listener of a port on 127.0.0.1.
type listenerCheck func(port int) error

// procNet and procRoot are /proc/net and /proc (tests point them
// elsewhere); checkListeners is false only in tests on machines without
// /proc (the integration test on macOS).
var (
	procNet        = "/proc/net"
	procRoot       = "/proc"
	checkListeners = true
)

// listenerUIDs are the owners of the sockets listening on port (TCP, IPv4
// and IPv6, any address).
func listenerUIDs(port int) ([]int, error) {
	var uids []int
	found := false
	for _, f := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procNet, f))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && f == "tcp6" {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
			if len(fs) < 10 || fs[3] != "0A" { // LISTEN
				continue
			}
			i := strings.LastIndex(fs[1], ":")
			if i < 0 {
				continue
			}
			p, err := strconv.ParseInt(fs[1][i+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			uid, err := strconv.Atoi(fs[7])
			if err != nil {
				continue
			}
			found = true
			if !slices.Contains(uids, uid) {
				uids = append(uids, uid)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("nothing on this machine listens on port %d", port)
	}
	return uids, nil
}

// procUID is the user a process runs as (-1 when unknown).
func procUID(pid int) int {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				if u, err := strconv.Atoi(f[0]); err == nil {
					return u
				}
			}
		}
	}
	return -1
}

// unitMainPID is the main process of a systemd unit (0 when none).
func unitMainPID(unit string) int {
	if unit == "" || strings.ContainsAny(unit, " /\n") {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", unit)
	cmd.Env = minimalEnv()
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func ownerUID(path string) int {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}

// meilisearchUIDs are the users production Meilisearch may listen as.
func meilisearchUIDs(s server) []int {
	uids := []int{0}
	if u, err := user.Lookup("meilisearch"); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			uids = append(uids, n)
		}
	}
	if pid := unitMainPID(s.Unit); pid > 0 {
		if u := procUID(pid); u >= 0 {
			uids = append(uids, u)
		}
	}
	if s.DBPath != "" && filepath.IsAbs(s.DBPath) {
		if u := ownerUID(s.DBPath); u >= 0 {
			uids = append(uids, u)
		}
	}
	return uids
}

func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(uid)
}

// checkOwners: every socket listening on port belongs to one of allowed.
func checkOwners(port int, allowed []int, who string) error {
	if !checkListeners {
		return nil
	}
	uids, err := listenerUIDs(port)
	if err != nil {
		return err
	}
	for _, u := range uids {
		if !slices.Contains(allowed, u) {
			return fmt.Errorf("port %d on this machine is held by the user %s, not by %s: Rowsafe sends nothing to it "+
				"(is another program listening there?)", port, userName(u), who)
		}
	}
	return nil
}

// prodCheck vets production's port for s.
func prodCheck(s server) listenerCheck {
	return func(port int) error { return checkOwners(port, meilisearchUIDs(s), "Meilisearch") }
}

// scratchCheck vets a temporary Meilisearch's port: the agent's own.
func scratchCheck(port int) error {
	return checkOwners(port, []int{os.Getuid()}, "Rowsafe's temporary Meilisearch")
}
