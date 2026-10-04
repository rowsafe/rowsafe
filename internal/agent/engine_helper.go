package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Engines ask root's helper for what root allowed them at install, beyond
// restarts: MongoDB standbys (mongodb-key-export, mongodb-standby-config).
// The request is the same one-line file as a restart's; the helper checks
// every word against its own allow lists.

// MongoDBStandbyAllowFile lists the MongoDB servers root let Rowsafe
// configure as standby servers ("PORT UNIT CONFIG" lines, written by the
// installer with --mongodb-standby).
var MongoDBStandbyAllowFile = "/etc/rowsafe/mongodb-standby-allowed"

// helperArgRE: the only characters a helper request's words may have.
var helperArgRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// engineHelper hands one request to root's helper and waits for its answer.
func (a *Agent) engineHelper(ctx context.Context, action string, args ...string) (map[string]string, error) {
	if a.cfg.Sidecar() || a.cfg.RestartDir == "" {
		return nil, errors.New("root's helper isn't installed on this server")
	}
	for _, w := range append([]string{action}, args...) {
		if !helperArgRE.MatchString(w) {
			return nil, fmt.Errorf("invalid helper request word %q", w)
		}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	line := id + " " + action + " " + strings.Join(args, " ") + "\n"
	request := filepath.Join(a.cfg.RestartDir, "request")
	if err := writeFileAtomic(request, []byte(line), 0o600); err != nil {
		return nil, err
	}
	res, err := waitRestartResult(ctx, filepath.Join(a.cfg.RestartResultDir, "result"), id)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, errRestartNoAnswer) {
			return nil, fmt.Errorf("root's helper on this server didn't answer within %s", restartHelperTimeout)
		}
		return nil, err
	}
	if res["ok"] != "1" {
		msg := res["error"]
		if msg == "malformed request" {
			msg = "root's helper on this server is from an older Rowsafe: run the Rowsafe installer there again"
		}
		return res, errors.New(cmpOrStr(msg, "root's helper refused"))
	}
	return res, nil
}

func cmpOrStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// helperCanDo reports whether root's helper may do action for port.
func (a *Agent) helperCanDo(action string, port int) bool {
	if a.cfg.Sidecar() || a.cfg.RestartHelper == "" {
		return false
	}
	switch action {
	case helperRestart, helperStop, helperStart:
		return slices.Contains(a.restartPorts(), port) && (action == helperRestart || slices.Contains(a.helperActions(), action))
	}
	if !slices.Contains(a.helperAllActions(), action) {
		return false
	}
	if strings.HasPrefix(action, "mongodb-") {
		return slices.Contains(allowFilePorts(MongoDBStandbyAllowFile), port)
	}
	if strings.HasPrefix(action, "redis-") {
		lo, hi := allowFileRange(RedisServersAllowFile)
		return lo > 0 && port >= lo && port <= hi
	}
	return false
}

// RedisServersAllowFile is where root lets Rowsafe create Redis or Valkey
// servers for standbys and clones ("ports MIN-MAX", "purposes ...",
// written by the installer with --redis-standby or --redis-clones).
var RedisServersAllowFile = "/etc/rowsafe/redis-servers-allowed"

// RedisCreatedFile lists the servers root's helper created ("PORT UNIT").
var RedisCreatedFile = "/etc/rowsafe/redis-created"

// allowFileRange is the "ports MIN-MAX" line of an allow file (0, 0: none).
func allowFileRange(path string) (int, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "ports" {
			lo, hi, ok := strings.Cut(f[1], "-")
			a, err1 := strconv.Atoi(lo)
			b, err2 := strconv.Atoi(hi)
			if ok && err1 == nil && err2 == nil && a > 0 && a <= b && b < 65536 {
				return a, b
			}
		}
	}
	return 0, 0
}

// helperAllActions is every word of the helper's "# actions:" line.
func (a *Agent) helperAllActions() []string {
	f, err := os.Open(a.cfg.RestartHelper)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "# actions:"); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// allowFilePorts are the ports listed first on the lines of an allow file.
func allowFilePorts(path string) []int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []int
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if p, err := strconv.Atoi(f[0]); err == nil && p > 0 && p < 65536 {
			out = append(out, p)
		}
	}
	return out
}
