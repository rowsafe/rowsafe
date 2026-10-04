package tuneroot

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// ---- Redis and Valkey ----
//
// The configuration file is "name value" lines. For each setting, every
// line that sets it is replaced by Rowsafe's one line, where the last of
// them was (the server reads the last one; "save" lines add up, so all of
// them go), or appended at the end under a comment when the file had none.
// The first time Rowsafe sets a setting it keeps the lines the file had,
// so removing it (an undo) puts them back. Included files are not edited.

const redisMarker = "# Rowsafe tuning: the settings below were changed from the Rowsafe dashboard (a copy of this file was kept first)."

// maxRedisConf bounds the configuration file root reads.
const maxRedisConf = 4 << 20

func (a *Applier) applyRedis(r Request, file string, st *state, backup string) ([]string, error) {
	if err := a.safeDir(filepath.Dir(file)); err != nil {
		return nil, err
	}
	// Open without following a link, then check what was opened: a regular
	// file with one name, not the agent's.
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	uid, gid := -1, -1
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(sys.Uid), int(sys.Gid)
		if sys.Nlink != 1 {
			return nil, fmt.Errorf("%s has other names (hard links), so Rowsafe leaves it alone", file)
		}
		if os.Getuid() == 0 && a.AgentUID >= 0 && uid == a.AgentUID {
			return nil, fmt.Errorf("%s belongs to the agent's user; Rowsafe's helper doesn't write it", file)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRedisConf+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRedisConf {
		return nil, fmt.Errorf("%s is too large", file)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(data) == 0 {
		lines = nil
	}
	names := make([]string, 0, len(r.Settings))
	for name := range r.Settings {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		v := r.Settings[name]
		at, old := redisLines(lines, name)
		if _, had := st.Values[name]; !had {
			// The first time Rowsafe sets it: remember what the file had.
			if len(old) > 0 {
				st.Original[name] = strings.Join(old, "\n")
			} else {
				st.Original[name] = nil
			}
		}
		var repl []string
		switch {
		case v != "":
			st.Values[name] = v
			repl = []string{name + " " + v}
		default:
			delete(st.Values, name)
			if orig, ok := st.Original[name].(string); ok {
				repl = strings.Split(orig, "\n")
			}
			delete(st.Original, name)
		}
		lines = redisReplace(lines, name, at, repl)
	}
	out := []byte(strings.Join(lines, "\n") + "\n")
	if bytes.Equal(out, data) {
		return []string{file}, nil
	}
	if err := copyIfExists(file, backup); err != nil {
		return nil, err
	}
	if err := writeAtomic(file, out, fi.Mode().Perm(), uid, gid); err != nil {
		return nil, err
	}
	return []string{file}, nil
}

// redisKey is the setting a configuration line sets ("" for comments and
// blank lines), lowercased like Redis reads it.
func redisKey(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	return strings.ToLower(strings.Fields(t)[0])
}

// redisLines finds the lines that set name: the index of the last one
// (-1: none) and their text.
func redisLines(lines []string, name string) (last int, text []string) {
	last = -1
	for i, l := range lines {
		if redisKey(l) == name {
			last, text = i, append(text, l)
		}
	}
	return last, text
}

// redisReplace removes every line that sets name and puts repl where the
// last one was, or at the end under Rowsafe's comment.
func redisReplace(lines []string, name string, last int, repl []string) []string {
	var out []string
	inserted := false
	for i, l := range lines {
		if redisKey(l) == name {
			if i == last {
				out = append(out, repl...)
				inserted = true
			}
			continue
		}
		out = append(out, l)
	}
	if !inserted && len(repl) > 0 {
		if !slices.Contains(out, redisMarker) {
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
			out = append(out, redisMarker)
		}
		out = append(out, repl...)
	}
	return out
}
