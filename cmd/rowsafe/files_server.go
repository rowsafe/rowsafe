package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Files on this server, as root (sudo rowsafe files ...): the agent runs as
// its own user (postgres), so a folder it should back up must be readable
// by it, and a folder it restores into must be its own. Root says yes here,
// like the installer's --files.

const agentBinary = "/opt/rowsafe/rowsafe-agent"

// agentUser is the user the agent runs as on this server: its socket's
// owner.
func agentUser() (*user.User, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	sock, ok := protocol.LocalSocket(cfg.URL)
	if !ok {
		return nil, errors.New("not on a server whose agent answers here")
	}
	fi, err := os.Stat(sock)
	if err != nil {
		return nil, err
	}
	uid, _, ok := fileOwner(fi)
	if !ok {
		return nil, errors.New("no file owners here")
	}
	return user.LookupId(strconv.Itoa(uid))
}

// asAgent runs a command as the agent's user.
func asAgent(u *user.User, args ...string) ([]byte, error) {
	return exec.Command("runuser", append([]string{"-u", u.Username, "--"}, args...)...).CombinedOutput()
}

// agentCanRead says whether the agent's user can read all of dir: "yes",
// "no" or "missing" (the agent's own check when it is installed).
func agentCanRead(u *user.User, dir string) string {
	if _, err := os.Stat(agentBinary); err == nil {
		if out, err := asAgent(u, agentBinary, "files", "access", dir); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	if _, err := asAgent(u, "sh", "-c", `test -r "$1" && test -x "$1" && ls -- "$1" >/dev/null`, "sh", dir); err != nil {
		return "no"
	}
	return "yes"
}

// letAgentRead makes sure the agent can read dir before it is protected:
// if it can't, root is asked (or --yes) to give it read access with an ACL.
// Not root: the agent's report says whether it can.
func letAgentRead(dir string, yes bool) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s doesn't exist on this server", dir)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s isn't a folder: protect the folder it is in", dir)
	}
	u, err := agentUser()
	if err != nil {
		return nil // the agent's report will say
	}
	if agentCanRead(u, dir) == "yes" {
		return nil
	}
	if err := confirmChange(yes, fmt.Sprintf("Rowsafe's agent (user %s) can't read %s yet. Let it read the folder? "+
		"(read-only, with an ACL; owners and modes stay as they are)", u.Username, dir)); err != nil {
		return fmt.Errorf("%s isn't protected: Rowsafe needs to read it to back it up (%w)", dir, err)
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		return errors.New("giving read access needs the acl package: install it (sudo apt install acl, or dnf install acl) and run this again")
	}
	if err := grantRead(dir, u); err != nil {
		return fmt.Errorf("giving Rowsafe read access to %s: %w", dir, err)
	}
	fmt.Fprintf(os.Stderr, "Gave Rowsafe's agent read access to %s (read-only, with an ACL; nothing else changed).\n", dir)
	return nil
}

// grantRead lets u read dir and everything in it, now and later (default
// ACLs), and pass through the folders above it, as the installer's --files
// does. Masks that were already there are put back as they were, so no
// other named entry gains rights.
func grantRead(dir string, u *user.User) error {
	before, err := exec.Command("getfacl", "-R", "-P", "-s", "-p", "--", dir).Output()
	if err != nil {
		return fmt.Errorf("getfacl: %w", err)
	}
	run := func(args ...string) error {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s", strings.Join(args[:2], " "), strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("setfacl", "-R", "-P", "-m", "u:"+u.Username+":rX", "--", dir); err != nil {
		return err
	}
	if err := run("find", "-P", dir, "-xdev", "-type", "d", "-exec", "setfacl", "-m", "d:u:"+u.Username+":rX", "--", "{}", "+"); err != nil {
		return err
	}
	if masks := aclMasks(before); len(masks) > 0 {
		after, err := exec.Command("getfacl", "-R", "-P", "-s", "-p", "--", dir).Output()
		if err != nil {
			return fmt.Errorf("getfacl: %w", err)
		}
		if restore := aclKeepMasks(after, masks); len(restore) > 0 {
			f, err := os.CreateTemp("", "rowsafe-acl-")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			_, err = f.Write(restore)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			if err := run("setfacl", "--restore="+f.Name()); err != nil {
				return err
			}
		}
	}
	for p := filepath.Dir(dir); p != "/" && p != "."; p = filepath.Dir(p) {
		if _, err := asAgent(u, "test", "-x", p); err == nil {
			continue
		}
		args := []string{"setfacl", "-m", "u:" + u.Username + ":x", "--", p}
		if out, _ := exec.Command("getfacl", "-p", "-s", "--", p).Output(); bytes.Contains(out, []byte("\nmask::")) {
			args = []string{"setfacl", "-n", "-m", "u:" + u.Username + ":x", "--", p}
		}
		if err := run(args...); err != nil {
			return err
		}
	}
	return nil
}

type aclMask struct{ mask, dmask string }

// aclMasks reads the mask entries of getfacl -p output, per file.
func aclMasks(out []byte) map[string]aclMask {
	m := map[string]aclMask{}
	file := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if f, ok := strings.CutPrefix(line, "# file: "); ok {
			file = f
			m[file] = aclMask{}
			continue
		}
		e := m[file]
		switch {
		case strings.HasPrefix(line, "mask::"):
			e.mask = line
		case strings.HasPrefix(line, "default:mask::"):
			e.dmask = line
		default:
			continue
		}
		m[file] = e
	}
	return m
}

// aclKeepMasks is a setfacl --restore file of the files that had an ACL
// before, as they are now but with their earlier masks.
func aclKeepMasks(after []byte, before map[string]aclMask) []byte {
	var b bytes.Buffer
	file, keep := "", false
	sc := bufio.NewScanner(bytes.NewReader(after))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if f, ok := strings.CutPrefix(line, "# file: "); ok {
			file = f
			_, keep = before[file]
		}
		if !keep || strings.HasPrefix(line, "# owner:") || strings.HasPrefix(line, "# group:") || strings.HasPrefix(line, "# flags:") {
			continue
		}
		old := before[file]
		switch {
		case strings.HasPrefix(line, "mask::") && old.mask != "":
			line = old.mask
		case strings.HasPrefix(line, "default:mask::") && old.dmask != "":
			line = old.dmask
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

var dockerVolumeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

// dockerVolumePath is the folder on this server that holds a Docker
// volume's files.
func dockerVolumePath(vol string) (string, error) {
	if !dockerVolumeRE.MatchString(vol) {
		return "", fmt.Errorf("docker:%s: not a Docker volume name", vol)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker:%s needs Docker on this server; or give the volume's folder, e.g. /var/lib/docker/volumes/%s/_data", vol, vol)
	}
	out, err := exec.Command("docker", "volume", "inspect", "--format", "{{.Mountpoint}}", vol).CombinedOutput()
	p := strings.TrimSpace(string(out))
	if err != nil || !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("docker:%s: %s", vol, orText(p, "no such Docker volume"))
	}
	return p, nil
}

// prepareInto creates the folder a restore goes into, owned by the agent's
// user and only readable by it and root (the restored files may be
// private). An existing folder must be empty.
func prepareInto(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("--into: give the folder's full, plain path (got %q)", dir)
	}
	if strings.HasPrefix(dir+"/", "/home/") || strings.HasPrefix(dir+"/", "/root/") {
		return fmt.Errorf("--into: Rowsafe's agent doesn't see home folders; choose one like /srv/restored")
	}
	if os.Geteuid() != 0 {
		return nil // the agent creates it if it may
	}
	u, err := agentUser()
	if err != nil {
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
	case err != nil:
		return err
	case len(entries) > 0:
		return fmt.Errorf("--into: %s isn't empty; choose a new folder", dir)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if _, err := asAgent(u, "test", "-w", dir); err != nil {
		return fmt.Errorf("--into: Rowsafe's agent (user %s) can't reach %s (a folder above it is closed to it); choose a folder under /srv or /var", u.Username, dir)
	}
	return nil
}
