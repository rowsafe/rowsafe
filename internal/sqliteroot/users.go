package sqliteroot

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Never cut off a running program: before a path is closed to other
// users, Tighten looks at the programs that have it open (for the folder:
// any file in it) in /proc. One that reaches it only through the "others"
// bits (not its owner, not in its group, no ACL entry for its user or
// groups) would lose its access, so the path is left as it is and the
// refusal names the program's user. Root sees every program; the agent
// only its own (the files it changes are its own too).

// procRoot is /proc (tests move it).
var procRoot = "/proc"

// maxProcFDs bounds the look.
const maxProcFDs = 200000

// opener is a program with a file open.
type opener struct {
	pid      int
	uid      uint32   // file system uid
	gids     []uint32 // file system gid and supplementary groups
	path     string   // the file, as /proc shows it
	dev, ino uint64
}

// scanOpeners lists the open regular files of every program it can see.
func scanOpeners() []opener {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []opener
	seen := 0
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pdir := filepath.Join(procRoot, ent.Name())
		fds, err := os.ReadDir(filepath.Join(pdir, "fd"))
		if err != nil {
			continue // another user's program (the agent), or gone
		}
		uid, gids, ok := procCreds(filepath.Join(pdir, "status"))
		if !ok {
			continue
		}
		for _, fd := range fds {
			if seen++; seen > maxProcFDs {
				return out
			}
			link := filepath.Join(pdir, "fd", fd.Name())
			target, err := os.Readlink(link)
			if err != nil || !strings.HasPrefix(target, "/") {
				continue
			}
			var st unix.Stat_t
			if unix.Stat(link, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
				continue
			}
			out = append(out, opener{pid: pid, uid: uid, gids: gids, path: strings.TrimSuffix(target, " (deleted)"),
				dev: uint64(st.Dev), ino: uint64(st.Ino)})
		}
	}
	return out
}

// procCreds reads a program's file system uid and groups.
func procCreds(status string) (uint32, []uint32, bool) {
	data, err := os.ReadFile(status)
	if err != nil {
		return 0, nil, false
	}
	var uid uint32
	var gids []uint32
	okU, okG := false, false
	for _, line := range strings.Split(string(data), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch k {
		case "Uid":
			if len(f) == 4 {
				if n, err := strconv.ParseUint(f[3], 10, 32); err == nil {
					uid, okU = uint32(n), true
				}
			}
		case "Gid":
			if len(f) == 4 {
				if n, err := strconv.ParseUint(f[3], 10, 32); err == nil {
					gids, okG = append(gids, uint32(n)), true
				}
			}
		case "Groups":
			for _, g := range f {
				if n, err := strconv.ParseUint(g, 10, 32); err == nil {
					gids = append(gids, uint32(n))
				}
			}
		}
	}
	return uid, gids, okU && okG
}

// aclEntries reads the named user and group entries of a file's POSIX ACL.
func aclEntries(fd int) (users, groups []uint32) {
	buf := make([]byte, 4+8*64)
	n, err := unix.Fgetxattr(fd, "system.posix_acl_access", buf)
	if err != nil || n < 4 {
		return nil, nil
	}
	for i := 4; i+8 <= n; i += 8 {
		tag := binary.LittleEndian.Uint16(buf[i:])
		id := binary.LittleEndian.Uint32(buf[i+4:])
		switch tag {
		case 0x02: // ACL_USER
			users = append(users, id)
		case 0x08: // ACL_GROUP
			groups = append(groups, id)
		}
	}
	return users, groups
}

// throughOthers reports whether a program reaches a file only through its
// "others" bits.
func throughOthers(o opener, uid, gid uint32, aclUsers, aclGroups []uint32) bool {
	if o.uid == 0 || o.uid == uid {
		return false
	}
	for _, u := range aclUsers {
		if u == o.uid {
			return false
		}
	}
	for _, g := range o.gids {
		if g == gid {
			return false
		}
		for _, ag := range aclGroups {
			if g == ag {
				return false
			}
		}
	}
	return true
}

// othersInUse names a program that would lose its access if the path
// (open as fd, with st) were closed to other users ("" when none).
func othersInUse(openers []opener, p string, folder bool, fd int, st *unix.Stat_t) string {
	var aclU, aclG []uint32
	loaded := false
	for _, o := range openers {
		uses := folder && filepath.Dir(o.path) == p || !folder && o.dev == uint64(st.Dev) && o.ino == uint64(st.Ino)
		if !uses {
			continue
		}
		if !loaded {
			aclU, aclG = aclEntries(fd)
			loaded = true
		}
		if throughOthers(o, st.Uid, st.Gid, aclU, aclG) {
			return fmt.Sprintf("a program running as %s (process %d) uses it through other users' access, so closing it would cut that program off",
				userName(o.uid), o.pid)
		}
	}
	return ""
}

func userName(uid uint32) string {
	data, err := os.ReadFile("/etc/passwd")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) > 2 && f[2] == strconv.FormatUint(uint64(uid), 10) {
				return "user " + f[0]
			}
		}
	}
	return "user " + strconv.FormatUint(uint64(uid), 10)
}
