package sqlite

import (
	"encoding/binary"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// matchPermissions gives f (created by the agent) the database file's
// permissions for the database's owner and group: as root by ownership,
// otherwise with a POSIX ACL (user:<owner>, group:<group> entries).
func matchPermissions(f *os.File, mode os.FileMode, uid, gid uint32) error {
	me := uint32(os.Geteuid())
	if me == 0 {
		if err := f.Chown(int(uid), int(gid)); err != nil {
			return err
		}
		return f.Chmod(mode)
	}
	if me == uid {
		myGid := uint32(os.Getegid())
		if myGid == gid {
			return f.Chmod(mode)
		}
	}
	owner := uint16(mode>>6) & 7
	group := uint16(mode>>3) & 7
	other := uint16(mode) & 7
	type entry struct {
		tag  uint16
		perm uint16
		id   uint32
	}
	const (
		userObj  = 0x01
		user     = 0x02
		groupObj = 0x04
		grp      = 0x08
		mask     = 0x10
		oth      = 0x20
		none     = 0xFFFFFFFF
	)
	entries := []entry{{userObj, 6, none}, {oth, other, none}}
	m := uint16(0)
	if uid != me {
		entries = append(entries, entry{user, owner, uid})
		m |= owner
	}
	if gid == uint32(os.Getegid()) {
		entries = append(entries, entry{groupObj, group, none})
		m |= group
	} else {
		entries = append(entries, entry{groupObj, 0, none}, entry{grp, group, gid})
		m |= group
	}
	entries = append(entries, entry{mask, m, none})
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].tag != entries[j].tag {
			return entries[i].tag < entries[j].tag
		}
		return entries[i].id < entries[j].id
	})
	buf := make([]byte, 4, 4+8*len(entries))
	binary.LittleEndian.PutUint32(buf, 2)
	for _, e := range entries {
		var b [8]byte
		binary.LittleEndian.PutUint16(b[0:], e.tag)
		binary.LittleEndian.PutUint16(b[2:], e.perm)
		binary.LittleEndian.PutUint32(b[4:], e.id)
		buf = append(buf, b[:]...)
	}
	return unix.Fsetxattr(int(f.Fd()), "system.posix_acl_access", buf, 0)
}
