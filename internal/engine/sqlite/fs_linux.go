package sqlite

import "golang.org/x/sys/unix"

// networkFS names the network filesystem dir is on ("" for a local one).
// SQLite's locking (and WAL's shared memory) isn't reliable there.
func networkFS(dir string) string {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return ""
	}
	switch uint32(st.Type) {
	case 0x6969:
		return "nfs"
	case 0xFF534D42:
		return "cifs"
	case 0xFE534D42:
		return "smb2"
	case 0x517B:
		return "smb"
	case 0x01021997:
		return "9p"
	case 0x00C36400:
		return "ceph"
	case 0x65735546:
		return "fuse"
	case 0x564C:
		return "ncp"
	case 0x47504653:
		return "gpfs"
	case 0x6B414653:
		return "afs"
	case 0x5346414F:
		return "afs"
	case 0x0BD00BD0:
		return "lustre"
	case 0x013111A8:
		return "ibrix"
	}
	return ""
}

// diskSpace is the total and available bytes of dir's filesystem.
func diskSpace(dir string) (total, free int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize), nil
}
