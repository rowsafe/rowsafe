package local

import "golang.org/x/sys/unix"

// machineMemory is this Mac's memory (collect reads Linux's /proc).
func machineMemory() int64 {
	n, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return int64(n)
}
