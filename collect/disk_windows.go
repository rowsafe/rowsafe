package collect

import (
	"errors"

	"golang.org/x/sys/windows"
)

// diskUsage reports a volume's size and the space available to this user.
func diskUsage(path string) (disk, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return disk{}, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return disk{}, err
	}
	d := disk{total: float64(total), free: float64(avail)}
	used := float64(total - free)
	if used+float64(avail) <= 0 {
		return d, errors.New("empty filesystem")
	}
	d.freePct = clampPct(100 * float64(avail) / (used + float64(avail)))
	return d, nil
}
