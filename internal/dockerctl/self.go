package dockerctl

import (
	"bufio"
	"os"
	"regexp"
)

var mountContainerRE = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// ownContainerID finds this container's ID: Docker bind-mounts
// /etc/hostname, /etc/hosts and /etc/resolv.conf from
// .../containers/<id>/, which /proc/self/mountinfo shows (with cgroup v2 the
// cgroup path no longer names the container). "" when not found.
func ownContainerID() string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := mountContainerRE.FindStringSubmatch(sc.Text()); m != nil {
			return m[1]
		}
	}
	return ""
}
