package collect

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// cpuTimes is the aggregate "cpu" line of /proc/stat, in clock ticks.
type cpuTimes struct {
	total, idle float64
}

// parseProcStat reads the first "cpu" line of /proc/stat. Idle includes
// iowait: a CPU waiting for IO could run other work.
func parseProcStat(data string) (cpuTimes, int, error) {
	var t cpuTimes
	cpus := 0
	found := false
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			cpus++
			continue
		}
		if len(f) < 5 {
			return t, 0, errors.New("short cpu line in /proc/stat")
		}
		// user nice system idle iowait irq softirq steal guest guest_nice;
		// guest time is already counted in user and nice.
		for i, s := range f[1:] {
			if i >= 8 {
				break
			}
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return t, 0, fmt.Errorf("/proc/stat: %w", err)
			}
			t.total += v
			if i == 3 || i == 4 {
				t.idle += v
			}
		}
		found = true
	}
	if !found {
		return t, 0, errors.New("no cpu line in /proc/stat")
	}
	return t, cpus, nil
}

// parseLoadavg reads /proc/loadavg.
func parseLoadavg(data string) (l1, l5, l15 float64, err error) {
	f := strings.Fields(data)
	if len(f) < 3 {
		return 0, 0, 0, errors.New("short /proc/loadavg")
	}
	vals := make([]float64, 3)
	for i := range vals {
		if vals[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return 0, 0, 0, fmt.Errorf("/proc/loadavg: %w", err)
		}
	}
	return vals[0], vals[1], vals[2], nil
}

// parseMeminfo returns /proc/meminfo values in bytes.
func parseMeminfo(data string) map[string]float64 {
	out := map[string]float64{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		out[name] = v
	}
	return out
}

// hostCollector reads host metrics from /proc (Linux). On other systems
// only disk metrics are reported.
type hostCollector struct {
	procRoot string
	prevCPU  *cpuTimes
}

func (h *hostCollector) collect(dataDirs []string) map[string]float64 {
	out := map[string]float64{}
	if data, err := os.ReadFile(filepath.Join(h.procRoot, "stat")); err == nil {
		if cur, cpus, err := parseProcStat(string(data)); err == nil {
			if cpus > 0 {
				out[HCPUCount] = float64(cpus)
			}
			if p := h.prevCPU; p != nil && cur.total > p.total && cur.idle >= p.idle {
				busy := (cur.total - p.total) - (cur.idle - p.idle)
				out[HCPUPct] = clampPct(100 * busy / (cur.total - p.total))
			}
			h.prevCPU = &cur
		}
	}
	if data, err := os.ReadFile(filepath.Join(h.procRoot, "loadavg")); err == nil {
		if l1, l5, l15, err := parseLoadavg(string(data)); err == nil {
			out[HLoad1], out[HLoad5], out[HLoad15] = l1, l5, l15
		}
	}
	if data, err := os.ReadFile(filepath.Join(h.procRoot, "meminfo")); err == nil {
		m := parseMeminfo(string(data))
		if total, avail := m["MemTotal"], m["MemAvailable"]; total > 0 {
			out[HMemTotal] = total
			if _, ok := m["MemAvailable"]; ok {
				out[HMemAvailable] = avail
				out[HMemUsedPct] = clampPct(100 * (1 - avail/total))
			}
		}
		if st, ok := m["SwapTotal"]; ok {
			out[HSwapTotal] = st
			out[HSwapUsed] = max(st-m["SwapFree"], 0)
		}
	}
	// The fullest filesystem holding a data directory is the one that
	// matters; with no known data directory, fall back to /.
	if len(dataDirs) == 0 {
		dataDirs = []string{"/"}
	}
	worst := -1.0
	for _, dir := range dataDirs {
		d, err := diskUsage(dir)
		if err != nil {
			continue
		}
		if used := 100 - d.freePct; used > worst {
			worst = used
			out[HDiskUsedPct] = clampPct(used)
			out[MDiskFreeBytes] = d.free
			out[MDiskTotalBytes] = d.total
		}
	}
	return out
}

type disk struct {
	total, free, freePct float64
}

// diskUsage reports a filesystem's size and the space available to
// unprivileged users, like df: free% = avail / (used + avail).
func diskUsage(path string) (disk, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return disk{}, err
	}
	bs := float64(st.Bsize)
	used := float64(st.Blocks-st.Bfree) * bs
	avail := float64(st.Bavail) * bs
	d := disk{total: float64(st.Blocks) * bs, free: avail}
	if used+avail <= 0 {
		return d, errors.New("empty filesystem")
	}
	d.freePct = clampPct(100 * avail / (used + avail))
	return d, nil
}

func clampPct(v float64) float64 {
	return min(max(v, 0), 100)
}
