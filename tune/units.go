package tune

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Size and time units as PostgreSQL writes them.
const (
	KB = int64(1024)
	MB = 1024 * KB
	GB = 1024 * MB
	TB = 1024 * GB
)

var memUnits = map[string]float64{"B": 1, "kB": 1024, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}

var timeUnits = map[string]float64{"us": 0.001, "ms": 1, "s": 1000, "min": 60_000, "h": 3_600_000, "d": 86_400_000}

// IsMemoryUnit reports whether a pg_settings unit is a size ("8kB", "kB",
// "MB", "B").
func IsMemoryUnit(unit string) bool {
	_, ok := baseMultiplier(unit, memUnits)
	return ok
}

// IsTimeUnit reports whether a pg_settings unit is a time ("ms", "s", "min").
func IsTimeUnit(unit string) bool {
	_, ok := baseMultiplier(unit, timeUnits)
	return ok
}

// baseMultiplier turns a pg_settings unit ("8kB", "16MB", "ms") into bytes
// or milliseconds per unit.
func baseMultiplier(unit string, units map[string]float64) (float64, bool) {
	i := 0
	for i < len(unit) && unit[i] >= '0' && unit[i] <= '9' {
		i++
	}
	m, ok := units[unit[i:]]
	if !ok || unit == "" {
		return 0, false
	}
	n := 1.0
	if i > 0 {
		v, err := strconv.ParseFloat(unit[:i], 64)
		if err != nil {
			return 0, false
		}
		n = v
	}
	return n * m, true
}

// Quantity parses a value of a setting whose pg_settings unit is unit, as
// PostgreSQL would: a bare number is in unit ("16384" of "8kB" is 128 MB),
// or a number with its own unit ("4GB", "250ms", "1.5 min"). It returns
// bytes for sizes and milliseconds for times; ok is false when value is not
// a number or the unit doesn't fit.
func Quantity(value, unit string) (float64, bool) {
	v := strings.TrimSpace(value)
	units := memUnits
	if IsTimeUnit(unit) {
		units = timeUnits
	} else if !IsMemoryUnit(unit) {
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	base, _ := baseMultiplier(unit, units)
	end := 0
	for end < len(v) && (v[end] >= '0' && v[end] <= '9' || v[end] == '.' || v[end] == '-' || v[end] == '+') {
		end++
	}
	num, err := strconv.ParseFloat(v[:end], 64)
	if err != nil {
		return 0, false
	}
	suffix := strings.TrimSpace(v[end:])
	if suffix == "" {
		return num * base, true
	}
	m, ok := units[suffix]
	if !ok {
		return 0, false
	}
	return num * m, true
}

// Bytes parses a size setting's value (see Quantity).
func Bytes(value, unit string) (int64, bool) {
	if !IsMemoryUnit(unit) {
		return 0, false
	}
	f, ok := Quantity(value, unit)
	return int64(f), ok
}

// PGBytes writes a size the way PostgreSQL accepts it, in the largest unit
// that divides it: "4GB", "3840MB", "64kB".
func PGBytes(b int64) string {
	switch {
	case b >= GB && b%GB == 0:
		return strconv.FormatInt(b/GB, 10) + "GB"
	case b >= MB && b%MB == 0:
		return strconv.FormatInt(b/MB, 10) + "MB"
	case b%KB == 0:
		return strconv.FormatInt(b/KB, 10) + "kB"
	}
	return strconv.FormatInt(b, 10) + "B"
}

// HumanBytes is a size for people: "128 MB", "3.75 GB".
func HumanBytes(b int64) string {
	neg := b < 0
	if neg {
		b = -b
	}
	s := ""
	switch {
	case b >= TB:
		s = trimFloat(float64(b)/float64(TB)) + " TB"
	case b >= GB:
		s = trimFloat(float64(b)/float64(GB)) + " GB"
	case b >= MB:
		s = trimFloat(float64(b)/float64(MB)) + " MB"
	case b >= KB:
		s = trimFloat(float64(b)/float64(KB)) + " kB"
	default:
		s = strconv.FormatInt(b, 10) + " B"
	}
	if neg {
		return "-" + s
	}
	return s
}

// HumanMillis is a time for people: "250 ms", "5 s", "10 min", "1.5 h".
func HumanMillis(ms float64) string {
	switch {
	case ms >= 86_400_000 && math.Mod(ms, 86_400_000) == 0:
		return trimFloat(ms/86_400_000) + " d"
	case ms >= 3_600_000:
		return trimFloat(ms/3_600_000) + " h"
	case ms >= 60_000:
		return trimFloat(ms/60_000) + " min"
	case ms >= 1000:
		return trimFloat(ms/1000) + " s"
	}
	return trimFloat(ms) + " ms"
}

func trimFloat(f float64) string {
	s := strconv.FormatFloat(math.Round(f*100)/100, 'f', 2, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// autoValues are settings whose "off" value means "automatic".
var autoValues = map[string]string{
	"wal_buffers":                  "automatic",
	"autovacuum_work_mem":          "same as maintenance memory",
	"autovacuum_vacuum_cost_limit": "automatic (200)",
}

// Display is a setting's value for people: "128 MB", "5 min", "on",
// "off" (a timeout of 0), "(none)" (an empty string).
func Display(name, value, unit, vartype string) string {
	if e, ok := Lookup(name); ok && e.Off != "" && strings.TrimSpace(value) == e.Off {
		if a, ok := autoValues[e.Name]; ok {
			return a
		}
		return "off"
	}
	switch {
	case vartype == "string" && value == "":
		return "(none)"
	case IsMemoryUnit(unit):
		if b, ok := Bytes(value, unit); ok {
			return HumanBytes(b)
		}
	case IsTimeUnit(unit):
		if ms, ok := Quantity(value, unit); ok {
			return HumanMillis(ms)
		}
	}
	return value
}

// SameValue compares a setting's value in pg_settings with a value as
// given in a change ("64MB" is 8192 of 8kB; "on" is "true").
func SameValue(s protocol.PGSetting, want string) bool {
	got := strings.TrimSpace(s.Setting)
	want = strings.Trim(strings.TrimSpace(want), `'"`)
	switch s.VarType {
	case "bool":
		return boolValue(got) == boolValue(want)
	case "integer", "real":
		g, ok1 := Quantity(got, s.Unit)
		w, ok2 := Quantity(want, s.Unit)
		if !ok1 || !ok2 {
			return strings.EqualFold(got, want)
		}
		if g == w {
			return true
		}
		// PostgreSQL rounds sizes and times to its unit (8kB pages, whole ms).
		unit := 0.0
		if IsMemoryUnit(s.Unit) || IsTimeUnit(s.Unit) {
			unit, _ = Quantity("1", s.Unit)
		}
		diff := g - w
		if diff < 0 {
			diff = -diff
		}
		return diff <= max(unit, 1e-9*max(g, w, 1))
	case "string":
		if ListSetting(s.Name) {
			return slices.Equal(Libraries(got), Libraries(want))
		}
	}
	return strings.EqualFold(got, want)
}

func boolValue(v string) string {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1", "t", "y":
		return "on"
	}
	return "off"
}

// ListSetting reports whether a setting is a list whose elements
// PostgreSQL quotes one by one (GUC_LIST_QUOTE): ALTER SYSTEM needs one
// literal per element, or 'a,b' becomes a single library named "a,b" and
// PostgreSQL won't start.
func ListSetting(name string) bool {
	switch name {
	case "shared_preload_libraries", "session_preload_libraries", "local_preload_libraries", "search_path", "temp_tablespaces":
		return true
	}
	return false
}
