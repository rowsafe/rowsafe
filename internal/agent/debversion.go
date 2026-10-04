package agent

import (
	"strconv"
	"strings"
)

// debCompare compares two Debian package versions like
// `dpkg --compare-versions` (-1, 0, 1): "5:7.0.15-1~deb12u6" is newer than
// "5:7.0.15-1~deb12u4", "1.0~rc1" older than "1.0".
func debCompare(a, b string) int {
	ea, ua, ra := debSplit(a)
	eb, ub, rb := debSplit(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := debVerrevcmp(ua, ub); c != 0 {
		return c
	}
	return debVerrevcmp(ra, rb)
}

// debSplit: "5:7.0.15-1~deb12u6" -> 5, "7.0.15", "1~deb12u6".
func debSplit(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok {
		epoch, _ = strconv.Atoi(e)
		v = rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// debOrder is a non-digit character's weight: ~ first (even before the
// end of the string), then the end, letters, then everything else.
func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// debVerrevcmp is dpkg's verrevcmp.
func debVerrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debOrder(a[i])
			}
			if j < len(b) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			if first < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}
