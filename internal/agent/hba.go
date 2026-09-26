package agent

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Editing pg_hba.conf. The edit is a pure text transformation that keeps
// every line it does not change byte for byte: a rule it replaces stays in
// the file as a comment right above its replacement. security_fix.go takes
// a backup, writes the result, has PostgreSQL validate it (the error column
// of pg_hba_file_rules) and reloads, restoring the backup on any problem.

// hbaLine is one line of pg_hba.conf.
type hbaLine struct {
	raw    string
	fields []string // tokens without the comment; nil for blank and comment lines
}

// hbaRecordTypes are the connection types of pg_hba.conf records.
var hbaRecordTypes = map[string]bool{
	"local": true, "host": true, "hostssl": true, "hostnossl": true, "hostgssenc": true, "hostnogssenc": true,
}

// parseHBA splits pg_hba.conf into lines and tokens. It refuses what it
// does not edit safely: include directives and line continuations.
func parseHBA(content string) ([]hbaLine, error) {
	raw := strings.Split(content, "\n")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]hbaLine, 0, len(raw))
	for i, line := range raw {
		fields, err := hbaTokens(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if len(fields) > 0 {
			if strings.HasPrefix(fields[0], "include") {
				return nil, fmt.Errorf("line %d includes another file (%s); Rowsafe only edits a pg_hba.conf that holds every rule itself", i+1, fields[0])
			}
			if strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\") {
				return nil, fmt.Errorf("line %d continues on the next line; Rowsafe only edits one rule per line", i+1)
			}
		}
		out = append(out, hbaLine{raw: line, fields: fields})
	}
	return out, nil
}

// hbaTokens splits a line into tokens: whitespace separates them, double
// quotes group, '#' outside quotes starts a comment. Quotes are kept, so a
// token written back is written exactly as it was.
func hbaTokens(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote, inToken := false, false
	flush := func() {
		if inToken {
			out = append(out, cur.String())
			cur.Reset()
			inToken = false
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
			inToken = true
		case inQuote:
			cur.WriteRune(r)
		case r == '#':
			flush()
			return out, nil
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return out, nil
}

// hbaRecord is a host record's parts: fields[addrAt] is the address, and
// the next field its netmask when hasMask.
type hbaRecord struct {
	typ     string
	addrAt  int
	hasMask bool
	method  int // index of the method field
}

func recordOf(fields []string) (hbaRecord, bool) {
	if len(fields) < 4 || !hbaRecordTypes[fields[0]] || fields[0] == "local" {
		return hbaRecord{}, false
	}
	r := hbaRecord{typ: fields[0], addrAt: 3, method: 4}
	addr := fields[3]
	if !strings.Contains(addr, "/") {
		if _, err := netip.ParseAddr(addr); err == nil && len(fields) >= 6 {
			if _, err := netip.ParseAddr(fields[4]); err == nil {
				r.hasMask, r.method = true, 5
			}
		}
	}
	if r.method >= len(fields) {
		return hbaRecord{}, false
	}
	return r, true
}

// Address families a rule's address covers.
const (
	famNone = 0
	famV4   = 1
	famV6   = 2
	famAll  = famV4 | famV6
)

// openFamilies reports which address families a rule opens to every
// address: "all", 0.0.0.0/0, ::/0, or an IP with an all-zero netmask.
func openFamilies(fields []string, r hbaRecord) int {
	addr := strings.Trim(fields[r.addrAt], `"`)
	if addr == "all" {
		return famAll
	}
	if r.hasMask {
		ip, _ := netip.ParseAddr(addr)
		mask, _ := netip.ParseAddr(fields[r.addrAt+1])
		if mask.IsUnspecified() {
			return familyOf(ip)
		}
		return famNone
	}
	if p, err := netip.ParsePrefix(addr); err == nil && p.Bits() == 0 {
		return familyOf(p.Addr())
	}
	return famNone
}

func familyOf(a netip.Addr) int {
	if a.Is4() || a.Is4In6() {
		return famV4
	}
	return famV6
}

// isLocalAddress: loopback and samehost rules stay "host" under Require TLS.
func isLocalAddress(fields []string, r hbaRecord) bool {
	addr := strings.Trim(fields[r.addrAt], `"`)
	if addr == "samehost" {
		return true
	}
	if r.hasMask {
		ip, err := netip.ParseAddr(addr)
		return err == nil && ip.IsLoopback()
	}
	if p, err := netip.ParsePrefix(addr); err == nil {
		return p.Addr().IsLoopback() && (p.Bits() >= 8 && p.Addr().Is4() || p.Bits() == 128)
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// hbaEdit is what an edit changed.
type hbaEdit struct {
	content  string
	replaced int // open rules replaced
	added    int // rules written for the allowed addresses
	toTLS    int // rules turned into hostssl
}

// restrictHBA replaces every rule open to all addresses with the same rule
// for each allowed address (of the rule's address family); requireTLS also
// turns remote "host" rules into "hostssl". Rules with the reject method
// are left alone.
func restrictHBA(content string, allowed []netip.Prefix, requireTLS bool, now time.Time) (hbaEdit, error) {
	lines, err := parseHBA(content)
	if err != nil {
		return hbaEdit{}, err
	}
	stamp := now.UTC().Format(time.RFC3339)
	var b strings.Builder
	var e hbaEdit
	for _, l := range lines {
		r, ok := recordOf(l.fields)
		if !ok || strings.EqualFold(l.fields[r.method], "reject") {
			b.WriteString(l.raw + "\n")
			continue
		}
		typ := r.typ
		if requireTLS && typ == "host" && !isLocalAddress(l.fields, r) {
			typ = "hostssl"
		}
		fam := openFamilies(l.fields, r)
		if fam == famNone {
			if typ == r.typ {
				b.WriteString(l.raw + "\n")
				continue
			}
			fmt.Fprintf(&b, "# Rowsafe %s: requires TLS now; was:\n# %s\n", stamp, l.raw)
			b.WriteString(joinRule(typ, l.fields, r, l.fields[r.addrAt], r.hasMask) + "\n")
			e.toTLS++
			continue
		}
		fmt.Fprintf(&b, "# Rowsafe %s: open to every address; replaced by the allowed addresses below. Was:\n# %s\n", stamp, l.raw)
		e.replaced++
		if typ != r.typ {
			e.toTLS++
		}
		for _, p := range allowed {
			if familyOf(p.Addr())&fam == 0 {
				continue
			}
			b.WriteString(joinRule(typ, l.fields, r, p.String(), false) + "\n")
			e.added++
		}
	}
	e.content = b.String()
	return e, nil
}

// joinRule writes a record with a new type and address, keeping its
// databases, users, method and options as they were written.
func joinRule(typ string, fields []string, r hbaRecord, addr string, keepMask bool) string {
	parts := []string{typ, fields[1], fields[2], addr}
	next := r.addrAt + 1
	if r.hasMask {
		if keepMask {
			parts = append(parts, fields[next])
		}
		next++
	}
	parts = append(parts, fields[next:]...)
	return strings.Join(parts, "\t")
}

// requireTLSHBA only turns remote "host" rules into "hostssl".
func requireTLSHBA(content string, now time.Time) (hbaEdit, error) {
	lines, err := parseHBA(content)
	if err != nil {
		return hbaEdit{}, err
	}
	stamp := now.UTC().Format(time.RFC3339)
	var b strings.Builder
	var e hbaEdit
	for _, l := range lines {
		r, ok := recordOf(l.fields)
		if !ok || r.typ != "host" || isLocalAddress(l.fields, r) || strings.EqualFold(l.fields[r.method], "reject") {
			b.WriteString(l.raw + "\n")
			continue
		}
		fmt.Fprintf(&b, "# Rowsafe %s: requires TLS now; was:\n# %s\n", stamp, l.raw)
		b.WriteString(joinRule("hostssl", l.fields, r, l.fields[r.addrAt], r.hasMask) + "\n")
		e.toTLS++
	}
	e.content = b.String()
	return e, nil
}

// parseAllowed validates allowed addresses: IPv4/IPv6 addresses or CIDRs,
// never one that opens everything, at most 32. A bare address becomes /32
// (/128).
func parseAllowed(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("no allowed addresses: say which addresses may connect")
	}
	if len(in) > 32 {
		return nil, fmt.Errorf("too many allowed addresses (%d, at most 32): use a range such as 10.0.0.0/16", len(in))
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || !p.IsValid() || strings.Contains(s, "%") {
			return nil, fmt.Errorf("%q is not an IP address or range (like 10.0.1.5 or 10.0.0.0/16)", s)
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 || p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
			return nil, fmt.Errorf("%s is too wide: it lets most of the internet in", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}
