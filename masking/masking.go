// Package masking turns real values into realistic fake ones for Guard's
// safe copies. It runs on the database server, inside the agent: the real
// values never leave it.
//
// Masking is deterministic: the same value always becomes the same fake
// value under the same key (a secret kept on the server), so joins across
// tables keep working, and repeated copies look the same. It is one-way: the
// fake value can't be turned back without the key, and most strategies drop
// information for good.
package masking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Strategies.
const (
	Keep      = "keep"       // leave the column as it is
	Null      = "null"       // set it to NULL
	Email     = "email"      // olivia.3f9a2c1b7e4d5a6b@example.com (unique)
	FirstName = "first_name" // Olivia
	LastName  = "last_name"  // Martin
	FullName  = "full_name"  // Olivia Martin
	Address   = "address"    // 4821 Maple Avenue
	City      = "city"       // Riverton
	Format    = "format"     // same shape: digits stay digits, letters stay letters (phones, IDs, tokens)
	IP        = "ip"         // 10.x.y.z / fd00::...
	Password  = "password"   // bcrypt hashes become the hash of CopyPassword; others keep their format
	Lorem     = "lorem"      // lorem ipsum of about the same length
	Noise     = "noise"      // numbers moved by up to 10%
	DateShift = "date_shift" // dates moved by up to 30 days
	JSON      = "json"       // every string inside the JSON masked, keys and structure kept
)

// CopyPassword is the password every bcrypt password hash accepts on a
// masked copy, so people can sign in to their app running against it.
const CopyPassword = "rowsafe-copy"

// bcryptCopyPassword is bcrypt(CopyPassword) at cost 10.
const bcryptCopyPassword = "$2a$10$ZQzBfrwZ1yImcA9o8meBnuNjAS3OaRMHmqV5Jx3Yqx6IMMSrKniR6"

// Info describes a strategy for people choosing one.
type Info struct {
	Name        string
	Label       string
	Description string
	Example     string
}

// Strategies lists every strategy, in the order the dashboard shows them.
var Strategies = []Info{
	{Email, "Email", "A fake, unique email at example.com.", "olivia.3f9a2c1b7e4d5a6b@example.com"},
	{FirstName, "First name", "A common first name.", "Olivia"},
	{LastName, "Last name", "A common last name.", "Martin"},
	{FullName, "Full name", "A first and last name.", "Olivia Martin"},
	{Address, "Street address", "A made-up street address.", "4821 Maple Avenue"},
	{City, "City", "A made-up city name.", "Riverton"},
	{Format, "Same format", "Digits stay digits and letters stay letters, so phone numbers, IDs and tokens keep their shape.", "+1 (415) 555-0199 → +8 (203) 961-4471"},
	{IP, "IP address", "A private IP address (10.x.x.x, or fd00:: for IPv6).", "10.24.181.7"},
	{Password, "Password hash", "bcrypt hashes become the hash of \"" + CopyPassword + "\" so you can sign in; other hashes keep their format but match nothing.", ""},
	{Lorem, "Lorem ipsum", "Placeholder text of about the same length.", "Lorem ipsum dolor sit amet"},
	{Noise, "Numbers ±10%", "Moves each number by up to 10% (whole numbers stay whole).", "5200 → 4987"},
	{DateShift, "Dates ±30 days", "Moves each date by up to 30 days.", "1985-04-12 → 1985-05-03"},
	{JSON, "JSON strings", "Masks every text value inside the JSON; keys, numbers and structure stay.", `{"name":"Wkvab"}`},
	{Null, "Empty (NULL)", "Removes the value.", ""},
	{Keep, "Keep", "Leaves the real value. Only for columns without personal data.", ""},
}

// Known reports whether s is a strategy.
func Known(s string) bool {
	for _, i := range Strategies {
		if i.Name == s {
			return true
		}
	}
	return false
}

// Masker masks values under a secret key.
type Masker struct {
	key []byte
}

// New returns a Masker for key (at least 16 bytes of randomness).
func New(key []byte) *Masker { return &Masker{key: append([]byte(nil), key...)} }

// Options tune one value's masking.
type Options struct {
	// MaxLen is the column's length limit in characters (varchar(n)); 0:
	// none.
	MaxLen int
	// Attempt > 0 derives a different value, for a unique column whose
	// first fake value is already taken.
	Attempt int
	// Integer: the column holds whole numbers (Noise).
	Integer bool
}

// stream is a deterministic byte source for one value.
type stream struct {
	key   []byte
	seed  []byte
	buf   []byte
	block uint32
}

func (m *Masker) stream(strategy, value string, attempt int) *stream {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(strategy))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	if attempt > 0 {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(attempt))
		mac.Write([]byte{0})
		mac.Write(b[:])
	}
	return &stream{key: m.key, seed: mac.Sum(nil)}
}

func (s *stream) byte() byte {
	if len(s.buf) == 0 {
		if s.block == 0 {
			s.buf = s.seed
		} else {
			mac := hmac.New(sha256.New, s.key)
			mac.Write(s.seed)
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], s.block)
			mac.Write(b[:])
			s.buf = mac.Sum(nil)
		}
		s.block++
	}
	b := s.buf[0]
	s.buf = s.buf[1:]
	return b
}

// intn returns a number in [0, n) (n <= 65536; the bias is negligible).
func (s *stream) intn(n int) int {
	v := int(s.byte())<<16 | int(s.byte())<<8 | int(s.byte())
	return v % n
}

func (s *stream) hex(n int) string {
	b := make([]byte, (n+1)/2)
	for i := range b {
		b[i] = s.byte()
	}
	return hex.EncodeToString(b)[:n]
}

func (s *stream) pick(list []string) string { return list[s.intn(len(list))] }

// Value masks one non-NULL value (in its PostgreSQL text form). ok is false
// when the strategy leaves it as it is (Keep, or a value it can't read, such
// as "infinity").
func (m *Masker) Value(strategy, in string, o Options) (out string, ok bool) {
	s := m.stream(strategy, in, o.Attempt)
	switch strategy {
	case Keep, Null:
		return in, false
	case Email:
		out = m.email(s, o.MaxLen)
	case FirstName:
		out = s.pick(firstNames)
	case LastName:
		out = s.pick(lastNames)
	case FullName:
		out = s.pick(firstNames) + " " + s.pick(lastNames)
		if o.Attempt > 0 {
			out += " " + strings.ToUpper(s.hex(2))
		}
	case Address:
		out = strconv.Itoa(1+s.intn(9999)) + " " + s.pick(streetNames) + " " + s.pick(streetKinds)
	case City:
		out = s.pick(cities)
	case Format:
		out = sameFormat(s, in)
	case IP:
		out, ok = fakeIP(s, in)
		if !ok {
			return in, false
		}
	case Password:
		out = fakePasswordHash(s, in)
	case Lorem:
		out = lorem(s, utf8.RuneCountInString(in))
	case Noise:
		return noise(s, in, o.Integer)
	case DateShift:
		return shiftDate(s, in)
	case JSON:
		return m.maskJSON(in)
	default:
		return in, false
	}
	return truncate(out, o.MaxLen), true
}

func truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// email is first.<16 hex>@example.com: 64 random bits make two emails
// colliding vanishingly rare, and unique columns retry with Attempt.
func (m *Masker) email(s *stream, maxLen int) string {
	first := strings.ToLower(s.pick(firstNames))
	h := s.hex(16)
	domain := s.pick([]string{"example.com", "example.net", "example.org"})
	out := first + "." + h + "@" + domain
	if maxLen > 0 && len(out) > maxLen {
		out = h + "@" + domain
		if len(out) > maxLen {
			out = truncate(h+"@x.io", maxLen)
		}
	}
	return out
}

// sameFormat replaces digits with digits and letters with letters of the
// same case, keeping everything else (spaces, dashes, +, @, dots...). A
// leading non-zero digit stays non-zero so numbers keep their length.
func sameFormat(s *stream, in string) string {
	var b strings.Builder
	first := true
	for _, r := range in {
		switch {
		case r >= '0' && r <= '9':
			d := s.intn(10)
			if first && r != '0' {
				d = 1 + s.intn(9)
			}
			b.WriteByte(byte('0' + d))
			first = false
		case r >= 'a' && r <= 'z':
			b.WriteByte(byte('a' + s.intn(26)))
			first = false
		case r >= 'A' && r <= 'Z':
			b.WriteByte(byte('A' + s.intn(26)))
			first = false
		case unicode.IsLetter(r):
			if unicode.IsUpper(r) {
				b.WriteByte(byte('A' + s.intn(26)))
			} else {
				b.WriteByte(byte('a' + s.intn(26)))
			}
			first = false
		case unicode.IsDigit(r):
			b.WriteByte(byte('0' + s.intn(10)))
			first = false
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fakeIP maps an address to one in 10.0.0.0/8 or fd00::/8, keeping a
// /prefix suffix.
func fakeIP(s *stream, in string) (string, bool) {
	addr, suffix, _ := strings.Cut(strings.TrimSpace(in), "/")
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", false
	}
	var out netip.Addr
	if ip.Is4() || ip.Is4In6() {
		out = netip.AddrFrom4([4]byte{10, s.byte(), s.byte(), 1 + byte(s.intn(254))})
	} else {
		var b [16]byte
		b[0] = 0xfd
		for i := 1; i < 16; i++ {
			b[i] = s.byte()
		}
		out = netip.AddrFrom16(b)
	}
	if suffix != "" {
		bits, err := strconv.Atoi(suffix)
		if err != nil {
			return "", false
		}
		p, err := out.Prefix(bits)
		if err != nil {
			return "", false
		}
		if p.Addr() == out {
			return p.String(), true
		}
		return out.String() + "/" + suffix, true
	}
	return out.String(), true
}

// fakePasswordHash: bcrypt hashes ($2a$, $2b$, $2y$) become the hash of
// CopyPassword with the same variant; anything else keeps everything up to
// its last '$' and gets a same-format tail, so it matches no password.
func fakePasswordHash(s *stream, in string) string {
	if len(in) == 60 && strings.HasPrefix(in, "$2") && in[3] == '$' {
		return in[:3] + bcryptCopyPassword[3:]
	}
	if i := strings.LastIndexByte(in, '$'); i >= 0 && i < len(in)-1 {
		return in[:i+1] + sameFormat(s, in[i+1:])
	}
	return sameFormat(s, in)
}

// lorem is placeholder text of about n characters (at least one word, at
// most 2000 characters).
func lorem(s *stream, n int) string {
	n = min(max(n, 1), 2000)
	var b strings.Builder
	for b.Len() < n {
		w := s.pick(loremWords)
		if b.Len() == 0 {
			w = strings.ToUpper(w[:1]) + w[1:]
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(w)
	}
	out := b.String()
	if len(out) > n+8 {
		if i := strings.LastIndexByte(out[:n+1], ' '); i > 0 {
			out = out[:i]
		}
	}
	return out + "."
}

// noise moves a number by up to ±10%, keeping its sign, whole-ness and
// decimal places.
func noise(s *stream, in string, integer bool) (string, bool) {
	t := strings.TrimSpace(in)
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return in, false
	}
	factor := 1 + (float64(s.intn(20001))-10000)/100000 // [-0.1, +0.1]
	v := f * factor
	decimals := 0
	if i := strings.IndexByte(t, '.'); i >= 0 {
		end := len(t)
		if j := strings.IndexAny(t, "eE"); j > i {
			end = j
		}
		decimals = end - i - 1
	}
	if integer || !strings.ContainsAny(t, ".eE") {
		r := math.Round(v)
		if r == 0 && f != 0 {
			r = math.Copysign(1, f)
		}
		return strconv.FormatFloat(r, 'f', 0, 64), true
	}
	return strconv.FormatFloat(v, 'f', decimals, 64), true
}

// shiftDate moves the leading YYYY-MM-DD of an ISO date or timestamp by up
// to ±30 days (never 0), keeping the time and zone.
func shiftDate(s *stream, in string) (string, bool) {
	if len(in) < 10 {
		return in, false
	}
	d, err := time.Parse("2006-01-02", in[:10])
	if err != nil {
		return in, false
	}
	days := 1 + s.intn(30)
	if s.byte()&1 == 0 {
		days = -days
	}
	return d.AddDate(0, 0, days).Format("2006-01-02") + in[10:], true
}

// maskJSON masks every string value (not the keys) of a JSON document.
// Strings that look like emails become fake emails.
func (m *Masker) maskJSON(in string) (string, bool) {
	var v any
	dec := json.NewDecoder(strings.NewReader(in))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return in, false
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				t[k] = walk(e)
			}
			return t
		case []any:
			for i, e := range t {
				t[i] = walk(e)
			}
			return t
		case string:
			if looksLikeEmail(t) {
				out, _ := m.Value(Email, t, Options{})
				return out
			}
			return sameFormat(m.stream(Format, t, 0), t)
		}
		return x
	}
	out, err := json.Marshal(walk(v))
	if err != nil {
		return in, false
	}
	return string(out), true
}

func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-3 && strings.Contains(s[at:], ".") && !strings.ContainsAny(s, " \t\n")
}
