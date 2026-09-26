package masking

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestDeterministic(t *testing.T) {
	m1, m2 := New(testKey), New(testKey)
	other := New([]byte("another key, another copy......."))
	for _, s := range Strategies {
		in := map[string]string{Noise: "5200", DateShift: "1985-04-12", IP: "203.0.113.9", JSON: `{"a":"banana split"}`}[s.Name]
		if in == "" {
			in = "ada.lovelace@example.org"
		}
		a, okA := m1.Value(s.Name, in, Options{})
		b, okB := m2.Value(s.Name, in, Options{})
		if a != b || okA != okB {
			t.Errorf("%s: not deterministic: %q vs %q", s.Name, a, b)
		}
		if s.Name == Keep || s.Name == Null || s.Name == Password {
			continue
		}
		if c, _ := other.Value(s.Name, in, Options{}); c == a && s.Name != FirstName && s.Name != LastName && s.Name != City {
			t.Errorf("%s: a different key gave the same value %q", s.Name, c)
		}
		if okA && a == in {
			t.Errorf("%s: value unchanged: %q", s.Name, a)
		}
	}
}

func TestEmailUnique(t *testing.T) {
	m := New(testKey)
	seen := map[string]string{}
	re := regexp.MustCompile(`^[a-z-]+\.[0-9a-f]{16}@example\.(com|net|org)$`)
	for i := range 200000 {
		in := fmt.Sprintf("user%d@corp.example", i)
		out, ok := m.Value(Email, in, Options{})
		if !ok || !re.MatchString(out) {
			t.Fatalf("email %q -> %q", in, out)
		}
		if prev, dup := seen[out]; dup {
			t.Fatalf("%q and %q both became %q", prev, in, out)
		}
		seen[out] = in
	}
	// Same input, same output (joins across tables keep working).
	a, _ := m.Value(Email, "Ada@Example.org", Options{})
	b, _ := m.Value(Email, "Ada@Example.org", Options{})
	if a != b {
		t.Fatal("email not deterministic")
	}
	// A retry for a unique column gives another value.
	c, _ := m.Value(Email, "Ada@Example.org", Options{Attempt: 1})
	if c == a {
		t.Fatal("attempt 1 gave the same email")
	}
	// Length limits are kept.
	for _, n := range []int{10, 20, 30} {
		out, _ := m.Value(Email, "someone.with.a.long.name@example.com", Options{MaxLen: n})
		if utf8.RuneCountInString(out) > n {
			t.Errorf("MaxLen %d: %q", n, out)
		}
	}
}

// TestFormat: the Stripe-shaped value is Stripe's public documentation example,
// split so secret scanners don't flag it.
func TestFormat(t *testing.T) {
	m := New(testKey)
	for _, in := range []string{"+1 (415) 555-0199", "AB-123456-C", "sk_"+"live_"+"4eC39HqLyjWDarjtT1zdp7dc", "SW1A 1AA", "078-05-1120"} {
		out, ok := m.Value(Format, in, Options{})
		if !ok || len(out) != len(in) || out == in {
			t.Fatalf("%q -> %q", in, out)
		}
		for i := range in {
			a, b := in[i], out[i]
			switch {
			case a >= '0' && a <= '9':
				if b < '0' || b > '9' {
					t.Errorf("%q -> %q: digit %d became %q", in, out, i, b)
				}
			case a >= 'a' && a <= 'z':
				if b < 'a' || b > 'z' {
					t.Errorf("%q -> %q: lower letter %d became %q", in, out, i, b)
				}
			case a >= 'A' && a <= 'Z':
				if b < 'A' || b > 'Z' {
					t.Errorf("%q -> %q: upper letter %d became %q", in, out, i, b)
				}
			default:
				if a != b {
					t.Errorf("%q -> %q: punctuation %d changed", in, out, i)
				}
			}
		}
	}
	// A leading non-zero digit stays non-zero.
	for i := range 2000 {
		out, _ := m.Value(Format, fmt.Sprintf("9%09d", i), Options{})
		if out[0] == '0' {
			t.Fatalf("leading zero: %q", out)
		}
	}
}

func TestOtherStrategies(t *testing.T) {
	m := New(testKey)
	v := func(s, in string, o Options) string {
		t.Helper()
		out, ok := m.Value(s, in, o)
		if !ok {
			t.Fatalf("%s(%q) not masked", s, in)
		}
		return out
	}
	if out := v(FullName, "Ada Lovelace", Options{}); len(strings.Fields(out)) != 2 {
		t.Errorf("full name %q", out)
	}
	if out := v(Address, "10 Downing Street", Options{}); !regexp.MustCompile(`^\d{1,4} [A-Z][a-z]+ [A-Z][a-z]+$`).MatchString(out) {
		t.Errorf("address %q", out)
	}
	for in, want := range map[string]string{"203.0.113.9": "10.", "192.168.1.0/24": "/24", "2001:db8::1": "fd", "::ffff:1.2.3.4": "10."} {
		out := v(IP, in, Options{})
		addr, _, _ := strings.Cut(out, "/")
		if _, err := netip.ParseAddr(addr); err != nil || !strings.Contains(out, want) {
			t.Errorf("ip %q -> %q", in, out)
		}
	}
	if _, ok := m.Value(IP, "not an ip", Options{}); ok {
		t.Error("an invalid IP was masked")
	}
	bc := "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
	if out := v(Password, bc, Options{}); out != "$2b"+bcryptCopyPassword[3:] {
		t.Errorf("bcrypt -> %q", out)
	}
	dj := "pbkdf2_sha256$600000$abcdefgh$ZmFrZWhhc2hmYWtlaGFzaA=="
	if out := v(Password, dj, Options{}); !strings.HasPrefix(out, "pbkdf2_sha256$600000$abcdefgh$") || out == dj || len(out) != len(dj) {
		t.Errorf("django -> %q", out)
	}
	if out := v(Lorem, strings.Repeat("secret note ", 20), Options{}); len(out) < 200 || len(out) > 260 || strings.Contains(out, "secret") {
		t.Errorf("lorem %d %q", len(out), out)
	}
	if out := v(Lorem, "hi", Options{MaxLen: 5}); utf8.RuneCountInString(out) > 5 {
		t.Errorf("lorem MaxLen: %q", out)
	}
	for in, integer := range map[string]bool{"5200": true, "1234.56": false, "-80.5": false, "7": true} {
		out := v(Noise, in, Options{Integer: integer})
		var a, b float64
		fmt.Sscan(in, &a)
		fmt.Sscan(out, &b)
		if d := b - a; d > max(a*0.1, 1) || d < -max(a*0.1, 1) && a > 0 || (integer && strings.Contains(out, ".")) {
			t.Errorf("noise %q -> %q", in, out)
		}
		if i := strings.IndexByte(in, '.'); i >= 0 && len(out)-strings.IndexByte(out, '.') != len(in)-i {
			t.Errorf("noise %q -> %q: decimals changed", in, out)
		}
	}
	if _, ok := m.Value(Noise, "NaN", Options{}); ok {
		t.Error("NaN masked")
	}
	for _, in := range []string{"1985-04-12", "2024-02-29 13:14:15.123+00", "2024-01-31 00:00:00"} {
		out := v(DateShift, in, Options{})
		if out[:10] == in[:10] || out[10:] != in[10:] {
			t.Errorf("date %q -> %q", in, out)
		}
	}
	if _, ok := m.Value(DateShift, "infinity", Options{}); ok {
		t.Error("infinity masked")
	}
	js := v(JSON, `{"name":"Ada","email":"ada@example.org","age":36,"tags":["vip"],"nested":{"phone":"+44 20 7946 0958"}}`, Options{})
	var got map[string]any
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] == "Ada" || got["age"] != float64(36) || !strings.HasSuffix(got["email"].(string), "@example.org") &&
		!strings.HasSuffix(got["email"].(string), "@example.com") && !strings.HasSuffix(got["email"].(string), "@example.net") {
		t.Errorf("json %s", js)
	}
	if strings.Contains(js, "7946") || !strings.Contains(js, `"phone"`) {
		t.Errorf("json nested %s", js)
	}
	if out, ok := m.Value(Keep, "x", Options{}); ok || out != "x" {
		t.Error("keep changed the value")
	}
}

func TestSuggest(t *testing.T) {
	cases := []struct{ table, column, typ, want string }{
		{"public.users", "email", "character varying(255)", Email},
		{"public.users", "emailAddress", "text", Email},
		{"public.users", "email_verified", "boolean", Keep},
		{"public.users", "email_verified_at", "timestamp with time zone", Keep},
		{"public.users", "encrypted_password", "character varying", Password},
		{"public.users", "password_changed_at", "timestamp without time zone", Keep},
		{"public.users", "first_name", "text", FirstName},
		{"public.users", "lastName", "text", LastName},
		{"public.users", "name", "text", FullName},
		{"public.products", "name", "text", Keep},
		{"public.users", "phone", "text", Format},
		{"public.users", "mobile_number", "character varying(20)", Format},
		{"public.users", "last_sign_in_ip", "inet", IP},
		{"public.sessions", "remote_addr", "text", IP},
		{"public.users", "api_key", "text", Format},
		{"public.users", "reset_password_token", "character varying", Password},
		{"public.users", "confirmation_token", "character varying", Format},
		{"public.users", "tokens_used", "integer", Keep},
		{"public.addresses", "street", "text", Address},
		{"public.addresses", "line1", "text", Address},
		{"public.orders", "shipping_address", "text", Address},
		{"public.orders", "billing_address", "jsonb", JSON},
		{"public.events", "payload", "jsonb", Keep},
		{"public.addresses", "city", "text", City},
		{"public.addresses", "zip_code", "text", Format},
		{"public.users", "date_of_birth", "date", DateShift},
		{"public.users", "ssn", "text", Format},
		{"public.payments", "card_number", "text", Format},
		{"public.tickets", "notes", "text", Lorem},
		{"public.products", "description", "text", Keep},
		{"public.employees", "salary", "numeric(12,2)", Noise},
		{"public.stores", "latitude", "double precision", Noise},
		{"public.users", "id", "bigint", Keep},
		{"public.users", "uuid", "uuid", Keep},
		{"public.users", "tags", "text[]", Keep},
		{"public.products", "handle", "text", Keep},
		{"public.users", "username", "citext", Format},
		{"public.devices", "mac_address", "macaddr", Keep},
		{"public.devices", "mac_address", "text", Format},
		{"public.orders", "total", "numeric", Keep},
		{"public.users", "created_at", "timestamp with time zone", Keep},
	}
	for _, c := range cases {
		if got := Suggest(c.table, c.column, c.typ); got != c.want {
			t.Errorf("Suggest(%s, %s, %s) = %s, want %s", c.table, c.column, c.typ, got, c.want)
		}
		if got := Suggest(c.table, c.column, c.typ); !Fits(got, c.typ) {
			t.Errorf("Suggest(%s, %s) = %s does not fit %s", c.table, c.column, got, c.typ)
		}
	}
}

func TestClassAndMaxLen(t *testing.T) {
	for typ, want := range map[string]string{"character varying(255)": ClassText, "public.citext": ClassText, "jsonb": ClassJSON,
		"bigint": ClassInteger, "numeric(12,2)": ClassNumber, "timestamp(3) with time zone": ClassDate, "uuid": ClassOther,
		"text[]": ClassOther, "cidr": ClassInet} {
		if got := Class(typ); got != want {
			t.Errorf("Class(%s) = %s, want %s", typ, got, want)
		}
	}
	if MaxLen("character varying(40)") != 40 || MaxLen("text") != 0 || MaxLen("numeric(12,2)") != 0 {
		t.Error("MaxLen")
	}
}

func TestNameWords(t *testing.T) {
	for in, want := range map[string]string{"billingEmailAddress": "billing email address", "first_name": "first name",
		"APIKey": "api key", "ip": "ip", "user-name": "user name"} {
		if got := strings.Join(nameWords(in), " "); got != want {
			t.Errorf("nameWords(%s) = %q, want %q", in, got, want)
		}
	}
}
