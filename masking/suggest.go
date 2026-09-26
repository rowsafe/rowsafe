package masking

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Type classes of PostgreSQL column types (format_type output).
const (
	ClassText    = "text"    // text, varchar, char, citext, name
	ClassJSON    = "json"    // json, jsonb
	ClassInet    = "inet"    // inet, cidr
	ClassNumber  = "number"  // integers, numeric, floats
	ClassInteger = "integer" // smallint, integer, bigint (a ClassNumber)
	ClassDate    = "date"    // date, timestamp, timestamptz
	ClassOther   = "other"   // everything else (uuid, bytea, boolean, arrays, enums...): keep or NULL
)

// Class classifies a column type as format_type prints it.
func Class(typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	if strings.HasSuffix(t, "[]") {
		return ClassOther
	}
	base, _, _ := strings.Cut(t, "(")
	base = strings.TrimSpace(base)
	if i := strings.LastIndexByte(base, '.'); i >= 0 { // public.citext
		base = base[i+1:]
	}
	switch base {
	case "text", "character varying", "varchar", "character", "char", "bpchar", "citext", "name":
		return ClassText
	case "json", "jsonb":
		return ClassJSON
	case "inet", "cidr":
		return ClassInet
	case "smallint", "integer", "bigint", "int", "int2", "int4", "int8":
		return ClassInteger
	case "numeric", "decimal", "real", "double precision", "float4", "float8":
		return ClassNumber
	case "date":
		return ClassDate
	}
	if strings.HasPrefix(base, "timestamp") {
		return ClassDate
	}
	return ClassOther
}

// MaxLen is a text type's length limit ("character varying(40)" -> 40), or
// 0.
func MaxLen(typ string) int {
	t := strings.ToLower(typ)
	if Class(t) != ClassText {
		return 0
	}
	_, rest, ok := strings.Cut(t, "(")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), ")"))
	if err != nil {
		return 0
	}
	return n
}

// Allowed lists the strategies that fit a column type.
func Allowed(typ string) []string {
	switch Class(typ) {
	case ClassText:
		return []string{Keep, Email, FirstName, LastName, FullName, Address, City, Format, IP, Password, Lorem, DateShift, Null}
	case ClassJSON:
		return []string{Keep, JSON, Null}
	case ClassInet:
		return []string{Keep, IP, Null}
	case ClassNumber, ClassInteger:
		return []string{Keep, Noise, Null}
	case ClassDate:
		return []string{Keep, DateShift, Null}
	}
	return []string{Keep, Null}
}

// Fits reports whether strategy may be used on a column of type typ.
func Fits(strategy, typ string) bool { return slices.Contains(Allowed(typ), strategy) }

// Suggest proposes a strategy for a column from its table, name and type:
// anything that looks personal or secret is masked, the rest kept. People
// review the suggestions before relying on them.
func Suggest(table, column, typ string) string {
	class := Class(typ)
	words := nameWords(column)
	has := func(ws ...string) bool {
		for _, w := range ws {
			if slices.Contains(words, w) {
				return true
			}
		}
		return false
	}
	name := strings.Join(words, "_")
	joined := strings.Join(words, "")
	text := class == ClassText
	pick := func(s string) string {
		if Fits(s, typ) {
			return s
		}
		return Keep
	}

	switch {
	case class == ClassOther:
		return Keep
	case class == ClassJSON:
		if has("profile", "personal", "contact", "billing", "shipping", "address", "identity", "customer", "pii") {
			return JSON
		}
		return Keep
	case has("email", "mail") || joined == "emailaddress":
		return pick(Email)
	case has("password", "passwd", "pwd") || name == "password_digest" || name == "pass_hash":
		return pick(Password)
	case class == ClassInet || has("ip") || joined == "remoteaddr" || joined == "ipaddress":
		return pick(IP)
	case secretRE.MatchString(name) || has("token", "secret", "salt", "otp", "totp", "apikey"):
		if text {
			return Format
		}
		return Keep
	case has("phone", "mobile", "cell", "telephone", "tel", "fax", "msisdn", "whatsapp", "cellphone", "phonenumber"):
		return pick(Format)
	case idNumberRE.MatchString(name):
		return pick(Format)
	case has("firstname", "fname", "forename") || name == "first_name" || name == "given_name":
		return pick(FirstName)
	case has("lastname", "lname", "surname") || name == "last_name" || name == "family_name":
		return pick(LastName)
	case has("fullname", "displayname") || name == "full_name" || name == "display_name" || contactNameRE.MatchString(name):
		return pick(FullName)
	case (name == "name" || name == "names") && personTable(table):
		return pick(FullName)
	case has("username", "nickname") || name == "user_name" || name == "screen_name" || (has("login", "handle") && personTable(table)):
		return pick(Format)
	case has("mac") && (has("address") || has("addr")):
		return pick(Format)
	case has("street", "address", "addr") || name == "address_line1" || name == "address_line2" || name == "line1" && addressTable(table) || name == "line2" && addressTable(table):
		return pick(Address)
	case has("city", "town"):
		return pick(City)
	case has("zip", "zipcode", "postcode", "postal", "postalcode"):
		return pick(Format)
	case has("dob", "birth", "birthday", "birthdate", "born"):
		if class == ClassDate {
			return DateShift
		}
		return pick(Format)
	case has("latitude", "longitude", "lat", "lng", "lon"):
		return pick(Noise)
	case has("salary", "income", "wage", "wages", "compensation"):
		return pick(Noise)
	case text && has("note", "notes", "comment", "comments", "bio", "biography", "about", "message", "messages", "feedback", "remarks"):
		return Lorem
	}
	return Keep
}

var (
	secretRE      = regexp.MustCompile(`(^|_)(api_?key|access_?key|secret_?key|private_?key|session_?(key|id|token)|auth_?(token|key)|recovery_?codes?|refresh_?token|webhook_?secret|signing_?key|encryption_?key|mfa_?(secret|seed)|2fa|otp_?secret)($|_)`)
	idNumberRE    = regexp.MustCompile(`(^|_)(ssn|social_?security(_?number)?|sin|nino?|national_?id(_?number)?|tax_?(id|number)|tin|passport(_?(no|number))?|driver_?s?_?licen[cs]e(_?(no|number))?|licen[cs]e_?number|iban|account_?number|routing_?number|card_?number|cc_?number|credit_?card(_?number)?|pan|cvv|cvc|bank_?account)($|_)`)
	contactNameRE = regexp.MustCompile(`^(contact|customer|client|billing|shipping|legal|real|emergency_?contact|owner|holder|card_?holder|recipient|sender|patient|guardian|parent|spouse)_?name$`)
)

var personWords = []string{"user", "users", "customer", "customers", "client", "clients", "contact", "contacts",
	"person", "persons", "people", "member", "members", "employee", "employees", "patient", "patients",
	"student", "students", "account", "accounts", "profile", "profiles", "author", "authors", "lead", "leads",
	"subscriber", "subscribers", "guest", "guests", "applicant", "applicants", "candidate", "candidates",
	"staff", "teacher", "teachers", "driver", "drivers", "owner", "owners", "tenant", "tenants", "buyer", "buyers",
	"seller", "sellers", "recipient", "recipients", "attendee", "attendees", "volunteer", "volunteers"}

func personTable(table string) bool {
	_, name, ok := strings.Cut(table, ".")
	if !ok {
		name = table
	}
	for _, w := range nameWords(name) {
		if slices.Contains(personWords, w) {
			return true
		}
	}
	return false
}

func addressTable(table string) bool {
	return strings.Contains(strings.ToLower(table), "address")
}

// nameWords splits snake_case, kebab-case and camelCase into lowercase
// words: "billingEmailAddress" -> billing, email, address.
func nameWords(s string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}
