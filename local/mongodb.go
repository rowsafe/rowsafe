package local

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
)

// MongoDB (mongodb://, mongodb+srv://): the MongoDB engine's own reading
// and fixes on the connection (internal/engine/mongodb, direct.go), and
// pulse's MongoDB rules. What needs the server itself is left out: the
// disk when it runs on another machine, settings changes (they live in its
// configuration file), backups.

// mongoConn is a MongoDB server reached with a connection string.
type mongoConn struct {
	uri  string // with its password
	cs   *connstring.ConnString
	host string // the first host, for people
}

// isMongoURL reports whether s is a mongodb:// or mongodb+srv:// URL.
func isMongoURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "mongodb://") || strings.HasPrefix(s, "mongodb+srv://")
}

// openMongo parses mongodb://user:password@host:27017/db?authSource=admin
// (several hosts, mongodb+srv:// and the driver's options too).
func openMongo(connString string) (*DB, error) {
	// An SRV record is looked up when connecting, not here: its options are
	// read as a mongodb:// string's.
	parse, srv := connString, false
	if scheme, rest, _ := strings.Cut(connString, "://"); strings.EqualFold(scheme, connstring.SchemeMongoDBSRV) {
		parse, srv = "mongodb://"+rest, true
	}
	cs, err := connstring.ParseAndValidate(parse)
	if err == nil && srv {
		cs.Scheme = connstring.SchemeMongoDBSRV
	}
	if err != nil {
		// The driver's error may quote the string, password included.
		return nil, errors.New("reading the connection string: it isn't a valid mongodb:// URL (mongodb://USER:PASSWORD@HOST:27017/DB?authSource=admin)")
	}
	mc := &mongoConn{uri: connString, cs: cs}
	if len(cs.Hosts) > 0 {
		mc.host = cs.Hosts[0]
		if h, p, err := net.SplitHostPort(mc.host); err == nil && p == "27017" {
			mc.host = h
		}
		if strings.HasSuffix(mc.host, ".sock") {
			mc.host = "localhost"
		}
	}
	d := &DB{mg: mc, PasswordInURL: cs.PasswordSet}
	d.Ref = withoutPassword(connString)
	return d, nil
}

// withoutPassword removes the password from a URL's user information (a
// mongodb:// URL may list several hosts, which net/url doesn't read).
func withoutPassword(s string) string {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return s
	}
	end := len(rest)
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		end = i
	}
	at := strings.LastIndex(rest[:end], "@")
	if at < 0 {
		return s
	}
	user, _, _ := strings.Cut(rest[:at], ":")
	return scheme + "://" + user + rest[at:]
}

func (m *mongoConn) name() string {
	switch {
	case m.cs.Database != "":
		return m.cs.Database
	case m.cs.Username != "":
		return m.cs.Username
	}
	return "mongodb"
}

// local: every host is this machine (an SRV record never is).
func (m *mongoConn) local() bool {
	if m.cs.Scheme == connstring.SchemeMongoDBSRV || len(m.cs.Hosts) == 0 {
		return false
	}
	for _, hp := range m.cs.Hosts {
		h := hp
		if x, _, err := net.SplitHostPort(hp); err == nil {
			h = x
		}
		if h != "localhost" && h != "127.0.0.1" && h != "::1" && !strings.HasSuffix(h, ".sock") {
			return false
		}
	}
	return true
}

// mongoSettingsLocked says why settings don't change over a connection.
const mongoSettingsLocked = "MongoDB keeps its settings in its configuration file on the server (mongod.conf), which Rowsafe can't reach over a connection: " +
	"set them there and restart MongoDB when it suits you, or let the Rowsafe agent on the server do it."

func (d *DB) mongoConnectError(err error) error {
	if err == nil {
		return nil
	}
	user := d.mg.cs.Username
	if user == "" {
		return fmt.Errorf("can't read MongoDB on %s: %w", d.Host(), err)
	}
	return fmt.Errorf("can't read MongoDB on %s as %s: %w", d.Host(), user, err)
}
