package protocol

import (
	"fmt"
	"regexp"
	"strings"
)

// ---- Databases & users for Redis and Valkey
//
// Users are the server's ACL users. A new user gets one of three presets
// (DBAccess*), on the keys matching DBAdminParams.KeyPattern:
//
//   - read_only: the read commands (no KEYS, nothing dangerous), no pub/sub;
//   - read_write: every command but the administrative and dangerous ones
//     (FLUSHALL, FLUSHDB, KEYS, CONFIG, DEBUG, SHUTDOWN, MODULE, ACL...),
//     scripts and pub/sub included, plus INFO and naming its connection;
//   - owner ("admin" in the dashboard): every command.
//
// Passwords are stored by the server as SHA-256 (ACL SETUSER #<hash>), so
// the password itself never even crosses the Redis protocol. The default
// user, Rowsafe's own user and the users replicas sign in with are listed
// but never changed. "Databases" are the numbered logical databases: they
// are listed with their keys; Redis has a fixed number of them, so they
// can't be created or removed.

// MaxRedisKeyPatterns caps the patterns of one user.
const MaxRedisKeyPatterns = 10

// redisKeyPatternRE: a Redis glob pattern Rowsafe writes into an ACL rule
// (no spaces, quotes or backslashes, so it stays one rule in the ACL file).
var redisKeyPatternRE = regexp.MustCompile(`^[A-Za-z0-9:_.*?\[\]{}/@#|^!=+,%$<>-]{1,200}$`)

// RedisKeyPatterns splits and checks DBAdminParams.KeyPattern: nil for
// every key.
func RedisKeyPatterns(s string) ([]string, error) {
	pats := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' })
	if len(pats) > MaxRedisKeyPatterns {
		return nil, fmt.Errorf("too many key patterns (at most %d)", MaxRedisKeyPatterns)
	}
	for i, p := range pats {
		p = strings.TrimPrefix(p, "~")
		if !redisKeyPatternRE.MatchString(p) {
			return nil, fmt.Errorf("%q can't be used as a key pattern: use letters, digits and : _ . - with * for any characters (session:*)", p)
		}
		pats[i] = p
	}
	if len(pats) == 1 && pats[0] == "*" {
		return nil, nil
	}
	return pats, nil
}

// validateRedisDBAdmin checks what is Redis's own: no creating or removing
// logical databases, users on keys rather than databases.
func validateRedisDBAdmin(name string, p DBAdminParams) error {
	switch p.Action {
	case DBAdminCreateDatabase, DBAdminDropDatabase:
		return fmt.Errorf("%s has a fixed set of numbered logical databases (0 to 15 by default), so they can't be created or removed; "+
			"give apps their own user, or a key prefix, instead", name)
	case DBAdminCreateUser:
		if len(p.Databases) > 0 {
			return fmt.Errorf("a %s user reaches every logical database; limit it with a key pattern instead", name)
		}
		if _, err := RedisKeyPatterns(p.KeyPattern); err != nil {
			return err
		}
	case DBAdminDropUser:
		if p.ReassignTo != "" {
			return fmt.Errorf("%s users own nothing, so there is nothing to hand over", name)
		}
	default:
		if p.KeyPattern != "" {
			return fmt.Errorf("a key pattern is chosen when the user is created")
		}
	}
	return nil
}
