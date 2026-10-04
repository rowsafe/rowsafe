package redis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Rowsafe's ACL user gets the least it needs:
//
//   - read and inspect: the read commands (not KEYS), INFO, CONFIG GET,
//     CLIENT LIST, SLOWLOG, LATENCY, MODULE LIST, MEMORY USAGE/STATS;
//   - the replication handshake: SYNC, PSYNC, REPLCONF (snapshots and the
//     stream of changes);
//   - BGSAVE and LASTSAVE (snapshot mode);
//   - DUMP and RESTORE (bringing keys back), SWAPDB, FLUSHDB and DEL (rewind
//     in place: only into and out of an empty logical database, and its own
//     marker key);
//   - the fixes: CONFIG SET and REWRITE, MEMORY PURGE, CLIENT KILL.
//
// It holds no pub/sub channels and can't run scripts, MONITOR, DEBUG or
// FLUSHALL.
const aclRules = "~* resetchannels -@all +@read -keys +ping +info +select +dbsize +scan +type +exists +ttl +pttl +pexpiretime " +
	"+object|encoding +dump +restore +swapdb +flushdb +del +memory|usage +memory|stats +memory|purge " +
	"+config|get +config|set +config|rewrite +client|list +client|kill +client|setname +client|info +client|id " +
	"+slowlog|get +slowlog|len +latency|latest +module|list +role +sync +psync +replconf +bgsave +lastsave +acl|whoami"

// Installer errors (exit codes in cmd/rowsafe-agent).
var (
	ErrNeedAdmin       = errors.New("the server asks for a password: an administrator's login is needed once to create Rowsafe's own user (it is used once and never saved)")
	ErrAdminRefused    = errors.New("the server refused that administrator login")
	ErrCantManageUsers = errors.New("that login can't create users on this server (it needs the ACL command)")
)

// LoginResult says how Rowsafe's user was kept across restarts.
type LoginResult struct {
	// Persisted is "aclfile" (ACL SAVE), "config" (CONFIG REWRITE) or
	// "none": the server forgets the user when it restarts unless root adds
	// ACLLine to its configuration file.
	Persisted string
	ACLLine   string // "user rowsafe on #<sha256> ..." (the password's hash, never the password)
	Why       string // why it couldn't be kept, when Persisted is none
}

// CreateLogin creates (or refreshes) Rowsafe's user with a new random
// password, signing in as adminUser (default: the default user, without a
// password unless adminPass is given), and saves the login for the agent.
func CreateLogin(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPass string) (LoginResult, error) {
	var res LoginResult
	l := Login{User: LoginUser}
	addr := addrOf(l, port)
	c, err := dial(ctx, addr)
	if err != nil {
		return res, plainConnError(err)
	}
	defer c.Close()
	switch {
	case adminUser != "" || adminPass != "":
		args := []any{"AUTH"}
		if adminUser != "" {
			args = append(args, adminUser)
		}
		args = append(args, adminPass)
		if _, err := c.do(ctx, args...); err != nil {
			if isRespError(err, "WRONGPASS") || strings.Contains(err.Error(), "invalid") {
				return res, ErrAdminRefused
			}
			return res, err
		}
	}
	m, err := c.info(ctx, "server")
	if err != nil {
		if isRespError(err, "NOAUTH") {
			if adminUser == "" && adminPass == "" {
				return res, ErrNeedAdmin
			}
			return res, ErrAdminRefused
		}
		if isRespError(err, "NOPERM") {
			return res, ErrCantManageUsers
		}
		return res, err
	}
	in := infoFrom(m)
	if why := in.supported(in.Engine); why != "" {
		return res, errors.New(why)
	}
	pw, err := randomPassword()
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256([]byte(pw))
	hash := "#" + hex.EncodeToString(sum[:])
	args := []any{"ACL", "SETUSER", LoginUser, "reset", "on", hash}
	for _, r := range strings.Fields(aclRules) {
		args = append(args, r)
	}
	if _, err := c.do(ctx, args...); err != nil {
		if isRespError(err, "NOPERM") || isUnknownCommand(err) {
			return res, ErrCantManageUsers
		}
		return res, fmt.Errorf("creating Rowsafe's user: %w", err)
	}
	// It signs in?
	t, err := connectAddr(ctx, addr, LoginUser, pw, clientName)
	if err != nil {
		return res, fmt.Errorf("Rowsafe's new user can't sign in: %w", err)
	}
	t.Close()
	l.Host = ""
	l.Password = pw
	if err := saveLogin(env, port, l); err != nil {
		return res, err
	}
	res.ACLLine = "user " + LoginUser + " on " + hash + " " + aclRules
	// Kept across restarts?
	aclfile, _ := c.configGet(ctx, "aclfile")
	switch {
	case aclfile != "":
		if _, err := c.do(ctx, "ACL", "SAVE"); err != nil {
			res.Persisted, res.Why = "none", "ACL SAVE failed: "+firstLine(err.Error())
		} else {
			res.Persisted = "aclfile"
		}
	case m["config_file"] != "":
		if _, err := c.do(ctx, "CONFIG", "REWRITE"); err != nil {
			res.Persisted, res.Why = "none", "the server can't write its configuration file "+m["config_file"]+" ("+firstLine(err.Error())+")"
		} else {
			res.Persisted = "config"
		}
	default:
		res.Persisted, res.Why = "none", "the server runs without an ACL file or a configuration file"
	}
	return res, nil
}

func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// MissingRightsError lists what an existing login can't do.
type MissingRightsError struct{ Missing []string }

func (e *MissingRightsError) Error() string {
	return "that user can't run " + strings.Join(e.Missing, ", ") + ": Rowsafe needs them (see `rowsafe-agent redis --help`)"
}

// SaveLogin saves an existing "user:password" (a user the person made) as
// the agent's login, after checking it signs in and reads what Rowsafe
// needs.
func SaveLogin(ctx context.Context, env agent.EngineEnv, port int, userPass string) error {
	user, pass, ok := strings.Cut(strings.TrimSpace(userPass), ":")
	if !ok || user == "" {
		return errors.New("give the login as user:password")
	}
	l := Login{User: user, Password: pass}
	c, err := connectAddr(ctx, addrOf(l, port), user, pass, clientName)
	if err != nil {
		return err
	}
	defer c.Close()
	var missing []string
	for _, cmd := range [][]any{{"INFO", "server"}, {"CONFIG", "GET", "maxmemory"}, {"CLIENT", "LIST"}, {"SLOWLOG", "LEN"}, {"DBSIZE"}} {
		if _, err := c.do(ctx, cmd...); err != nil && isRespError(err, "NOPERM") {
			missing = append(missing, strings.ToUpper(fmt.Sprint(cmd[0])))
		}
	}
	if len(missing) > 0 {
		return &MissingRightsError{Missing: missing}
	}
	return saveLogin(env, port, l)
}
