package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/redis" // registers the Redis and Valkey engines
	"github.com/rowsafe/rowsafe/protocol"
)

const redisUsage = `rowsafe-agent redis - Redis and Valkey helpers for the installer

They run as the agent user with agent.env loaded. A password, when asked
for, is read from stdin (one line) and never stored (except the agent's own).

  rowsafe-agent redis status --port PORT
      key=value lines: port engine version login user unit binary config
      aclfile datadir dbfilename docker cluster role needs_auth ("-" when
      empty). login is ok, missing or refused; binary is the server program
      restore tests and copies use; needs_auth says the default user asks
      for a password. Exit 0 when the server answered, 1 when nothing
      answers on PORT.

  rowsafe-agent redis login --port PORT [--admin-user NAME]
      Create (or refresh) the ACL user "rowsafe" with a new random password,
      saved for the agent only. Without --admin-user it signs in as the
      default user without a password; with it, the administrator's password
      comes from stdin (for a requirepass setup: --admin-user default). It
      keeps the user across restarts with ACL SAVE (an aclfile) or CONFIG
      REWRITE, and prints key=value lines: persisted (aclfile, config or
      none), why (when none) and acl_line: the "user rowsafe on #<hash> ..."
      line (the password's hash only) root adds to the configuration file
      when persisted is none. Exit 11: an administrator's login is needed;
      12: it was refused; 13: it can't create users.

  rowsafe-agent redis save-login --port PORT
      Save "user:password" read from stdin as the agent's login (a user you
      made yourself), after checking it signs in and reads what Rowsafe needs.

  rowsafe-agent redis download-backup --engine redis|valkey --stanza STANZA [--label LABEL --to FILE]
      Restore without Rowsafe: with the bucket settings and passphrase in the
      environment (ROWSAFE_REPO_*, as in agent.env), list a database's
      snapshots (STANZA is its folder in the bucket), or decrypt snapshot
      LABEL into FILE: a dump.rdb any server of the same version loads at
      startup.

Rowsafe's user needs: the read commands (not KEYS), INFO, CONFIG GET/SET/
REWRITE, CLIENT LIST/KILL, SLOWLOG, LATENCY, MODULE LIST, MEMORY, SYNC,
PSYNC and REPLCONF (snapshots and the stream of changes), BGSAVE and
LASTSAVE (when replication is refused), DUMP and RESTORE (bringing keys
back), SWAPDB and FLUSHDB (rewind in place, through an empty logical
database). No pub/sub channels, scripts, MONITOR, DEBUG or FLUSHALL.
`

func redisCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(redisUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	fs := flag.NewFlagSet("redis "+args[0], flag.ContinueOnError)
	port := fs.Int("port", 6379, "the server's port")
	adminUser := fs.String("admin-user", "", "administrator user (password on stdin)")
	engine := fs.String("engine", protocol.EngineRedis, "redis or valkey")
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	label := fs.String("label", "", "the snapshot to download")
	to := fs.String("to", "", "the file to write")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *engine != protocol.EngineRedis && *engine != protocol.EngineValkey {
		fmt.Fprintln(os.Stderr, "error: --engine is redis or valkey")
		return 2
	}
	if args[0] == "download-backup" {
		return redisDownload(ctx, agent.EngineEnvFor(cfg, *engine, os.Stderr), *stanza, *label, *to)
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run this as the agent user, with /etc/rowsafe/agent.env loaded (the installer does this)")
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	readSecret := func() string {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	// The login lives in the state of the engine the server is.
	envFor := func() (agent.EngineEnv, string) {
		env := agent.EngineEnvFor(cfg, protocol.EngineRedis, os.Stderr)
		st, err := redis.ServerStatus(ctx, env, *port)
		if err == nil && st.Engine == protocol.EngineValkey {
			return agent.EngineEnvFor(cfg, protocol.EngineValkey, os.Stderr), protocol.EngineValkey
		}
		if err == nil && st.Engine == "" && *engine == protocol.EngineValkey {
			return agent.EngineEnvFor(cfg, protocol.EngineValkey, os.Stderr), protocol.EngineValkey
		}
		return env, protocol.EngineRedis
	}
	switch args[0] {
	case "status":
		env, _ := envFor()
		st, err := redis.ServerStatus(ctx, env, *port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		st.Print(os.Stdout)
		return 0
	case "login":
		env, _ := envFor()
		pw := ""
		if *adminUser != "" {
			pw = readSecret()
		}
		res, err := redis.CreateLogin(ctx, env, *port, *adminUser, pw)
		switch {
		case err == nil:
			fmt.Printf("persisted=%s\n", res.Persisted)
			if res.Why != "" {
				fmt.Printf("why=%s\n", res.Why)
			}
			fmt.Printf("acl_line=%s\n", res.ACLLine)
			return 0
		case errors.Is(err, redis.ErrNeedAdmin):
			fmt.Fprintln(os.Stderr, err)
			return exitNeedAdmin
		case errors.Is(err, redis.ErrAdminRefused):
			fmt.Fprintln(os.Stderr, err)
			return exitAdminRefused
		case errors.Is(err, redis.ErrCantManageUsers):
			fmt.Fprintln(os.Stderr, err)
			return exitCantManageUsers
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	case "save-login":
		env, _ := envFor()
		if err := redis.SaveLogin(ctx, env, *port, readSecret()); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			if strings.Contains(err.Error(), "refused") {
				return exitAdminRefused
			}
			return 1
		}
		fmt.Println("Saved the login for the agent only.")
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown redis command %q\n\n%s", args[0], redisUsage)
	return 2
}

// redisDownload is `rowsafe-agent redis download-backup`. It needs no
// server and may run as root (a restore on a new server).
func redisDownload(ctx context.Context, env agent.EngineEnv, stanza, label, to string) int {
	if stanza == "" || (label == "") != (to == "") {
		fmt.Fprint(os.Stderr, "usage: rowsafe-agent redis download-backup --stanza STANZA [--label LABEL --to FILE]\n")
		return 2
	}
	if label == "" {
		list, err := redis.Backups(ctx, env, stanza)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(list) == 0 {
			fmt.Println("No finished snapshots in this folder.")
		}
		for _, b := range list {
			fmt.Printf("%-20s %-8s %s %-6s taken %s\n", b.Label, b.Engine, b.Version, b.Source, b.TakenAt.UTC().Format("2006-01-02 15:04:05Z"))
		}
		return 0
	}
	if err := redis.DownloadBackup(ctx, env, stanza, label, to); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Wrote %s. Put it in an empty server's data folder as dump.rdb (dir and dbfilename in its configuration, with appendonly no) and start it.\n", to)
	return 0
}
