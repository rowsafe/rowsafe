package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	mysqlengine "github.com/rowsafe/rowsafe/internal/engine/mysql"
)

const setupUsage = `rowsafe-agent setup - turn on backups for this server's PostgreSQL

The installer runs these as the agent user with agent.env loaded; they never
ask questions (the installer does). They use the agent's own credentials, so
the agent must have connected to Rowsafe first.

  rowsafe-agent setup discover
      Find running PostgreSQL clusters (pg_lsclusters, sockets in
      /var/run/postgresql and /tmp) the agent can connect to. One
      tab-separated line each ("-" when empty):
        port socket_dir major cluster data_dir size_bytes name registered
        status databases size unit database_id engine
      name is the suggested name (the Rowsafe name when registered);
      registered is yes or no; status is the Rowsafe status; databases are
      comma-separated; size is human-readable; unit is the systemd unit;
      engine is postgresql, or another engine this agent supports.
      Replicas and clusters it can't reach are skipped with a note on stderr.

  rowsafe-agent setup plan --name NAME --port PORT [--socket-dir DIR] [--engine ENGINE] [--id-file FILE] [--timeout 3m]
      Add the cluster to Rowsafe (again: same database), wait for the
      read-only plan and print it. Nothing changes on this server.
      Exit 0 plan ready; 3 another backup tool is set up (apply --force
      replaces it); 4 the organization's plan has no room; 5 already
      protected; 7 the name is taken; 10 set up, waiting for a restart.

  rowsafe-agent setup apply --database ID [--force] [--timeout 10m]
      Turn on backups: apply the plan (ALTER SYSTEM + reload; never restarts).
      Exit 0 done, no restart needed; 10 done, PostgreSQL needs a restart;
      3 another backup tool is set up (use --force to replace it).

  rowsafe-agent setup wait --database ID [--timeout 10m]
      Print progress until the database is protected and its first full
      backup has started. Exit 0 done; 2 not yet (Rowsafe finishes on its own).

  rowsafe-agent setup status --database ID
      One tab-separated line: id name status backup(none|running|done) dashboard_url

  rowsafe-agent setup mysql-account --engine mysql|mariadb --port PORT [--socket FILE]
                                    [--admin-user root] [--admin-password-file FILE] [--owner USER]
      As root: create (or reset) Rowsafe's own MySQL/MariaDB account
      rowsafe@localhost with a random password, kept in the agent's state
      directory (0600, owned by --owner, the agent user). It logs in as the
      administrator through the socket (auth_socket / unix_socket), or with
      the password in --admin-password-file, which is used once and not kept.

Other errors exit 1.
`

func setup(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(setupUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	err := runSetup(ctx, args[0], args[1:])
	if err == nil {
		return 0
	}
	var exit *agent.ExitError
	if errors.As(err, &exit) {
		if exit.Err != nil {
			fmt.Fprintln(os.Stderr, exit.Err)
		}
		return exit.Code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

func runSetup(ctx context.Context, cmd string, args []string) error {
	fs := flag.NewFlagSet("setup "+cmd, flag.ContinueOnError)
	var (
		name      = fs.String("name", "", "database name in Rowsafe")
		port      = fs.Int("port", 0, "PostgreSQL port")
		socketDir = fs.String("socket-dir", "", "Unix socket directory")
		engine    = fs.String("engine", "", "database engine (from discover; default postgresql)")
		idFile    = fs.String("id-file", "", "write the database ID to this file")
		id        = fs.String("database", "", "database ID (from plan --id-file)")
		force     = fs.Bool("force", false, "replace another backup tool's archive_command")
		timeout   = fs.Duration("timeout", 0, "how long to wait")
	)
	if cmd == "mysql-account" {
		return mysqlAccount(ctx, args)
	}
	switch cmd {
	case "discover", "plan", "apply", "wait", "status":
	default:
		return fmt.Errorf("unknown setup command %q (see rowsafe-agent setup --help)", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if os.Geteuid() == 0 {
		return errors.New("run setup as the agent user, with /etc/rowsafe/agent.env loaded (the installer does this)")
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		return err
	}
	if cfg.Sidecar() {
		return errors.New("setup is for PostgreSQL on this server; in Docker, add the database in the dashboard")
	}
	s, err := agent.NewSetup(cfg, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	s.Engine = *engine
	needID := func() error {
		if *id == "" {
			return errors.New("--database ID is required")
		}
		return nil
	}
	orDefault := func(d time.Duration) time.Duration {
		if *timeout > 0 {
			return *timeout
		}
		return d
	}
	switch cmd {
	case "discover":
		cs, err := s.Discover(ctx)
		if err != nil {
			return err
		}
		agent.WriteClusters(os.Stdout, cs)
		return nil
	case "plan":
		if *name == "" || *port <= 0 {
			return errors.New("--name and --port are required")
		}
		return s.Plan(ctx, *name, *port, *socketDir, *idFile, orDefault(3*time.Minute))
	case "apply":
		if err := needID(); err != nil {
			return err
		}
		return s.Apply(ctx, *id, *force, orDefault(10*time.Minute))
	case "wait":
		if err := needID(); err != nil {
			return err
		}
		return s.Wait(ctx, *id, orDefault(10*time.Minute))
	default:
		if err := needID(); err != nil {
			return err
		}
		return s.Status(ctx, *id)
	}
}

// mysqlAccount creates Rowsafe's MySQL/MariaDB account (as root).
func mysqlAccount(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup mysql-account", flag.ContinueOnError)
	var (
		engine    = fs.String("engine", "", "mysql or mariadb")
		port      = fs.Int("port", 3306, "the server's port")
		socket    = fs.String("socket", "", "the server's Unix socket file")
		adminUser = fs.String("admin-user", "root", "administrator account")
		adminPW   = fs.String("admin-password-file", "", "file holding the administrator's password (default: socket login)")
		owner     = fs.String("owner", "", "OS user that owns the account file (the agent user)")
		stateDir  = fs.String("state-dir", "", "the agent's state directory (default ROWSAFE_STATE_DIR or /var/lib/rowsafe)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *engine == "" {
		return errors.New("--engine is required")
	}
	dir := *stateDir
	if dir == "" {
		dir = os.Getenv("ROWSAFE_STATE_DIR")
	}
	if dir == "" {
		dir = "/var/lib/rowsafe"
	}
	uid, gid := -1, -1
	if *owner != "" {
		u, err := user.Lookup(*owner)
		if err != nil {
			return err
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	msg, err := mysqlengine.CreateAccount(ctx, mysqlengine.AccountOptions{
		Engine: *engine, Port: *port, Socket: *socket, StateDir: dir,
		AdminUser: *adminUser, AdminPasswordFile: *adminPW, UID: uid, GID: gid,
	})
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
