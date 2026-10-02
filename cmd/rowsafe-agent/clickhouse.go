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
	"github.com/rowsafe/rowsafe/internal/engine/clickhouse" // registers the ClickHouse engine
	"github.com/rowsafe/rowsafe/protocol"
)

const clickhouseUsage = `rowsafe-agent clickhouse - ClickHouse helpers for the installer

They run as the agent user with agent.env loaded. A password, when asked
for, is read from stdin (one line) and never stored (except the agent's own).

  rowsafe-agent clickhouse status --port PORT
      key=value lines: port version login user datadir config usersd unit
      binary replicated docker ("-" when empty). login is ok, missing or
      refused; replicated counts the Replicated* tables; binary is the
      clickhouse program restore tests and copies use. Exit 0 when the
      server answered, 1 when nothing answers on PORT (its HTTP port).

  rowsafe-agent clickhouse login --port PORT --users-xml
      Make a new random password for ClickHouse user "rowsafe", save the
      login for the agent only, and print the users.d file that creates the
      user (root installs it as /etc/clickhouse-server/users.d/rowsafe.xml,
      root:clickhouse 0640; ClickHouse loads it within seconds).

  rowsafe-agent clickhouse login --port PORT [--admin-user NAME]
      Create (or refresh) "rowsafe" with SQL (CREATE USER, GRANT) with an
      administrator's login (password on stdin; without --admin-user it
      tries "default" without a password). Exit 11: an administrator's
      login is needed; 12: it was refused; 13: it can't create users (use
      --users-xml as root instead).

  rowsafe-agent clickhouse save-login --port PORT
      Save "user:password" read from stdin as the agent's login, after
      checking it signs in and has the grants Rowsafe needs (exit 12:
      refused; missing grants are listed on stderr).

Rowsafe's user needs, ON *.*: SELECT, BACKUP (back up every database and
compare tables with a copy), INSERT (bring rows back when you ask), KILL
QUERY, ALTER UPDATE, ALTER DELETE (stop a query or cancel a stuck change
when you ask), S3 (write backups to the agent's encrypting gateway).
`

const exitCantManageUsers = 13

func clickhouseCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(clickhouseUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	fs := flag.NewFlagSet("clickhouse "+args[0], flag.ContinueOnError)
	port := fs.Int("port", 8123, "ClickHouse HTTP port")
	adminUser := fs.String("admin-user", "", "administrator user (password on stdin)")
	usersXML := fs.Bool("users-xml", false, "print a users.d file instead of creating the user with SQL")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run this as the agent user, with /etc/rowsafe/agent.env loaded (the installer does this)")
		return 1
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineClickHouse, os.Stderr)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	readSecret := func() string {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	switch args[0] {
	case "status":
		st, err := clickhouse.ServerStatus(ctx, env, *port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		st.WriteTo(os.Stdout)
		return 0
	case "login":
		if *usersXML {
			var xml string
			if xml, err = clickhouse.UsersXML(env, *port); err == nil {
				fmt.Print(xml)
			}
			break
		}
		pw := ""
		if *adminUser != "" {
			pw = readSecret()
		}
		if err = clickhouse.CreateLogin(ctx, env, *port, *adminUser, pw); err == nil {
			fmt.Printf("Created ClickHouse user %q for Rowsafe; its password is saved for the agent only.\n", clickhouse.LoginUser)
		}
	case "save-login":
		err = clickhouse.SaveLogin(ctx, env, *port, readSecret())
	default:
		fmt.Fprintf(os.Stderr, "unknown clickhouse command %q\n\n%s", args[0], clickhouseUsage)
		return 2
	}
	var missing *clickhouse.MissingGrantsError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, clickhouse.ErrNeedAdmin):
		fmt.Fprintln(os.Stderr, err)
		return exitNeedAdmin
	case errors.Is(err, clickhouse.ErrAdminRefused):
		fmt.Fprintln(os.Stderr, err)
		return exitAdminRefused
	case errors.Is(err, clickhouse.ErrCantManageUsers):
		fmt.Fprintln(os.Stderr, err)
		return exitCantManageUsers
	case errors.As(err, &missing):
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}
