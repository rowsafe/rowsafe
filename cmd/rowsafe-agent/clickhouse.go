package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

  rowsafe-agent clickhouse download-backup --stanza STANZA [--label LABEL --to DIR]
      Restore without Rowsafe: with the bucket settings and passphrase in the
      environment (ROWSAFE_REPO_*, as in agent.env), list a database's
      backups (STANZA is its folder in the bucket), or decrypt backup LABEL
      (and the full backup a differential one needs) into DIR, ready for
      ClickHouse's RESTORE ... FROM File(...). It prints the statement. Run
      as root, it gives the files to the clickhouse user. Other files in the
      backup's folder (not written by Rowsafe) are skipped and listed.

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
	if args[0] == "download-backup" {
		return clickhouseDownload(ctx, args[1:])
	}
	fs := flag.NewFlagSet("clickhouse "+args[0], flag.ContinueOnError)
	port := fs.Int("port", 8123, "ClickHouse HTTP port")
	adminUser := fs.String("admin-user", "", "administrator user (password on stdin)")
	usersXML := fs.Bool("users-xml", false, "print a users.d file instead of creating the user with SQL")
	clones := fs.Bool("clones", false, "also let Rowsafe create and drop databases and tables, so this (empty) server can receive clones")
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
			if xml, err = clickhouse.UsersXMLWith(env, *port, *clones); err == nil {
				fmt.Print(xml)
			}
			break
		}
		pw := ""
		if *adminUser != "" {
			pw = readSecret()
		}
		if err = clickhouse.CreateLoginWith(ctx, env, *port, *adminUser, pw, *clones); err == nil {
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

// clickhouseDownload is `rowsafe-agent clickhouse download-backup`. It
// needs no ClickHouse and may run as root (a restore on a new server).
func clickhouseDownload(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("clickhouse download-backup", flag.ContinueOnError)
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	label := fs.String("label", "", "the backup to download (without it: list the backups)")
	at := fs.String("at", "", "a moment to download instead of a backup (RFC 3339, e.g. 2026-09-25T10:15:30Z)")
	to := fs.String("to", "", "an empty folder to decrypt it into")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stanza == "" || (*label != "" && *at != "") || (*label != "" || *at != "") != (*to != "") {
		fmt.Fprint(os.Stderr, "usage: rowsafe-agent clickhouse download-backup --stanza STANZA [--label LABEL | --at TIME] --to DIR]\n")
		return 2
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineClickHouse, os.Stderr)
	if *label == "" {
		list, err := clickhouse.Backups(ctx, env, *stanza)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(list) == 0 {
			fmt.Println("No finished backups in this folder.")
		}
		for _, b := range list {
			note := ""
			if b.Mark != "" {
				note = "  Mark " + b.Mark
			}
			fmt.Printf("%-40s %-4s finished %s%s\n", b.Label, b.Type, b.StoppedAt.UTC().Format("2006-01-02 15:04:05Z"), note)
		}
		return 0
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: --at:", err)
			return 2
		}
		out, exact, note, err := clickhouse.DownloadMoment(ctx, env, *stanza, t, *to, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if !exact {
			fmt.Fprintf(os.Stderr, "That moment can't be assembled exactly: %s.\nDownload that backup instead: --label %s\n", note, out)
			return 1
		}
		if a, err := filepath.Abs(*to); err == nil {
			fmt.Printf("\nWith %s in ClickHouse's backups.allowed_path, restore it with:\n\n", a)
		}
		if a, err := filepath.Abs(out); err == nil {
			out = a
		}
		fmt.Printf("  RESTORE ALL FROM File('%s/')\n", out)
		return 0
	}
	dirs, err := clickhouse.DownloadBackup(ctx, env, *stanza, *label, *to, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	abs := func(d string) string {
		if a, err := filepath.Abs(d); err == nil {
			return a
		}
		return d
	}
	last := abs(dirs[len(dirs)-1])
	if os.Geteuid() != 0 {
		fmt.Printf("\nThe files belong to the user that ran this: ClickHouse's user must be able to read them\n"+
			"(run this as root to give them to it, or: chown -R clickhouse:clickhouse %s).\n", abs(*to))
	}
	fmt.Printf("\nWith %s in ClickHouse's backups.allowed_path, restore it with:\n\n", abs(*to))
	if len(dirs) == 2 {
		fmt.Printf("  RESTORE ALL FROM File('%s/') SETTINGS base_backup = File('%s/')\n", last, abs(dirs[0]))
	} else {
		fmt.Printf("  RESTORE ALL FROM File('%s/')\n", last)
	}
	return 0
}
