package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/opensearch" // registers the OpenSearch engine
	"github.com/rowsafe/rowsafe/protocol"
)

const opensearchUsage = `rowsafe-agent opensearch - OpenSearch helpers for the installer

They run as the agent user with agent.env loaded. A password, when asked
for, is read from stdin (one line) and never stored (except the agent's own).

  rowsafe-agent opensearch status --port PORT
      key=value lines: port version login security tls repo repodir restapi
      hotreload nodes config home unit user ("-" when empty). login is ok,
      missing, refused or none (no security plugin: nothing to sign in
      with); repo is ok when path.repo allows Rowsafe's snapshot folder;
      restapi is ok when Rowsafe's role may manage users (it is listed in
      plugins.security.restapi.roles_enabled). Exit 0 when the server
      answered, 1 when nothing answers on PORT (the REST port).

  rowsafe-agent opensearch login --port PORT --admin-user NAME
      Create (or refresh) Rowsafe's role (rowsafe_agent) and user (rowsafe)
      through the security plugin's REST API, signing in as an administrator
      (password on stdin), with a new random password saved for the agent
      only. Without the security plugin nothing is needed: that is saved.
      Exit 11: an administrator's login is needed; 12: it was refused; 13:
      that login can't create users.

  rowsafe-agent opensearch save-login --port PORT
      Save "user:password" read from stdin as the agent's login, after
      checking it signs in (exit 12: refused).

  rowsafe-agent opensearch hash
      Print the bcrypt hash of the password read from stdin, for
      opensearch-security/internal_users.yml.

  rowsafe-agent opensearch download-backup --stanza STANZA [--label LABEL --to DIR]
      Restore without Rowsafe: with the bucket settings and passphrase in the
      environment (ROWSAFE_REPO_*, as in agent.env), list a database's
      snapshots (STANZA is its folder in the bucket), or decrypt the
      snapshot repository files snapshot LABEL needs into DIR, ready to be
      registered in OpenSearch as a shared-file-system repository (DIR in
      path.repo) and restored. It prints the requests.

Rowsafe's role (rowsafe_agent) can read the cluster's health and stats,
take, list, delete and restore snapshots in Rowsafe's own repository, and
(only when a person asks in the dashboard) delete, create and write indices
for rewinds and Databases & users, change replicas and remove a full disk's
read-only block. Listed in plugins.security.restapi.roles_enabled, it can
manage OpenSearch's users (Databases & users).
`

func opensearchCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(opensearchUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	readSecret := readSecretLine // nothing shown when typed on a terminal
	switch args[0] {
	case "hash":
		pw := readSecret()
		if pw == "" {
			fmt.Fprintln(os.Stderr, "give the password on stdin")
			return 2
		}
		h, err := opensearch.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Println(h)
		return 0
	case "download-backup":
		return opensearchDownload(ctx, args[1:])
	}
	fs := flag.NewFlagSet("opensearch "+args[0], flag.ContinueOnError)
	port := fs.Int("port", protocol.OpenSearchPort, "OpenSearch's REST port")
	adminUser := fs.String("admin-user", "", "administrator user (password on stdin)")
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
	env := agent.EngineEnvFor(cfg, protocol.EngineOpenSearch, os.Stderr)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	switch args[0] {
	case "status":
		st, err := opensearch.ServerStatus(ctx, env, *port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		st.WriteTo(os.Stdout)
		return 0
	case "login":
		pw := ""
		if *adminUser != "" {
			pw = readSecret()
		}
		if err = opensearch.CreateLogin(ctx, env, *port, *adminUser, pw); err == nil {
			fmt.Printf("Rowsafe's OpenSearch user %q is ready; its password is saved for the agent only.\n", opensearch.LoginUser)
		}
	case "save-login":
		err = opensearch.SaveLogin(ctx, env, *port, readSecret())
	default:
		fmt.Fprintf(os.Stderr, "unknown opensearch command %q\n\n%s", args[0], opensearchUsage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, opensearch.ErrNeedAdmin):
		fmt.Fprintln(os.Stderr, err)
		return exitNeedAdmin
	case errors.Is(err, opensearch.ErrAdminRefused):
		fmt.Fprintln(os.Stderr, err)
		return exitAdminRefused
	case errors.Is(err, opensearch.ErrCantManageUsers):
		fmt.Fprintln(os.Stderr, err)
		return exitCantManageUsers
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

// opensearchDownload is `rowsafe-agent opensearch download-backup`. It
// needs no OpenSearch and may run as root (a restore on a new server).
func opensearchDownload(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("opensearch download-backup", flag.ContinueOnError)
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	label := fs.String("label", "", "the snapshot to download (without it: list them)")
	to := fs.String("to", "", "an empty folder to decrypt it into")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stanza == "" || (*label != "") != (*to != "") {
		fmt.Fprint(os.Stderr, "usage: rowsafe-agent opensearch download-backup --stanza STANZA [--label LABEL --to DIR]\n")
		return 2
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineOpenSearch, os.Stderr)
	if *label == "" {
		list, err := opensearch.Backups(ctx, env, *stanza)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(list) == 0 {
			fmt.Println("No snapshots in this folder.")
		}
		for _, b := range list {
			fmt.Println(b)
		}
		return 0
	}
	name, err := opensearch.DownloadBackup(ctx, env, *stanza, *label, *to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	dir, _ := filepath.Abs(*to)
	if os.Geteuid() != 0 {
		fmt.Printf("\nThe files belong to the user that ran this: OpenSearch's user must be able to read them (chown -R opensearch:opensearch %s).\n", dir)
	}
	fmt.Printf("\nWith %s in OpenSearch's path.repo (opensearch.yml, then a restart), restore it with:\n\n", dir)
	fmt.Printf("  PUT _snapshot/rowsafe-download {\"type\":\"fs\",\"settings\":{\"location\":%q,\"readonly\":true}}\n", dir)
	fmt.Printf("  POST _snapshot/rowsafe-download/%s/_restore {\"indices\":\"*\",\"include_global_state\":false}\n", name)
	return 0
}
