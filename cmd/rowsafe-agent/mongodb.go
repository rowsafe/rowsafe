package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/mongodb" // registers the MongoDB engine
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

const mongodbUsage = `rowsafe-agent mongodb - MongoDB helpers for the installer

They run as the agent user with agent.env loaded. An administrator's
password, when asked for, is read from stdin (one line) and never stored.

  rowsafe-agent mongodb status --port PORT
      key=value lines: port version replset initiated primary auth login
      config dbpath keyfile unit ("-" when empty). login is ok, missing,
      refused or not-needed.

  rowsafe-agent mongodb login --port PORT [--admin-user NAME]
      Create (or refresh) Rowsafe's MongoDB user "rowsafe" with a new random
      password (roles backup, clusterMonitor, readAnyDatabase and
      rowsafeAgent: write a Mark, stop an operation, bring documents back)
      and save it for the agent. Exit 11: an administrator's login is
      needed; 12: that login was refused.

  rowsafe-agent mongodb initiate --port PORT [--admin-user NAME]
      Start the single-member replica set of a server restarted with a
      replica set name, and wait until it is primary.

  rowsafe-agent mongodb save-uri --port PORT
      Save a connection string read from stdin as the agent's login (for a
      user you created yourself).

  rowsafe-agent unseal < FILE.enc > FILE
      Decrypt a file from your bucket (MongoDB backups and oplog chunks)
      with ROWSAFE_REPO_CIPHER_PASS, e.g. to restore without Rowsafe.
`

const (
	exitNeedAdmin    = 11
	exitAdminRefused = 12
)

func mongodbCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(mongodbUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	fs := flag.NewFlagSet("mongodb "+args[0], flag.ContinueOnError)
	port := fs.Int("port", 27017, "mongod port")
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
	env := agent.EngineEnvFor(cfg, protocol.EngineMongoDB, os.Stderr)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	readSecret := func() string {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	switch args[0] {
	case "status":
		st, err := mongodb.ServerStatus(ctx, env, *port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		st.WriteTo(os.Stdout)
		return 0
	case "login", "initiate":
		pw := ""
		if *adminUser != "" {
			pw = readSecret()
		}
		if args[0] == "login" {
			var roles []string
			roles, err = mongodb.CreateLogin(ctx, env, *port, *adminUser, pw)
			if err == nil {
				fmt.Printf("Created MongoDB user %q for Rowsafe (roles: %s); its password is saved for the agent only.\n",
					mongodb.LoginUser, strings.Join(roles, ", "))
			}
		} else {
			err = mongodb.Initiate(ctx, env, *port, *adminUser, pw)
			if err == nil {
				fmt.Println("The replica set is running; this server is its primary.")
			}
		}
	case "save-uri":
		err = mongodb.SaveURI(env, *port, readSecret())
	default:
		fmt.Fprintf(os.Stderr, "unknown mongodb command %q\n\n%s", args[0], mongodbUsage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, mongodb.ErrNeedAdmin):
		fmt.Fprintln(os.Stderr, err)
		return exitNeedAdmin
	case errors.Is(err, mongodb.ErrAdminRefused):
		fmt.Fprintln(os.Stderr, err)
		return exitAdminRefused
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

// unseal decrypts stdin to stdout with ROWSAFE_REPO_CIPHER_PASS.
func unseal() error {
	pass := os.Getenv("ROWSAFE_REPO_CIPHER_PASS")
	if pass == "" {
		return errors.New("set ROWSAFE_REPO_CIPHER_PASS (the encryption passphrase in /etc/rowsafe/agent.env)")
	}
	r, err := objstore.Open(os.Stdin, pass)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	return w.Flush()
}
