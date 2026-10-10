package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

const postgresUsage = `rowsafe-agent postgres - PostgreSQL helpers for the installer

  rowsafe-agent postgres tune [--port 5432] [--socket-dir /var/run/postgresql]
      Give a NEW PostgreSQL (the one install.sh --install-postgres just
      installed: the installer runs this once, as postgres, for that cluster
      only) Rowsafe's recommended settings for this server, the ones Tune
      for this server recommends, without the optional ones. Refused when
      the cluster has databases of its own. Never restarts PostgreSQL.
      Prints "changed NAME VALUE" for each setting it set, then
      "restart yes" or "restart no" (whether one waits for a restart).
`

func postgresCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(postgresUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "tune" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], postgresUsage)
		return 2
	}
	fs := flag.NewFlagSet("postgres tune", flag.ContinueOnError)
	port := fs.Int("port", 5432, "PostgreSQL's port")
	socketDir := fs.String("socket-dir", "/var/run/postgresql", "PostgreSQL's socket directory")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run this as postgres (the installer does this)")
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := agent.TuneNew(ctx, *socketDir, *port, "postgres", os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	restart := "no"
	for _, ap := range res.Applied {
		fmt.Printf("changed %s %s\n", ap.Name, ap.To)
		if ap.Restart {
			restart = "yes"
		}
	}
	fmt.Printf("restart %s\n", restart)
	return 0
}
