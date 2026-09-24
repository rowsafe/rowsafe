package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
)

const filesUsage = `rowsafe-agent files - the folders that go with a database (used by the installer)

  rowsafe-agent files discover
      Suggest folders that look like uploads. One tab-separated line each:
        path size_bytes files readable(yes|no) size why
      Runs as root too (the installer does, to see every folder).

  rowsafe-agent files access PATH
      Print whether the agent's user can read PATH: yes, no or missing.

  rowsafe-agent files add --database ID --path PATH [--exclude cache,tmp]
      Protect PATH for the database (as the agent user, with agent.env
      loaded). Prints "folder_id path".
`

func filesCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(filesUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "discover":
		for _, c := range agent.DiscoverFolders(ctx, agent.FilesDiscoverRoots(), false) {
			fmt.Println(agent.FilesInfoLine(c))
		}
		return 0
	case "access":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: rowsafe-agent files access PATH")
			return 2
		}
		p, err := agent.CleanFolderPath(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(agent.FolderAccess(ctx, p))
		return 0
	case "add":
		fs := flag.NewFlagSet("files add", flag.ContinueOnError)
		id := fs.String("database", "", "database ID")
		path := fs.String("path", "", "folder to protect")
		exclude := fs.String("exclude", "", "comma-separated exclude patterns")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *id == "" || *path == "" {
			fmt.Fprintln(os.Stderr, "--database and --path are required")
			return 2
		}
		if os.Geteuid() == 0 {
			fmt.Fprintln(os.Stderr, "run files add as the postgres user, with /etc/rowsafe/agent.env loaded (the installer does this)")
			return 1
		}
		cfg, err := agent.ConfigFromEnv()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		s, err := agent.NewSetup(cfg, os.Stdout, os.Stderr)
		if err == nil {
			err = s.AddFolder(ctx, *id, *path, agent.ParseExcludes(*exclude))
		}
		if err != nil {
			var exit *agent.ExitError
			if errors.As(err, &exit) && exit.Err != nil {
				err = exit.Err
			}
			fmt.Fprintln(os.Stderr, "error:", strings.TrimSpace(err.Error()))
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown files command %q\n\n%s", args[0], filesUsage)
	return 2
}
