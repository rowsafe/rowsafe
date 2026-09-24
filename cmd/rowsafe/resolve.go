package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Which database a command acts on, when NAME is optional:
//
//  1. the NAME argument;
//  2. ROWSAFE_DATABASE;
//  3. "database" in the nearest .rowsafe.json, from the current directory
//     up (the file `rowsafe init` writes and the Claude Code guard reads);
//  4. the org's only database, if it has exactly one.
//
// Otherwise the command fails and lists the databases.
const nameRules = `Commands that take NAME find the database like this:
  1. the NAME argument
  2. ROWSAFE_DATABASE
  3. "database" in the nearest .rowsafe.json (this directory or a parent; see rowsafe init)
  4. the organization's only database, if there is exactly one`

// positionals parses flags that may come before, between or after
// positional arguments, and returns the positionals.
func positionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos, nil
}

// dbArg parses a command's flags and its optional NAME, and resolves the
// database.
func dbArg(ctx context.Context, c *client.Client, fs *flag.FlagSet, args []string) (string, error) {
	pos, err := positionals(fs, args)
	if err != nil {
		return "", err
	}
	if len(pos) > 1 {
		return "", fmt.Errorf("expected at most one database name, got %q", strings.Join(pos, " "))
	}
	explicit := ""
	if len(pos) == 1 {
		explicit = pos[0]
	}
	return resolveDatabase(ctx, c, explicit)
}

// projectDatabase is the database named by ROWSAFE_DATABASE or the nearest
// .rowsafe.json, and where it came from.
func projectDatabase() (name, source string) {
	if v := strings.TrimSpace(os.Getenv("ROWSAFE_DATABASE")); v != "" {
		return v, "ROWSAFE_DATABASE"
	}
	if pc, path := findProjectConfig(""); strings.TrimSpace(pc.Database) != "" {
		return strings.TrimSpace(pc.Database), path
	}
	return "", ""
}

func resolveDatabase(ctx context.Context, c *client.Client, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if name, _ := projectDatabase(); name != "" {
		return name, nil
	}
	dbs, err := c.Databases(ctx)
	if err != nil {
		return "", err
	}
	switch len(dbs) {
	case 1:
		return dbs[0].Name, nil
	case 0:
		return "", errors.New("no databases yet: register one with `rowsafe adopt NAME`")
	}
	return "", fmt.Errorf("which database? This organization has %s.\n"+
		"Pass NAME, set ROWSAFE_DATABASE, or run `rowsafe init NAME` in your project", listNames(dbs))
}

func listNames(dbs []protocol.Database) string {
	names := make([]string, len(dbs))
	for i, d := range dbs {
		names[i] = d.Name
	}
	return fmt.Sprintf("%d databases: %s", len(dbs), strings.Join(names, ", "))
}

// resolveHost picks the host for `rowsafe adopt` when --host is omitted:
// the org's only host.
func resolveHost(ctx context.Context, c *client.Client, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	hosts, err := c.Hosts(ctx)
	if err != nil {
		return "", err
	}
	switch len(hosts) {
	case 1:
		return hosts[0].Hostname, nil
	case 0:
		return "", errors.New("no hosts enrolled yet: install the agent with the command from `rowsafe hosts enroll-token`")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "this organization has %d hosts; say which one with --host:", len(hosts))
	for _, h := range hosts {
		fmt.Fprintf(&b, "\n  --host %s", h.Hostname)
	}
	return "", errors.New(b.String())
}

// markArgs splits `rowsafe mark [NAME] [LABEL]`. With one argument it is
// the database if it names one of the org's databases, otherwise the label
// for the inferred database.
func markArgs(ctx context.Context, c *client.Client, pos []string) (db, label string, err error) {
	switch len(pos) {
	case 0:
	case 1:
		dbs, err := c.Databases(ctx)
		if err != nil {
			return "", "", err
		}
		for _, d := range dbs {
			if d.Name == pos[0] || d.ID == pos[0] {
				db = pos[0]
			}
		}
		if db == "" {
			label = pos[0]
		}
	case 2:
		db, label = pos[0], pos[1]
	default:
		return "", "", errors.New("expected [NAME] [LABEL]")
	}
	if db, err = resolveDatabase(ctx, c, db); err != nil {
		return "", "", err
	}
	return db, label, nil
}
