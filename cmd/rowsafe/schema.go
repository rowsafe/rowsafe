package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/local"
)

// rowsafe schema and rowsafe explain: what an AI coding agent needs to
// understand a PostgreSQL database, read-only, on a connection string
// (local.go). Nothing is sent to Rowsafe.

func init() {
	localCommands["schema"] = localSchema
	localCommands["explain"] = localExplain
}

// localOnly runs schema or explain when the CLI is logged in but no
// connection string was given: $DATABASE_URL still works, since there is
// no account version of these commands.
func localOnly(ctx context.Context, cmd string, args []string) error {
	db, rest, ok, err := localArgs(args, false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("rowsafe %s works on a connection string: rowsafe %s postgres://USER@HOST:5432/DB (or set DATABASE_URL)", cmd, cmd)
	}
	return localCommands[cmd](ctx, db, rest)
}

func localSchema(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	var tables, schemas nameList
	fs.Var(&tables, "table", "only these tables (repeat it, or a comma-separated list; * and ? match, schema.name works)")
	fs.Var(&schemas, "schema", "only these schemas")
	limit := fs.Int("limit", local.DefaultSchemaLimit, "at most this many tables and views, the largest (0: all)")
	asJSON := fs.Bool("json", false, "print everything as JSON (view definitions included)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	// rowsafe schema CONN orders customers
	tables = append(tables, pos...)
	if *limit == 0 {
		*limit = -1
	}
	s, err := l.Schema(ctx, local.SchemaOptions{Tables: tables, Schemas: schemas, Limit: *limit})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(s)
	}
	fmt.Print(s.Text())
	return nil
}

func localExplain(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	file := fs.String("f", "", "read the statement from this file (- for standard input)")
	analyze := fs.Bool("analyze", false, "run the query (SELECT only, in a read-only transaction) to measure real times and rows")
	timeout := fs.Duration("timeout", local.DefaultAnalyzeTimeout, "with --analyze, stop the query after this long")
	asJSON := fs.Bool("json", false, "print the result as JSON, with PostgreSQL's full plan")
	// The statement is the argument with a space in it (it may start with
	// "--" or "/*", which isn't a flag).
	var flagArgs, text []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.ContainsAny(a, " \t\n") && (i == 0 || (args[i-1] != "-f" && args[i-1] != "--f")) {
			text = append(text, a)
			continue
		}
		flagArgs = append(flagArgs, a)
	}
	pos, err := positionals(fs, flagArgs)
	if err != nil {
		return err
	}
	text = append(text, pos...)
	var sql string
	switch {
	case *file != "" && len(text) > 0:
		return errors.New("give the statement or -f FILE, not both")
	case *file == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		sql = string(b)
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		sql = string(b)
	case len(text) == 0:
		return errors.New(`expected a statement: rowsafe explain CONN "SELECT ..." (or -f FILE)`)
	default:
		sql = strings.Join(text, " ")
	}
	if *timeout <= 0 || *timeout > 10*time.Minute {
		return errors.New("--timeout must be between 1s and 10m")
	}
	e, err := l.Explain(ctx, sql, local.ExplainOptions{Analyze: *analyze, Timeout: *timeout, Plan: *asJSON})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e)
	}
	fmt.Print(e.Text())
	return nil
}
