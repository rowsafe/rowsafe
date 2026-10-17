package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe preview without an account: rowsafe preview postgres://... FILE
// (or a saved NAME, or DATABASE_URL). The same contract as with an
// account (copies.go): progress on stderr, the report on stdout, --json
// with verdict, summary and error, exit 0 once the preview ran (--fail-on:
// 3 at or above the verdict, 2 when the migration fails), 1 when it
// couldn't run. Production is never written to (local/preview.go).

func localPreview(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	format := fs.String("format", "text", "output: text, json or markdown")
	asJSON := fs.Bool("json", false, "same as --format json")
	failOn := fs.String("fail-on", "never", "fail (exit 3) when the verdict is at least this: careful or dangerous; never (default) always exits 0 once the preview ran")
	label := fs.String("label", "", "a name for the preview (default: the file name)")
	static := fs.Bool("static", false, "only check the SQL against the database's catalog, without a temporary copy of the schema")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long the migration may run on the temporary copy")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if *asJSON {
		*format = "json"
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		return errors.New("--format must be text, json or markdown")
	}
	if *failOn != protocol.PreviewCareful && *failOn != protocol.PreviewDangerous && *failOn != "never" {
		return errors.New("--fail-on must be careful, dangerous or never")
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe preview [NAME | postgres://...] FILE (.sql; - reads stdin)")
	}
	file := pos[0]
	if file != "-" && *label == "" {
		*label = filepath.Base(file)
	}
	res, err := runLocalPreview(ctx, l.DB, file, *label, local.PreviewOptions{Static: *static, Timeout: *timeout})
	switch *format {
	case "json":
		out := previewJSON{Database: l.Name(), Label: *label, Result: res}
		if err != nil {
			out.Error = "The preview couldn't run: " + err.Error()
		} else {
			out.Status = protocol.StatusSucceeded
			out.Verdict, out.Summary, out.Markdown = res.Verdict, res.Summary, preview.Markdown(res, *label)
		}
		if perr := printJSON(out); perr != nil {
			return perr
		}
		if err != nil {
			return exitError(1)
		}
	case "markdown":
		if err != nil {
			fmt.Printf("### Rowsafe migration preview\n\nThe preview couldn't run: %s\n", err)
			return exitError(1)
		}
		fmt.Print(preview.Markdown(res, *label))
	default:
		if err != nil {
			return fmt.Errorf("the preview couldn't run: %w", err)
		}
		fmt.Print(preview.Text(res))
		fmt.Println("\nNo restore point was saved: without Rowsafe's agent on the server, take a backup before running it (pg_dump).")
		localFooter(l)
	}
	return previewExit(res.Verdict, *failOn)
}

// runLocalPreview reads the SQL and previews it, telling stderr what
// happens.
func runLocalPreview(ctx context.Context, d *local.DB, file, label string, o local.PreviewOptions) (*protocol.PreviewResult, error) {
	sql, err := readMigration(file)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Previewing %s for %s on %s (nothing on it changes)...\n", orText(label, "the SQL"), d.Name(), d.Host())
	o.Progress = func(s string) { fmt.Fprintln(os.Stderr, "  "+s) }
	return d.Preview(ctx, sql, o)
}

// readMigration reads a migration file, or stdin for "-".
func readMigration(file string) (string, error) {
	var sql []byte
	var err error
	if file == "-" {
		sql, err = io.ReadAll(io.LimitReader(stdinReader, 1<<20+1))
	} else {
		sql, err = os.ReadFile(file)
	}
	switch {
	case err != nil:
		return "", err
	case len(sql) > 960<<10:
		return "", errors.New("the SQL is over 960 kB; preview one migration at a time")
	case strings.TrimSpace(string(sql)) == "":
		return "", errors.New("the SQL is empty")
	}
	return string(sql), nil
}
