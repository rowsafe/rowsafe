package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe files on a server on its own: a database's folders, the server's
// own (a folder or Docker volume with no database), restores in place
// (after the name) and into another folder, and rowsafe status.
func TestFilesOnServer(t *testing.T) {
	c := localServer(t) // shop, protected
	ctx := t.Context()
	run := func(args ...string) string {
		t.Helper()
		out, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("rowsafe %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}

	// The only database is the default; a path isn't a name.
	if out := run("files", "add", "/var/www/uploads"); !strings.Contains(out, "shop: protecting /var/www/uploads") {
		t.Fatalf("add:\n%s", out)
	}
	// --server: the server's own folder, with no database.
	if out := run("files", "add", "--server", "/srv/media"); !strings.Contains(out, "db1: protecting /srv/media") {
		t.Fatalf("add --server:\n%s", out)
	}
	if info, err := c.HostFilesInfo(ctx, "db1"); err != nil || len(info.Folders) != 1 || info.Folders[0].Path != "/srv/media" {
		t.Fatalf("the server's folders: %+v %v", info, err)
	}
	if out := run("files", "shop"); !strings.Contains(out, "/var/www/uploads") || strings.Contains(out, "/srv/media") ||
		!strings.Contains(out, "every 15 minutes and at every Mark") {
		t.Fatalf("files shop:\n%s", out)
	}
	if out := run("files", "--server"); !strings.Contains(out, "db1: Files") || !strings.Contains(out, "/srv/media") {
		t.Fatalf("files --server:\n%s", out)
	}
	if out := run("files", "set", "--server", "--every", "1h", "--keep-days", "60"); !strings.Contains(out, "every 60 minutes, kept 60 days") {
		t.Fatalf("set:\n%s", out)
	}
	if _, err := runCLI(t, "files", "set", "shop", "--keep-days", "60"); err == nil {
		t.Fatal("--keep-days for a database's files")
	}
	run("files", "backup", "shop")
	if out := run("files", "snapshots", "--server"); !strings.Contains(out, "/srv/media (0 snapshots)") {
		t.Fatalf("snapshots:\n%s", out)
	}

	// In place: the database's name is typed (no terminal: --yes).
	if _, err := runCLI(t, "files", "restore", "shop", "--at", "1m ago"); !errors.Is(err, errNoTerminal) {
		t.Fatalf("restore without a confirmation: %v", err)
	}
	if out := run("files", "restore", "shop", "--at", "1m ago", "--yes"); !strings.Contains(out, "A Mark is saved first") {
		t.Fatalf("restore:\n%s", out)
	}
	tasks, _ := c.Tasks(ctx, "shop", 10)
	if len(tasks) < 2 || tasks[0].Type != protocol.TaskFilesRestore || tasks[1].Type != protocol.TaskRestorePoint {
		t.Fatalf("tasks: %+v", tasks)
	}
	// Into another folder: nothing to confirm.
	into := t.TempDir() + "/restored"
	if out := run("files", "restore", "--server", "--at", "1m ago", "--into", into); !strings.Contains(out, "into "+into) ||
		!strings.Contains(out, "Nothing that exists now changes") {
		t.Fatalf("restore --into:\n%s", out)
	}
	if _, err := runCLI(t, "files", "restore", "--server", "--at", "1m ago", "--into", into, "--whole-folder"); err == nil {
		t.Fatal("--into with --whole-folder")
	}

	// rowsafe status lists the folders.
	out, _ := runCLI(t, "status")
	if !strings.Contains(out, "Files:") || !strings.Contains(out, "/var/www/uploads (shop): pending") ||
		!strings.Contains(out, "/srv/media (the server itself): pending") {
		t.Fatalf("status:\n%s", out)
	}
	if err := c.HostRemoveFilesFolder(ctx, "db1", "/srv/media"); err != nil {
		t.Fatal(err)
	}
	if out := run("files", "--server"); !strings.Contains(out, "No folders of this server") {
		t.Fatalf("after remove:\n%s", out)
	}
}
