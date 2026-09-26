package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// failingRunner fails the commands whose last argument is in fail, like
// ExecRunner does (a CommandError with the output), and succeeds otherwise.
type failingRunner struct {
	calls [][]string
	fail  map[string]string // last argument -> output
	exit  int
}

func (f *failingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if out, ok := f.fail[args[len(args)-1]]; ok {
		return []byte(out), &pgbackrest.CommandError{Tool: protocol.ToolName(name, args...), ExitCode: f.exit, Output: []byte(out),
			Err: &exec.ExitError{}}
	}
	return nil, nil
}

const pathNotEmptyOut = "2026-09-26 04:46:00.101 P00   INFO: stanza-create command begin 2.55.0: --repo1-s3-key=<redacted> --stanza=app\n" +
	"2026-09-26 04:46:00.345 P00  ERROR: [040]: backup directory and/or archive directory not empty\n" +
	"2026-09-26 04:46:00.346 P00   INFO: stanza-create command end: aborted with exception [040]\n"

func TestStanzaCreateFailureIsExplained(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	fr := &failingRunner{fail: map[string]string{"stanza-create": pathNotEmptyOut + "secret OWNSECRET leaked\n"}, exit: 40}
	a.runner = fr
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	tl := &taskLog{}
	err := a.createStanza(context.Background(), testDB, protocol.InspectResult{VersionNum: 180001}, "", tl)
	if err == nil {
		t.Fatal("stanza-create failure not reported")
	}
	if !strings.Contains(err.Error(), "backup directory and/or archive directory not empty") {
		t.Errorf("error doesn't name pgBackRest's message: %v", err)
	}
	te := a.taskErrorOf(err)
	if te == nil || te.Code != protocol.TaskErrPathNotEmpty || te.ExitCode != 40 || te.Tool != "pgbackrest" {
		t.Fatalf("task error = %+v", te)
	}
	if strings.Contains(te.Detail, "OWNSECRET") {
		t.Error("the storage secret reached the task error")
	}
	// pgbackrest info can't read the folder here: whose backups they are is unknown.
	if te.Facts[protocol.TaskFactRepoBelongs] != protocol.RepoBelongsUnknown || te.Facts[protocol.TaskFactRepoFolder] != "/rowsafe/app" ||
		te.Facts[protocol.TaskFactDBVersion] != "18" {
		t.Errorf("facts = %v", te.Facts)
	}
	if !strings.Contains(tl.String(), "ERROR: [040]") {
		t.Error("pgBackRest's output is not in the task log")
	}
	// "Use the backups already there" is refused when they can't be shown to be this database's.
	fr.calls = nil
	if err := a.createStanza(context.Background(), testDB, protocol.InspectResult{VersionNum: 180001}, protocol.ExistingBackupsUse, tl); err == nil {
		t.Fatal("used backups of unknown origin")
	}
	for _, c := range fr.calls {
		if c[len(c)-1] == "stanza-upgrade" {
			t.Fatal("stanza-upgrade ran on backups of unknown origin")
		}
	}
}

func TestStartFreshInNewFolder(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	tl := &taskLog{}
	folder, err := a.prepareFolder(testDB, protocol.ExistingBackupsNewFolder, tl)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(folder, "app-20") || validFolder(folder) != folder {
		t.Fatalf("folder = %q", folder)
	}
	if !strings.Contains(tl.String(), "/rowsafe/app stay where they are") {
		t.Errorf("log doesn't say the old files stay:\n%s", tl.String())
	}
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	if conf := readConf(t, a, "app"); !strings.Contains(conf, "repo1-path=/rowsafe/"+folder+"\n") {
		t.Fatalf("config not in the new folder:\n%s", conf)
	}
	// Every later command keeps the new folder, and the stanza is created there.
	if got := a.repoFolder("app"); got != folder {
		t.Errorf("repoFolder = %q, want %q", got, folder)
	}
	if !a.stanzaPending("app") {
		t.Error("the stanza must be created in the new folder")
	}
	// A standby is handed the folder too.
	a.cfg.Repo.CAFile = ""
	r, err := a.handedRepo(testDB)
	if err != nil || r.Folder != folder {
		t.Errorf("handed repo folder = %q, %v", r.Folder, err)
	}
	// Without a choice, the folder in use stays.
	if f, _ := a.prepareFolder(testDB, "", tl); f != folder {
		t.Errorf("prepareFolder without a choice = %q", f)
	}
	// A tampered folder file is ignored.
	os.WriteFile(a.cfg.repoFolderPath("app"), []byte("../../etc\n"), 0o600)
	if got := a.repoFolder("app"); got != "" {
		t.Errorf("unsafe folder accepted: %q", got)
	}
}

func TestTaskErrorOnlyForTools(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	if te := a.taskErrorOf(errors.New("archive_mode is still off")); te != nil {
		t.Errorf("plain error explained as a tool failure: %+v", te)
	}
	wrapped := errors.Join(errors.New("while backing up"), &pgbackrest.CommandError{Tool: "pg_ctl", ExitCode: 1,
		Output: []byte("pg_ctl: could not start server: No space left on device"), Err: errors.New("exit status 1")})
	if te := a.taskErrorOf(wrapped); te == nil || te.Code != protocol.TaskErrPGDiskFull {
		t.Errorf("pg_ctl failure: %+v", te)
	}
}
