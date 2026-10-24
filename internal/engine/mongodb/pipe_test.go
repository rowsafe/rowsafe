package mongodb

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// A restore that exits early (a refused login, a full disk) ends the dump
// too, and its error is the one reported.
func TestPipeToolsRestoreExitsEarly(t *testing.T) {
	dump := exec.Command("sh", "-c", "while :; do printf '%01024d' 0; done")
	restore := exec.Command("sh", "-c", "head -c 10 >/dev/null; exit 3")
	done := make(chan struct{})
	var dumpErr, restoreErr error
	go func() {
		dumpErr, restoreErr = pipeTools(dump, restore)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = dump.Process.Kill()
		t.Fatal("the dump kept writing into a restore that had exited")
	}
	var ee *exec.ExitError
	if dumpErr != nil || !errors.As(restoreErr, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("dump %v, restore %v", dumpErr, restoreErr)
	}
}

func TestPipeToolsBothSucceed(t *testing.T) {
	dump := exec.Command("sh", "-c", "printf 'archive bytes'")
	out := filepath.Join(t.TempDir(), "out")
	restore := exec.Command("sh", "-c", "cat > "+out)
	if dumpErr, restoreErr := pipeTools(dump, restore); dumpErr != nil || restoreErr != nil {
		t.Fatalf("dump %v, restore %v", dumpErr, restoreErr)
	}
	if b, _ := os.ReadFile(out); string(b) != "archive bytes" {
		t.Fatalf("restore read %q", b)
	}
	// A failing dump is reported as the dump's error.
	dump = exec.Command("sh", "-c", "printf x; exit 4")
	restore = exec.Command("sh", "-c", "cat >/dev/null")
	if dumpErr, restoreErr := pipeTools(dump, restore); dumpErr == nil || restoreErr != nil {
		t.Fatalf("failing dump: dump %v, restore %v", dumpErr, restoreErr)
	}
}

// A damaged oplog state file doesn't stop copying: it is set aside and
// copying starts again from now.
func TestDamagedShipState(t *testing.T) {
	env := agent.EngineEnv{StateDir: t.TempDir(), Log: slog.New(slog.DiscardHandler)}
	path := statePath(env, "db1", "oplog.json")
	if err := saveJSONFile(path, shipState{Shipped: 7}); err != nil {
		t.Fatal(err)
	}
	if st, err := loadShipState(env, "db1"); err != nil || st.Shipped != 7 {
		t.Fatalf("saved state: %+v %v", st, err)
	}
	if err := os.WriteFile(path, []byte(`{"last": {"t": 1`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadShipState(env, "db1")
	if err != nil || !st.Last.IsZero() || st.Shipped != 0 {
		t.Fatalf("damaged state: %+v %v", st, err)
	}
	if _, err := os.Stat(path + ".damaged"); err != nil {
		t.Fatalf("the damaged file wasn't set aside: %v", err)
	}
}
