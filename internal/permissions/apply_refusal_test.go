package permissions

import (
	"errors"
	"testing"
)

type exitErr int

func (e exitErr) Error() string { return "exit status" }
func (e exitErr) ExitCode() int { return int(e) }

func TestInstallerRefusal(t *testing.T) {
	out := []byte("summary...\nerror: security-updates needs restart: sudo rowsafe-allow restart security-updates\n")
	if got := installerRefusal(exitErr(2), out); got != "security-updates needs restart: sudo rowsafe-allow restart security-updates" {
		t.Errorf("exit 2: %q", got)
	}
	if got := installerRefusal(exitErr(1), out); got != "the change didn't complete: security-updates needs restart: sudo rowsafe-allow restart security-updates" {
		t.Errorf("exit 1: %q", got)
	}
	if got := installerRefusal(errors.New("signal: killed"), []byte("no error line")); got != "the installer couldn't apply the change (signal: killed)" {
		t.Errorf("no line: %q", got)
	}
}
