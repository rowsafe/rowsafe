//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in its own process group.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
