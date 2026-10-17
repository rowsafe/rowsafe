package main

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in its own process group, without a console window.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
}
