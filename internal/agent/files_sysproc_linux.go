package agent

import "syscall"

// filesSysProcAttr makes restic die with the agent, like pgBackRest.
func filesSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
