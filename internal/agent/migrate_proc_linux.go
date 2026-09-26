package agent

import "syscall"

// migrateProcAttr makes pg_dump and pg_restore die with the agent.
func migrateProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
