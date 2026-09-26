//go:build !linux

package agent

import "syscall"

func migrateProcAttr() *syscall.SysProcAttr { return nil }
