//go:build !linux

package agent

import "syscall"

func filesSysProcAttr() *syscall.SysProcAttr { return nil }
