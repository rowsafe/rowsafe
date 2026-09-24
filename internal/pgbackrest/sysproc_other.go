//go:build !linux

package pgbackrest

import "syscall"

func sysProcAttr() *syscall.SysProcAttr { return nil }
