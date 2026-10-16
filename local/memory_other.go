//go:build !darwin

package local

// machineMemory is 0 where collect already reads it (Linux's /proc) or
// can't.
func machineMemory() int64 { return 0 }
