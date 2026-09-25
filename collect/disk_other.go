//go:build !linux

package collect

// diskKind is unknown outside Linux.
func diskKind(string) string { return "" }
