//go:build linux || darwin

package main

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readSecretLine reads one line from stdin; when stdin is a terminal, the
// typed characters aren't shown.
func readSecretLine() string {
	fd := int(os.Stdin.Fd())
	if old, err := unix.IoctlGetTermios(fd, ioctlGetTermios); err == nil {
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		if unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet) == nil {
			defer func() {
				_ = unix.IoctlSetTermios(fd, ioctlSetTermios, old)
				os.Stderr.WriteString("\n")
			}()
		}
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
