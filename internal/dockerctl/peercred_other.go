//go:build !linux

package dockerctl

import (
	"errors"
	"net"
)

// peerCred is Linux only: elsewhere every connection is refused (the
// service only ever runs in a Linux container).
func peerCred(net.Conn) (Peer, error) {
	return Peer{}, errors.New("peer credentials are only available on Linux")
}
