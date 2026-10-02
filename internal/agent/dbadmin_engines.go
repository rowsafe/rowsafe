package agent

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rowsafe/rowsafe/protocol"
)

// Helpers for the other engines' Databases & users (dbadmin) tasks: the
// same passwords, sealing and addresses PostgreSQL uses, so a password
// made for a MySQL, MongoDB or ClickHouse user leaves the server only
// sealed to the requester's key.

// NewDBPassword returns a random password of letters and digits (32, ~190
// bits) for a new database user.
func NewDBPassword() (string, error) { return newPassword() }

// SealDBSecret encrypts a new password and its connection string to the
// requester's key, bound to the task. c.Engine picks the URL's scheme.
func SealDBSecret(publicKey, taskID string, c protocol.DBConnection, password string) (*protocol.SealedSecret, error) {
	secret := protocol.DBSecret{DBConnection: c, Password: password, URL: protocol.ConnectionURL(c, password)}
	plain, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	sealed, err := protocol.Seal(publicKey, []byte(taskID), plain)
	if err != nil {
		return nil, fmt.Errorf("the password was set but couldn't be encrypted for you (%v); reset it to get a new one", err)
	}
	return sealed, nil
}

// DBServerAddresses lists where apps can reach a server that listens on
// listen (comma-separated addresses; "*", "0.0.0.0" or "::" for all,
// "" or loopback addresses for this server only) and suggests the one for
// connection strings. clients counts the connections by client IP.
func DBServerAddresses(listen string, clients map[string]int) (addrs []protocol.DBAddress, suggested string, localOnly bool) {
	hostname, _ := os.Hostname()
	return serverAddresses(interfaceNets(), hostname, listen, clients)
}

// DBConnectionFor completes c (Engine, User, Database set) with the host
// asked for, else the suggested one, the port and the TLS mode.
func DBConnectionFor(c protocol.DBConnection, host string, inv *protocol.DBInventory, port int, tls bool) protocol.DBConnection {
	c.Port = port
	c.SSLMode = "prefer"
	if tls {
		c.SSLMode = "require"
	}
	c.Host = host
	if c.Host == "" && inv != nil {
		c.Host = inv.SuggestedHost
	}
	if c.Host == "" {
		c.Host = "localhost"
	}
	return c
}

// Sentence makes an error read as a sentence (capital first letter, final
// period), as task errors are shown to people.
func Sentence(err error) error { return sentence(err) }
