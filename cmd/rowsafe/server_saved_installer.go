package main

import (
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// installerEngine is the engine a connection string names that Rowsafe
// adds on the server through the installer only ("" for others):
// ClickHouse, whose own user for Rowsafe the installer creates (a users.d
// file root installs, or SQL with an administrator's login).
func installerEngine(conn string) string {
	if s := strings.ToLower(strings.TrimSpace(conn)); strings.HasPrefix(s, "clickhouse://") {
		return protocol.EngineClickHouse
	}
	return ""
}

// installerAddHelp says the installer adds that engine's server.
func installerAddHelp(engine string) error {
	name := protocol.EngineDisplayName(engine)
	return fmt.Errorf("Rowsafe adds %s on its server with the installer, which gives Rowsafe its own %s user and turns on its backups:\n"+
		"  curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account\n"+
		"Then sudo rowsafe ls lists it", name, name)
}
