package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// The databases a new Rowsafe Cloud server can run: what the catalog
// offers (protocol.CloudEngines filtered by the control plane), PostgreSQL
// alone from a control plane that doesn't say.

// offeredEngines are the catalog's engines.
func offeredEngines(cat client.CloudCatalog) []protocol.CloudEngine {
	if len(cat.Engines) > 0 {
		return cat.Engines
	}
	e, _ := protocol.CloudEngineFor(protocol.EnginePostgreSQL)
	return []protocol.CloudEngine{e}
}

// chooseEngine reads --engine, --engine-version and --postgres (an older
// spelling of --engine postgresql --engine-version).
func chooseEngine(cat client.CloudCatalog, name, version, pg string, standby bool) (protocol.CloudEngine, string, error) {
	offered := offeredEngines(cat)
	if pg != "" {
		if name != "" && protocol.NormalizeEngine(name) != protocol.EnginePostgreSQL {
			return protocol.CloudEngine{}, "", fmt.Errorf("--postgres is PostgreSQL's version: use --engine-version with --engine %s", name)
		}
		if version != "" && version != pg {
			return protocol.CloudEngine{}, "", fmt.Errorf("--postgres %s and --engine-version %s disagree: give one", pg, version)
		}
		name, version = protocol.EnginePostgreSQL, pg
	}
	want := protocol.NormalizeEngine(name)
	i := slices.IndexFunc(offered, func(e protocol.CloudEngine) bool { return e.Engine == want })
	if i < 0 {
		var names []string
		for _, e := range offered {
			names = append(names, e.Engine)
		}
		switch want {
		case protocol.EngineMongoDB, protocol.EngineRedis:
			return protocol.CloudEngine{}, "", fmt.Errorf("Rowsafe doesn't host %s (its license doesn't allow it): choose --engine %s", protocol.EngineDisplayName(want), strings.Join(names, ", "))
		}
		return protocol.CloudEngine{}, "", fmt.Errorf("Rowsafe Cloud doesn't offer --engine %s: choose %s", name, strings.Join(names, ", "))
	}
	e := offered[i]
	if version == "" {
		version = e.DefaultVersion
	}
	switch {
	case !slices.Contains(e.Versions, version):
		return e, "", fmt.Errorf("Rowsafe installs %s %s on new servers, not %s", e.Name, strings.Join(e.Versions, ", "), version)
	case standby && !e.Standby:
		return e, "", fmt.Errorf("a standby server is offered for PostgreSQL so far, not %s: leave out --standby", e.Name)
	}
	return e, version, nil
}

// catalogFor is the catalog without the sizes engine can't run on (MySQL's
// packages are built for Intel and AMD only); a size asked for by name that
// is one of them is kept, so pickCloud's error doesn't hide why (see
// armRefusal).
func catalogFor(cat client.CloudCatalog, e protocol.CloudEngine, size string) client.CloudCatalog {
	if !e.AMD64Only {
		return cat
	}
	out := cat
	out.Clouds = nil
	for _, cl := range cat.Clouds {
		cl.Sizes = slices.DeleteFunc(slices.Clone(cl.Sizes), func(z client.CloudSize) bool { return z.Arch == "arm64" && z.ID != size })
		out.Clouds = append(out.Clouds, cl)
	}
	return out
}

// armRefusal refuses a size with an Arm processor for an engine built for
// Intel and AMD only.
func armRefusal(e protocol.CloudEngine, z client.CloudSize) error {
	if e.AMD64Only && z.Arch == "arm64" {
		return fmt.Errorf("%s's own packages are built for Intel and AMD processors only, and the size %s has an Arm processor: choose another --size or --cloud", e.Name, z.ID)
	}
	return nil
}

// amd64OnlyEngines names the offered engines that can't run on Arm sizes.
func amd64OnlyEngines(cat client.CloudCatalog) string {
	var names []string
	for _, e := range offeredEngines(cat) {
		if e.AMD64Only {
			names = append(names, e.Name)
		}
	}
	return strings.Join(names, " or ")
}

// printEngines lists the databases a new server can run, when there is a
// choice.
func printEngines(cat client.CloudCatalog) {
	offered := offeredEngines(cat)
	if len(offered) < 2 {
		return
	}
	fmt.Println("Databases (--engine, --engine-version):")
	for _, e := range offered {
		line := fmt.Sprintf("  %s (%s): %s, default %s; apps connect on port %d with TLS", e.Name, e.Engine, strings.Join(e.Versions, ", "), e.DefaultVersion, e.Port)
		if !e.Standby {
			line += "; no standby yet"
		}
		if e.AMD64Only {
			line += "; Intel and AMD sizes only (not Arm)"
		}
		fmt.Println(line)
	}
}

// serverPort is where apps reach s: its own port, else its engine's.
func serverPort(s client.CloudServer) int {
	if s.Port != 0 {
		return s.Port
	}
	if e, ok := protocol.CloudEngineFor(s.Engine); ok {
		return e.Port
	}
	return 5432
}

// engineURLExample is the connection string to fill in for a server that
// isn't PostgreSQL.
func engineURLExample(s client.CloudServer, host string, port int) string {
	conn := protocol.DBConnection{Engine: protocol.NormalizeEngine(s.Engine), User: "USER", Host: host, Port: port, SSLMode: "require"}
	if conn.Engine != protocol.EngineValkey && conn.Engine != protocol.EngineRedis {
		conn.Database = "DBNAME"
	}
	return protocol.ConnectionURL(conn, "PASSWORD")
}
