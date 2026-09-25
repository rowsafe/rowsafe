package agent

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// dbInventory lists what is inside the server: databases, users,
// extensions, and the addresses apps can reach it at. Names and settings
// only: password hashes are reduced to their kind, never sent.
func dbInventory(ctx context.Context, t pginspect.Target, conn *pgx.Conn, port int, me string) (*protocol.DBInventory, error) {
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Port: port, AgentUser: me}
	var listen string
	var super bool
	if err := conn.QueryRow(ctx, `
		SELECT current_setting('server_version'), current_setting('ssl') = 'on', current_setting('listen_addresses'),
		       coalesce((SELECT datcollate::text FROM pg_database WHERE datname = 'template1'), ''),
		       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).
		Scan(&inv.ServerVersion, &inv.SSL, &listen, &inv.DefaultLocale, &super); err != nil {
		return nil, err
	}

	// Databases.
	rows, err := conn.Query(ctx, `
		SELECT d.datname::text, pg_get_userbyid(d.datdba)::text,
		       coalesce(CASE WHEN has_database_privilege(d.oid, 'CONNECT') THEN pg_database_size(d.oid) END, 0),
		       pg_encoding_to_char(d.encoding)::text, d.datcollate::text, d.datallowconn, d.datistemplate,
		       (SELECT count(*) FROM pg_stat_activity a WHERE a.datid = d.oid)::int
		FROM pg_database d ORDER BY d.datname LIMIT $1`, maxInventoryItems+1)
	if err != nil {
		return nil, err
	}
	var db protocol.DBDatabase
	if _, err := pgx.ForEachRow(rows, []any{&db.Name, &db.Owner, &db.SizeBytes, &db.Encoding, &db.Collation,
		&db.AllowConnections, &db.IsTemplate, &db.Connections}, func() error {
		db.System = protocol.SystemDatabase(db.Name)
		inv.Databases = append(inv.Databases, db)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(inv.Databases) > maxInventoryItems {
		inv.Databases, inv.Truncated = inv.Databases[:maxInventoryItems], true
	}

	// Users. How a password is stored needs pg_authid (superusers only);
	// only its kind is read.
	pwKind := `'unknown'`
	from := `pg_roles r`
	if super {
		pwKind = `CASE WHEN a.rolpassword IS NULL THEN 'none' WHEN a.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256'
		               WHEN a.rolpassword LIKE 'md5%' THEN 'md5' ELSE 'unknown' END`
		from = `pg_roles r JOIN pg_authid a ON a.oid = r.oid`
	}
	rows, err = conn.Query(ctx, `
		SELECT r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication,
		       CASE WHEN isfinite(r.rolvaliduntil) THEN r.rolvaliduntil END,
		       `+pwKind+`,
		       ARRAY(SELECT b.rolname::text FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid
		             WHERE m.member = r.oid AND b.rolname NOT LIKE 'pg\_%' ORDER BY 1),
		       ARRAY(SELECT d.datname::text FROM pg_database d
		             WHERE d.datallowconn AND NOT d.datistemplate AND has_database_privilege(r.oid, d.oid, 'CONNECT') ORDER BY 1),
		       ARRAY(SELECT d.datname::text FROM pg_database d WHERE d.datdba = r.oid ORDER BY 1),
		       (SELECT count(*) FROM pg_stat_activity s WHERE s.usesysid = r.oid)::int
		FROM `+from+`
		WHERE r.rolname NOT LIKE 'pg\_%'
		ORDER BY r.rolname LIMIT $1`, maxInventoryItems+1)
	if err != nil {
		return nil, err
	}
	var u protocol.DBUser
	if _, err := pgx.ForEachRow(rows, []any{&u.Name, &u.Login, &u.Superuser, &u.CreateDB, &u.CreateRole, &u.Replication,
		&u.ValidUntil, &u.Password, &u.MemberOf, &u.Databases, &u.Owns, &u.Connections}, func() error {
		x := u
		if why := protectedRole(x.Name, x.Superuser, me); why != "" {
			x.System, x.SystemReason = true, upperFirst(why)+"."
		}
		if u.ValidUntil != nil {
			v := *u.ValidUntil
			x.ValidUntil = &v
		}
		inv.Users = append(inv.Users, x)
		u = protocol.DBUser{} // nothing is shared with the next row
		return nil
	}); err != nil {
		return nil, err
	}
	if len(inv.Users) > maxInventoryItems {
		inv.Users, inv.Truncated = inv.Users[:maxInventoryItems], true
	}

	// Extensions available on the server, and installed per database.
	rows, err = conn.Query(ctx, `SELECT name::text, coalesce(default_version, ''), coalesce(comment, '') FROM pg_available_extensions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var e protocol.DBExtension
	if _, err := pgx.ForEachRow(rows, []any{&e.Name, &e.DefaultVersion, &e.Comment}, func() error {
		x := e
		x.Untrusted = protocol.DBExtensionUntrusted(x.Name)
		inv.Extensions = append(inv.Extensions, x)
		return nil
	}); err != nil {
		return nil, err
	}
	scanned := 0
	for i := range inv.Databases {
		d := &inv.Databases[i]
		if !d.AllowConnections || d.IsTemplate || scanned >= maxExtensionScans {
			continue
		}
		scanned++
		d.Extensions = databaseExtensions(ctx, t, d.Name)
	}

	// Where apps reach it.
	clients := map[string]int{}
	rows, err = conn.Query(ctx, `
		SELECT host(client_addr), count(*)::int FROM pg_stat_activity
		WHERE client_addr IS NOT NULL AND backend_type = 'client backend' GROUP BY 1`)
	if err == nil {
		var ip string
		var n int
		_, err = pgx.ForEachRow(rows, []any{&ip, &n}, func() error {
			clients[ip] = n
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = serverAddresses(interfaceNets(), hostname, listen, clients)
	return inv, nil
}

// databaseExtensions reads the extensions installed in one database (nil if
// it can't be read quickly).
func databaseExtensions(ctx context.Context, t pginspect.Target, name string) []protocol.DBInstalledExtension {
	ctx, cancel := context.WithTimeout(ctx, extensionScanBudget)
	defer cancel()
	c, err := t.Connect(ctx, name)
	if err != nil {
		return nil
	}
	defer closeConn(ctx, c)
	rows, err := c.Query(ctx, `SELECT extname::text, extversion FROM pg_extension ORDER BY 1`)
	if err != nil {
		return nil
	}
	out := []protocol.DBInstalledExtension{}
	var x protocol.DBInstalledExtension
	if _, err := pgx.ForEachRow(rows, []any{&x.Name, &x.Version}, func() error {
		out = append(out, x)
		return nil
	}); err != nil {
		return nil
	}
	return out
}

// interfaceNets are this host's addresses, without loopback and link-local
// ones.
func interfaceNets() []*net.IPNet {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || n.IP.IsMulticast() {
			continue
		}
		out = append(out, n)
	}
	return out
}

// cgnat is 100.64.0.0/10 (carrier-grade NAT, also Tailscale): private.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func addressKind(ip net.IP) string {
	if ip.IsPrivate() || cgnat.Contains(ip) {
		return protocol.AddressPrivate
	}
	return protocol.AddressPublic
}

// serverAddresses lists where apps can reach PostgreSQL (the addresses it
// listens on) and suggests the one for connection strings: the address
// most current clients came in through, else a private one, else a public
// one, else the host name. clients counts connections by client IP.
func serverAddresses(nets []*net.IPNet, hostname, listen string, clients map[string]int) ([]protocol.DBAddress, string, bool) {
	listenAll, localOnly := false, true
	var listenIPs []string
	for _, a := range strings.Split(listen, ",") {
		switch a = strings.TrimSpace(a); a {
		case "":
		case "*", "0.0.0.0", "::":
			listenAll, localOnly = true, false
		case "localhost", "127.0.0.1", "::1":
		default:
			localOnly = false
			listenIPs = append(listenIPs, a)
		}
	}
	local := protocol.DBAddress{Address: "localhost", Kind: protocol.AddressLocal}
	var out []protocol.DBAddress
	if !localOnly {
		for _, n := range nets {
			ip := n.IP.String()
			if !listenAll && !slices.Contains(listenIPs, ip) {
				continue
			}
			out = append(out, protocol.DBAddress{Address: ip, Kind: addressKind(n.IP)})
		}
		// Count clients by the local address in their network; others
		// (from elsewhere on the internet) came in through a public
		// address, if there is one.
		for cip, n := range clients {
			ip := net.ParseIP(cip)
			if ip == nil {
				continue
			}
			if ip.IsLoopback() {
				local.Clients += n
				continue
			}
			idx := -1
			for i, a := range out {
				for _, nw := range nets {
					if nw.IP.String() == a.Address && nw.Contains(ip) {
						idx = i
					}
				}
			}
			if idx < 0 {
				idx = slices.IndexFunc(out, func(a protocol.DBAddress) bool { return a.Kind == protocol.AddressPublic })
			}
			if idx >= 0 {
				out[idx].Clients += n
			}
		}
		if hostname != "" && hostname != "localhost" && (listenAll || slices.Contains(listenIPs, hostname)) {
			out = append(out, protocol.DBAddress{Address: hostname, Kind: protocol.AddressHostname})
		}
	} else {
		for _, n := range clients {
			local.Clients += n
		}
	}
	out = append(out, local)

	rank := func(a protocol.DBAddress) int {
		switch a.Kind {
		case protocol.AddressPrivate:
			return 0
		case protocol.AddressPublic:
			return 1
		case protocol.AddressHostname:
			return 2
		}
		return 3
	}
	slices.SortStableFunc(out, func(a, b protocol.DBAddress) int {
		if a.Clients != b.Clients {
			return b.Clients - a.Clients
		}
		return rank(a) - rank(b)
	})
	return out, out[0].Address, localOnly
}
