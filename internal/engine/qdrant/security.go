package qdrant

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for Qdrant: whether it asks for a key, uses TLS, takes
// JSON Web Tokens, lets any web page call it (CORS), may fetch snapshots
// from any URL, sends telemetry and opens its cluster port; and the keys
// (never their values): the server's own, Rowsafe's, and the ones made in
// Databases & users. Everything else is the agent's (addresses, firewall)
// and the control plane's (the look from the internet at REST and gRPC).

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	qs := &protocol.QdrantSecurity{}
	rep := protocol.SecurityReport{Port: db.Port, EngineSecurity: &protocol.EngineSecurity{Qdrant: qs}}
	es := rep.EngineSecurity
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return rep, err
	}
	defer c.Close()
	r, err := c.root(ctx)
	if err != nil {
		return rep, err
	}
	rep.ServerVersion, rep.VersionNum = r.Version, parseVersion(r.Version)
	rep.SSL = c.base.Scheme == "https"
	es.RequireTLS = rep.SSL // with TLS on, Qdrant serves nothing in plain text
	fc, path, known := readConfig()
	qs.ConfigFile, qs.ConfigKnown = path, known
	es.ConfigFile = path
	// Defaults Qdrant applies when the file doesn't say.
	host, grpcPort := "0.0.0.0", 6334
	qs.CORS, qs.URLRecovery, qs.Telemetry = true, true, true
	if known {
		if fc.Service.Host != "" {
			host = fc.Service.Host
		}
		if fc.Service.GRPCPort != nil {
			grpcPort = *fc.Service.GRPCPort
		}
		if fc.Service.EnableCORS != nil {
			qs.CORS = *fc.Service.EnableCORS
		}
		if fc.Service.SnapshotURLRecover != nil {
			qs.URLRecovery = *fc.Service.SnapshotURLRecover
		}
		if fc.TelemetryDisabled != nil {
			qs.Telemetry = !*fc.TelemetryDisabled
		}
		if fc.Cluster.Enabled != nil && *fc.Cluster.Enabled {
			p2pHost := fc.Cluster.P2P.Host
			if p2pHost == "" {
				p2pHost = host
			}
			qs.P2P = !isLoopback(p2pHost)
		}
	} else if inDocker() {
		host = "0.0.0.0"
	}
	rep.ListenAddresses = host
	qs.GRPCPort = grpcPort
	if grpcPort > 0 && grpcPort != db.Port {
		rep.OutsidePorts = []int{grpcPort}
	}
	// A key is required when Qdrant turns away a request without one.
	anon := &client{base: c.base, http: c.http}
	_, aerr := anon.collectionNames(ctx)
	qs.APIKey = aerr != nil && (isStatus(aerr, http.StatusUnauthorized) || isStatus(aerr, http.StatusForbidden))
	es.AuthDisabled = aerr == nil
	if !known {
		qs.CORS = corsOn(ctx, anon)
	}
	l, _, _ := loadLogin(env, db.Port)
	qs.JWT = l.JWT
	var t telemetry
	if err := c.call(ctx, http.MethodGet, "/telemetry", nil, nil, &t); err == nil && t.App.JWTRBAC != nil {
		qs.JWT = *t.App.JWTRBAC
	}
	qs.ReadOnlyKey = known && fc.Service.ReadOnlyAPIKey != "" || keysSet()["read_only_api_key"]
	if rep.SSL {
		rep.Cert = certInfo(ctx, c)
		if rep.Cert != nil {
			rep.SSLCertFile = filepath.Join(ServerTLSDir, serverCertFile)
			if !rep.Cert.Rowsafe {
				rep.SSLCertFile = ""
			}
		}
	}
	// Keys: the server's own, Rowsafe's and those made in Databases & users.
	switch {
	case !qs.APIKey:
		rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "anyone (no key)", Superuser: true, CanLogin: true, Password: protocol.PasswordNone})
	default:
		rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "api_key (admin)", Superuser: true, CanLogin: true, Password: protocol.PasswordSet})
		if qs.ReadOnlyKey {
			rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "read_only_api_key", CanLogin: true, Password: protocol.PasswordSet})
		}
	}
	if l.Key != "" && l.Source == "alt" {
		rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "rowsafe (Rowsafe's key)", Superuser: true, CanLogin: true, Password: protocol.PasswordSet})
	}
	// The keys made in Databases & users, after making Rowsafe's list in
	// Qdrant match the agent's own (keys.go).
	if l.Key != "" && l.JWT {
		if list, _, err := reconcile(ctx, env, db.Port, c); err == nil {
			for _, k := range list.Keys {
				rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: k.Name, Superuser: k.admin(), CanLogin: true, Password: protocol.PasswordSet,
					ValidUntil: k.ExpiresAt})
			}
		}
	}
	return rep, nil
}

// KeysSetFile is where the installer records which of Qdrant's keys it set
// in root's environment file (names only: "api_key read_only_api_key
// alt_api_key"), the values being root's.
const KeysSetFile = "/etc/rowsafe/qdrant-keys"

// keysSet reads KeysSetFile.
func keysSet() map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(KeysSetFile)
	if err != nil {
		return out
	}
	for _, f := range strings.Fields(string(data)) {
		out[f] = true
	}
	return out
}

// corsOn asks the server whether it lets any web page call it.
func corsOn(ctx context.Context, c *client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Origin", "https://rowsafe-check.invalid")
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.Header.Get("Access-Control-Allow-Origin") != ""
}

// certInfo describes the certificate the server serves.
func certInfo(ctx context.Context, c *client) *protocol.CertInfo {
	cert, err := servedCert(ctx, c.base.Host)
	if err != nil {
		return &protocol.CertInfo{Error: err.Error()}
	}
	ci := &protocol.CertInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter, DNSNames: cert.DNSNames,
		SelfSigned: cert.CheckSignatureFrom(cert) == nil && bytes.Equal(cert.RawIssuer, cert.RawSubject)}
	if data, err := os.ReadFile(filepath.Join(ServerTLSDir, serverCertFile)); err == nil {
		if b, _ := pem.Decode(data); b != nil && bytes.Equal(b.Bytes, cert.Raw) {
			ci.Rowsafe = true
		}
	}
	return ci
}

// SecurityFix runs one fix. Qdrant's own settings (keys, TLS, CORS) live
// in its configuration file, root's, and take effect at a restart: the
// security check shows how under "Do it yourself"; the firewall is the
// agent's (it runs before this).
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SecurityFixParams, tl agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	return nil, fmt.Errorf("Rowsafe can't change %q on Qdrant from here: Qdrant keeps it in its configuration file, which only root changes on the server",
		p.Action)
}
