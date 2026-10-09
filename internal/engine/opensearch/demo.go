package opensearch

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// What OpenSearch's demo configuration (install_demo_configuration.sh, the
// packages' default unless turned off) leaves behind, for Pulse and the
// installer: users that still sign in with their published passwords,
// published certificates, and its published super administrator
// certificate (CN=kirk), whose key Rowsafe never reads (only its mode).

// demoLogins are the demo users and their published passwords (admin's
// was admin before OpenSearch 2.12).
var demoLogins = []Login{
	{User: "admin", Password: "admin"}, {User: "kibanaserver", Password: "kibanaserver"}, {User: "kibanaro", Password: "kibanaro"},
	{User: "logstash", Password: "logstash"}, {User: "readall", Password: "readall"}, {User: "snapshotrestore", Password: "snapshotrestore"},
}

// demoEvery: the demo users are tried this often (a few sign-ins).
const demoEvery = 6 * time.Hour

// demoCheck fills st's demo fields (users only when tryLogins).
func demoCheck(ctx context.Context, port int, st *protocol.OpenSearchStatus, tryLogins bool) {
	conf := readNodeConf(prodConfDir())
	for _, p := range findServers() {
		if p.Port == port {
			conf = p.Conf
		}
	}
	st.DemoCertificates = conf.UnsafeDemoCerts
	for _, dn := range conf.AdminDN {
		if strings.Contains(strings.ToUpper(dn), "CN=KIRK") {
			st.DemoAdminDN = true
		}
	}
	for _, f := range []string{"kirk-key.pem", "admin-key.pem"} {
		if fi, err := os.Stat(filepath.Join(prodConfDir(), f)); err == nil && fi.Mode().Perm()&0o044 != 0 {
			st.AdminKeyReadable = true
		}
	}
	if st.TLS {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if c, err := servedCert(cctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
			if strings.Contains(c.Issuer.String(), "Example Com Inc.") || strings.HasSuffix(c.Subject.CommonName, ".example.com") {
				st.DemoCertificates = true
			}
		}
		cancel()
	}
	if !tryLogins || !st.SecurityPlugin {
		return
	}
	st.DemoUsers = nil
	for _, l := range demoLogins {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := dial(cctx, port, l)
		cancel()
		if err == nil {
			st.DemoUsers = append(st.DemoUsers, l.User)
		}
	}
}

// packageKeyStatus is where root's key refresher (the installer's
// rowsafe-opensearch-key.timer) says whether apt still trusts OpenSearch's
// repository: "ok", or a sentence.
const packageKeyStatus = "/var/lib/rowsafe-opensearch/key-status"

func packageKeyProblem() string {
	data, err := os.ReadFile(packageKeyStatus)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "ok" {
		return ""
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// transportPublic reports whether the node-to-node port is bound beyond
// loopback.
func transportPublic(ctx context.Context, c *client) bool {
	var v struct {
		Nodes map[string]struct {
			Transport struct {
				Bound []string `json:"bound_address"`
			} `json:"transport"`
		} `json:"nodes"`
	}
	if err := c.get(ctx, "/_nodes/_local/transport", &v); err != nil {
		return false
	}
	for _, n := range v.Nodes {
		for _, a := range n.Transport.Bound {
			h, _, err := net.SplitHostPort(a)
			if err != nil {
				h = a
			}
			h = strings.TrimPrefix(h, "::ffff:")
			if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
				return true
			}
		}
	}
	return false
}
