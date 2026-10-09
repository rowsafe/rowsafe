package opensearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Installer helpers (rowsafe-agent opensearch ...). They run as the agent
// user on the server; the installer asks the questions. An administrator's
// password, when one is needed, arrives on stdin and is used once: it is
// never written anywhere.

var (
	// ErrNeedAdmin: the server asks for a login, so an administrator must
	// sign in once.
	ErrNeedAdmin = errors.New("OpenSearch needs an administrator's login once to create Rowsafe's user (it is used once and never saved)")
	// ErrAdminRefused: the login given was refused.
	ErrAdminRefused = errors.New("OpenSearch refused that login")
	// ErrCantManageUsers: that login can't use the security plugin's REST API.
	ErrCantManageUsers = errors.New("that OpenSearch login can't create users (the security plugin's REST API refused it): use an administrator mapped to all_access")
)

// agentCluster and agentIndex are the permissions of Rowsafe's role: read
// the server's health and stats, take, list, delete and restore snapshots
// in Rowsafe's repository, and (rewinds, Databases & users, fixes, only
// when a person asks) delete, create and write indices, change their
// replicas and read blocks. Managing users comes from the role being in
// plugins.security.restapi.roles_enabled (opensearch.yml).
var (
	agentCluster = []string{"cluster_monitor", "cluster_composite_ops", "cluster:admin/snapshot/*", "cluster:admin/repository/*",
		"indices:data/write/bulk", "indices:data/read/scroll*", "indices:admin/index_template/get", "indices:admin/template/get"}
	agentIndex = []string{"indices_monitor", "read", "write", "delete", "create_index", "indices:admin/delete", "indices:admin/close*",
		"indices:admin/open", "indices:admin/mapping/put", "indices:admin/mappings/get", "indices:admin/get", "indices:admin/settings/update",
		"indices:monitor/settings/get", "indices:admin/refresh*", "indices:admin/data_stream/*", "indices:admin/resolve/index", "indices:admin/aliases*"}
)

// Status describes a local server for the installer (key=value lines).
type Status struct {
	Port      int
	Version   string
	Login     string // ok, missing, refused, none (no security plugin: nothing to sign in with)
	Security  string // on, off, unknown
	TLS       string // on, off, unknown
	Repo      string // ok (path.repo allows Rowsafe's folder), missing, unknown
	RepoDir   string
	RestAPI   string // ok, no, unknown: Rowsafe's role may use the security REST API
	HotReload string // on, off: the REST certificate reloads by itself without the same issuer
	Nodes     int
	Config    string
	Home      string
	Unit      string
	User      string
}

// WriteTo prints the status as key=value lines ("-" for empty).
func (s Status) WriteTo(w io.Writer) (int64, error) {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	n, err := fmt.Fprintf(w, "port=%d\nversion=%s\nlogin=%s\nsecurity=%s\ntls=%s\nrepo=%s\nrepodir=%s\nrestapi=%s\nhotreload=%s\nnodes=%d\nconfig=%s\nhome=%s\nunit=%s\nuser=%s\n",
		s.Port, dash(s.Version), dash(s.Login), dash(s.Security), dash(s.TLS), dash(s.Repo), dash(s.RepoDir), dash(s.RestAPI), dash(s.HotReload), s.Nodes,
		dash(s.Config), dash(s.Home), dash(s.Unit), dash(s.User))
	return int64(n), err
}

// ServerStatus inspects the server on port for the installer. It fails
// only when nothing answers there.
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) (Status, error) {
	st := Status{Port: port, Security: "unknown", TLS: "unknown", Repo: "unknown", RestAPI: "unknown", HotReload: "off",
		Config: filepath.Join(prodConfDir(), "opensearch.yml"), Home: openSearchHome(), RepoDir: defaultRepoDir}
	conf := readNodeConf(prodConfDir())
	for _, p := range findServers() {
		if p.Port == port {
			st.Config, st.Home, st.Unit, st.User, conf = filepath.Join(p.ConfDir, "opensearch.yml"), p.Home, p.Unit, p.User, p.Conf
		}
	}
	st.Version = installedVersion(st.Home)
	if conf.Read {
		st.Repo = "missing"
		if slices.ContainsFunc(conf.PathRepo, func(p string) bool { return filepath.Clean(strings.TrimSpace(p)) == defaultRepoDir }) {
			st.Repo = "ok"
		}
		if conf.HotReload && !conf.ReloadDNChecked {
			st.HotReload = "on"
		}
	}
	anon, err := dial(ctx, port, Login{})
	if err != nil && statusOf(err) == 0 {
		return st, fmt.Errorf("can't connect to OpenSearch on port %d: %w", port, err)
	}
	st.TLS = "off"
	if anon.base.Scheme == "https" {
		st.TLS = "on"
	}
	if err == nil {
		// Anyone gets in: no security plugin (or anonymous access).
		st.Security = "off"
		if securityOn(ctx, anon) {
			st.Security = "on"
		}
	} else if statusOf(err) == http.StatusUnauthorized {
		st.Security = "on"
	}
	l, ok, lerr := loadLogin(env, port)
	switch {
	case lerr != nil:
		st.Login = "refused"
	case !ok && st.Security == "off":
		st.Login = "none"
	case !ok:
		st.Login = "missing"
	default:
		c, err := dial(ctx, port, l)
		if err != nil {
			st.Login = "refused"
			break
		}
		st.Login = "ok"
		if in, err := inspect(ctx, c); err == nil {
			st.Version, st.Nodes = in.Version, in.Nodes
			if _, err := repoDir(in); err == nil {
				st.Repo = "ok"
			} else if errors.Is(err, errNoRepoPath) {
				st.Repo = "missing"
			}
		}
		if st.Security == "on" {
			err := c.get(ctx, secAPI+"internalusers/"+LoginUser, nil)
			switch {
			case err == nil:
				st.RestAPI = "ok"
			case statusOf(err) == http.StatusForbidden:
				st.RestAPI = "no"
			}
		}
	}
	return st, nil
}

// HashPassword is the bcrypt hash OpenSearch's internal_users.yml takes.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// CreateLogin creates (or refreshes) Rowsafe's role and user through the
// security plugin's REST API, signing in as adminUser with adminPass, with
// a new random password, and saves the login for the agent. A server
// without the security plugin needs no login: that is saved instead.
func CreateLogin(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPass string) error {
	anon, err := dial(ctx, port, Login{})
	if err == nil && !securityOn(ctx, anon) {
		return saveLogin(env, port, Login{NoAuth: true})
	}
	if err != nil && statusOf(err) == 0 {
		return fmt.Errorf("can't connect to OpenSearch on port %d: %w", port, err)
	}
	if adminUser == "" {
		return ErrNeedAdmin
	}
	c, err := dial(ctx, port, Login{User: adminUser, Password: adminPass})
	if err != nil {
		if statusOf(err) == http.StatusUnauthorized {
			return ErrAdminRefused
		}
		return err
	}
	role := map[string]any{
		"description":         "Rowsafe's agent: health, snapshots in its own repository, and what a person asks for in the dashboard",
		"cluster_permissions": agentCluster,
		"index_permissions":   []map[string]any{{"index_patterns": []string{"*"}, "allowed_actions": agentIndex}},
	}
	if err := c.do(ctx, http.MethodPut, secAPI+"roles/"+LoginRole, role, nil); err != nil {
		if s := statusOf(err); s == http.StatusForbidden || s == http.StatusUnauthorized {
			return fmt.Errorf("%w (%v)", ErrCantManageUsers, err)
		}
		return fmt.Errorf("making Rowsafe's role: %w", err)
	}
	pw := randomPassword()
	user := map[string]any{"password": pw, "description": "Rowsafe's agent (its password stays on this server)"}
	if err := c.do(ctx, http.MethodPut, secAPI+"internalusers/"+LoginUser, user, nil); err != nil {
		return fmt.Errorf("making Rowsafe's user: %w", err)
	}
	if err := c.do(ctx, http.MethodPut, secAPI+"rolesmapping/"+LoginRole, map[string]any{"users": []string{LoginUser}}, nil); err != nil {
		return fmt.Errorf("giving Rowsafe's user its role: %w", err)
	}
	l := Login{User: LoginUser, Password: pw}
	if _, err := dial(ctx, port, l); err != nil {
		return fmt.Errorf("Rowsafe's new user can't sign in: %w", err)
	}
	return saveLogin(env, port, l)
}

func randomPassword() string {
	pw, err := agent.NewDBPassword()
	if err != nil {
		panic(err)
	}
	return pw + "-Rs1"
}

// SaveLogin saves an existing "user:password" as the agent's login, after
// checking it signs in and reads the cluster's health and snapshots.
func SaveLogin(ctx context.Context, env agent.EngineEnv, port int, userPass string) error {
	u, pw, ok := strings.Cut(strings.TrimSpace(userPass), ":")
	if !ok || u == "" {
		return errors.New("give the login as user:password")
	}
	l := Login{User: u, Password: pw}
	c, err := dial(ctx, port, l)
	if err != nil {
		if statusOf(err) == http.StatusUnauthorized {
			return ErrAdminRefused
		}
		return err
	}
	for _, path := range []string{"/_cluster/health", "/_cat/indices?format=json", "/_snapshot"} {
		if err := c.get(ctx, path, nil); err != nil && statusOf(err) == http.StatusForbidden {
			return fmt.Errorf("that user can't read %s, which Rowsafe needs", strings.SplitN(path, "?", 2)[0])
		}
	}
	return saveLogin(env, port, l)
}
