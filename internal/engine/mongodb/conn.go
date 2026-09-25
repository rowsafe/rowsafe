package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Login is how the agent signs in to one MongoDB server. The installer
// creates a dedicated user with a random password (CreateLogin) and saves
// it in the engine's state directory, readable only by the agent; it never
// leaves the server.
type Login struct {
	User       string `json:"user,omitempty"`
	Password   string `json:"password,omitempty"`
	AuthSource string `json:"auth_source,omitempty"` // default admin
	// Host is where the server listens, "127.0.0.1" unless set.
	Host string `json:"host,omitempty"`
	// URI, when set, is used as is (ROWSAFE_MONGODB_URI, Docker sidecars).
	URI string `json:"-"`
}

// loginEnv is the whole connection string for a sidecar (or a single
// custom server): mongodb://user:password@host:port/?authSource=admin.
const loginEnv = "ROWSAFE_MONGODB_URI"

func loginsDir(env agent.EngineEnv) string { return filepath.Join(env.StateDir, "logins") }

func loginPath(env agent.EngineEnv, port int) string {
	return filepath.Join(loginsDir(env), strconv.Itoa(port)+".json")
}

// loadLogin finds the login for the server on port: ROWSAFE_MONGODB_URI,
// else the saved login, else none (a server without access control).
func loadLogin(env agent.EngineEnv, port int) (Login, error) {
	if u := strings.TrimSpace(os.Getenv(loginEnv)); u != "" {
		return Login{URI: u}, nil
	}
	data, err := os.ReadFile(loginPath(env, port))
	if errors.Is(err, os.ErrNotExist) {
		return Login{}, nil
	}
	if err != nil {
		return Login{}, err
	}
	var l Login
	if err := json.Unmarshal(data, &l); err != nil {
		return Login{}, fmt.Errorf("reading %s: %w", loginPath(env, port), err)
	}
	return l, nil
}

// saveLogin writes the login (0600) for the server on port.
func saveLogin(env agent.EngineEnv, port int, l Login) error {
	if err := os.MkdirAll(loginsDir(env), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(l, "", "  ")
	tmp := loginPath(env, port) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, loginPath(env, port))
}

// uri is the connection string for the server on port.
func (l Login) uri(port int) string {
	if l.URI != "" {
		return l.URI
	}
	host := l.Host
	if host == "" {
		// ROWSAFE_MONGODB_HOST: the database container's name for a Docker
		// sidecar; the server itself (127.0.0.1) everywhere else.
		host = cmpOr(strings.TrimSpace(os.Getenv("ROWSAFE_MONGODB_HOST")), "127.0.0.1")
	}
	u := url.URL{Scheme: "mongodb", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/"}
	q := url.Values{"directConnection": {"true"}}
	if l.User != "" {
		u.User = url.UserPassword(l.User, l.Password)
		q.Set("authSource", cmpOr(l.AuthSource, "admin"))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// socketURI is the connection string for a scratch server's Unix socket.
func socketURI(sock string) string {
	return "mongodb://" + url.PathEscape(sock) + "/?directConnection=true"
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// connect opens a client and checks the server answers.
func connect(ctx context.Context, uri string) (*mongo.Client, error) {
	opts := options.Client().SetAppName("rowsafe-agent").ApplyURI(uri).
		SetServerSelectionTimeout(10 * time.Second).SetConnectTimeout(10 * time.Second)
	c, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.Ping(pctx, nil); err != nil {
		_ = c.Disconnect(context.Background())
		return nil, plainConnError(err)
	}
	return c, nil
}

// connectDB connects to a production database's server.
func connectDB(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*mongo.Client, error) {
	l, err := loadLogin(env, db.Port)
	if err != nil {
		return nil, err
	}
	c, err := connect(ctx, l.uri(db.Port))
	if err != nil {
		return nil, fmt.Errorf("can't connect to MongoDB on port %d: %w", db.Port, err)
	}
	return c, nil
}

func disconnect(c *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Disconnect(ctx)
}

// plainConnError turns the driver's long errors into something people read.
func plainConnError(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "Authentication failed"), strings.Contains(s, "auth error"):
		return errors.New("MongoDB refused Rowsafe's login (wrong or missing user): run the Rowsafe installer on the server again to create it")
	case strings.Contains(s, "connection refused"):
		return errors.New("nothing answers on that port (is MongoDB running?)")
	case strings.Contains(s, "server selection error"), strings.Contains(s, "context deadline exceeded"):
		return fmt.Errorf("MongoDB didn't answer in time (%s)", firstLine(s))
	}
	return err
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// toolConfig writes a mongodump/mongorestore --config file holding the
// connection string (with its password), so the password never appears in
// a process list. The caller removes dir.
func toolConfig(dir, uri string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "tool.yaml")
	b, _ := json.Marshal(uri) // a JSON string is a valid YAML scalar
	if err := os.WriteFile(path, []byte("uri: "+string(b)+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
