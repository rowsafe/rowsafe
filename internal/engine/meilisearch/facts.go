package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// server is what the agent knows about one Meilisearch instance on this
// server: its own API key and the facts the installer (root) found when it
// made that key (`rowsafe-agent meilisearch login`). Meilisearch's API
// can't say where its program, data and snapshot folders are. It is kept
// in the agent's state (server-<port>.json, 0600): the key is the agent's
// own, never Meilisearch's master key, which stays root's.
type server struct {
	// Port is the port apps use (DatabaseSpec.Port); LocalPort, when set,
	// is where Meilisearch itself listens on 127.0.0.1, behind Rowsafe's
	// TLS front on Port (servers Rowsafe creates).
	Port      int `json:"port"`
	LocalPort int `json:"local_port,omitempty"`
	// TLS: Meilisearch serves TLS itself on Port (its own certificate).
	TLS bool `json:"tls,omitempty"`
	// Listen is where apps reach it: the addresses of its --http-addr (or
	// of Rowsafe's TLS front), "127.0.0.1" for this server only.
	Listen string `json:"listen,omitempty"`
	// Key is Rowsafe's API key, KeyUID its uid in Meilisearch. NoAuth:
	// the instance has no master key, so it asks for no key at all (Key
	// is empty; Pulse says so).
	Key    string `json:"key"`
	KeyUID string `json:"key_uid"`
	NoAuth bool   `json:"no_auth,omitempty"`
	// Binary is the Meilisearch program (temporary instances for Proof and
	// Rewind use it), DBPath its data folder (data.ms), SnapshotDir where
	// it writes snapshots (<SnapshotDir>/<base of DBPath>.snapshot), Unit
	// its systemd unit.
	Binary      string `json:"binary"`
	DBPath      string `json:"db_path,omitempty"`
	SnapshotDir string `json:"snapshot_dir"`
	Unit        string `json:"unit,omitempty"`
	// Rowsafe: installed by Rowsafe's installer (--install-meilisearch).
	Rowsafe bool `json:"rowsafe,omitempty"`
	// MaxIndexingMemory (bytes) and Analytics, when the installer read
	// them from the instance's settings (nil: unknown).
	MaxIndexingMemory int64     `json:"max_indexing_memory,omitempty"`
	Analytics         *bool     `json:"analytics,omitempty"`
	MadeAt            time.Time `json:"made_at"`
}

// localPort is where the agent talks to Meilisearch.
func (s server) localPort() int {
	if s.LocalPort > 0 {
		return s.LocalPort
	}
	return s.Port
}

// snapshotFile is the file Meilisearch writes a snapshot to.
func (s server) snapshotFile() string {
	name := "data.ms"
	if s.DBPath != "" {
		name = filepath.Base(filepath.Clean(s.DBPath))
	}
	return filepath.Join(s.SnapshotDir, name+".snapshot")
}

// keyRE: Meilisearch's keys are 64 hex characters.
var keyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func serverFile(env agent.EngineEnv, port int) string {
	return filepath.Join(env.SharedStateDir(), "server-"+strconv.Itoa(port)+".json")
}

// errNoLogin: the installer hasn't made Rowsafe's key for this port.
var errNoLogin = errors.New("Rowsafe has no API key for this Meilisearch yet: run the Rowsafe installer on the server again " +
	"(it makes Rowsafe's own key once with the master key, which it never keeps)")

// loadServer reads the facts for port.
func loadServer(env agent.EngineEnv, port int) (server, error) {
	var s server
	if port <= 0 {
		return s, fmt.Errorf("invalid Meilisearch port %d", port)
	}
	if err := loadJSONFile(serverFile(env, port), &s); err != nil {
		if notExist(err) {
			return s, errNoLogin
		}
		return s, fmt.Errorf("reading Rowsafe's Meilisearch settings: %w", err)
	}
	if s.Port != port || !(keyRE.MatchString(s.Key) || s.NoAuth && s.Key == "") {
		return s, errors.New("Rowsafe's Meilisearch settings for this port are damaged: run the Rowsafe installer on the server again")
	}
	return s, nil
}

func saveServer(env agent.EngineEnv, s server) error {
	return saveJSONFile(serverFile(env, s.Port), s)
}

// knownPorts are the ports the agent has a key for.
func knownPorts(env agent.EngineEnv) []int {
	matches, _ := filepath.Glob(filepath.Join(env.SharedStateDir(), "server-*.json"))
	var out []int
	for _, m := range matches {
		p, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "server-"), ".json"))
		if err == nil && p > 0 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// connect opens a client for db with Rowsafe's key, finding out once
// whether the instance speaks plain HTTP or TLS on its local port.
func connect(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*client, server, error) {
	if env.Config.Sidecar() {
		return nil, server{}, errors.New("Rowsafe protects a Meilisearch installed on the server itself for now, not one in Docker")
	}
	s, err := loadServer(env, db.Port)
	if err != nil {
		return nil, s, err
	}
	c, err := dial(ctx, s)
	return c, s, err
}

// dial is a client for s (plain HTTP, or TLS when the instance serves its
// own certificate on its port).
func dial(ctx context.Context, s server) (*client, error) {
	scheme := "http"
	if s.TLS && s.LocalPort == 0 {
		scheme = "https"
	}
	c := newClient(scheme, s.localPort(), s.Key, prodCheck(s))
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.health(hctx); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}
