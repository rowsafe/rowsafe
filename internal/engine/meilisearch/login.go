package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Rowsafe's own API key. The installer (root) reads Meilisearch's master
// key on the server and hands it to `rowsafe-agent meilisearch login` on
// stdin, once: the agent makes this key with it and forgets it. The key
// can do what the agent needs and nothing that reads documents in bulk for
// itself: snapshots (backups), statistics and settings (Pulse, Proof),
// indexes and keys (Databases & users), swapping indexes (rewind in place)
// and adding documents back (Rewind). Meilisearch has no narrower right for
// making keys, so a key that can make keys could make one with every right;
// it never leaves this server.
var agentKeyActions = []string{
	"version", "stats.get", "indexes.get", "settings.get", "tasks.get", "tasks.delete",
	"snapshots.create", "keys.get", "keys.create", "keys.delete",
	"indexes.create", "indexes.delete", "indexes.swap", "indexes.compact",
	"documents.get", "documents.add",
}

const (
	agentKeyName = "Rowsafe"
	agentKeyDesc = "Rowsafe's agent on this server: backups, Proof, Pulse, Rewind and Databases & users (https://rowsafe.sh). Removing it stops Rowsafe's backups."
)

// LoginOptions are what the installer found about one instance.
type LoginOptions struct {
	Port        int    // the port apps use
	LocalPort   int    // Meilisearch itself on 127.0.0.1 behind Rowsafe's TLS front (0: Port)
	Binary      string // the meilisearch program
	DBPath      string // its data folder (data.ms)
	SnapshotDir string // where it writes snapshots
	Unit        string // its systemd unit
	Listen      string // the addresses apps reach it on ("0.0.0.0", "127.0.0.1"...)
	Rowsafe     bool   // installed by Rowsafe's installer
	// MaxIndexingMemory (bytes) and Analytics as configured, when known.
	MaxIndexingMemory int64
	Analytics         *bool
}

// LoginResult says what Login did.
type LoginResult struct {
	Version string
	TLS     bool
	KeyUID  string
	NoAuth  bool // the instance has no master key: Rowsafe needs no key
	// Leftover: uids of Rowsafe's older keys Meilisearch didn't delete
	// (the installer says so; the next run tries again).
	Leftover []string
}

// ErrNeedMasterKey: the instance asks for a key and none was given.
var ErrNeedMasterKey = errors.New("Meilisearch asks for a key: give its master key")

// Login makes (or makes again) Rowsafe's key with the master key and
// saves it with opts for the agent. The master key is used for this only.
func Login(ctx context.Context, env agent.EngineEnv, opts LoginOptions, masterKey string) (LoginResult, error) {
	var res LoginResult
	if opts.Port <= 0 || opts.Port > 65535 || opts.LocalPort < 0 || opts.LocalPort > 65535 {
		return res, errors.New("invalid port")
	}
	for _, p := range []string{opts.Binary, opts.SnapshotDir} {
		if !filepath.IsAbs(p) {
			return res, fmt.Errorf("%q isn't an absolute path", p)
		}
	}
	if opts.DBPath != "" && !filepath.IsAbs(opts.DBPath) {
		return res, fmt.Errorf("%q isn't an absolute path", opts.DBPath)
	}
	s := server{Port: opts.Port, LocalPort: opts.LocalPort, Binary: filepath.Clean(opts.Binary), DBPath: opts.DBPath,
		SnapshotDir: filepath.Clean(opts.SnapshotDir), Unit: opts.Unit, Listen: opts.Listen, Rowsafe: opts.Rowsafe,
		MaxIndexingMemory: opts.MaxIndexingMemory, Analytics: opts.Analytics, MadeAt: time.Now().UTC()}
	if s.LocalPort == s.Port {
		s.LocalPort = 0
	}
	// The program runs for Proof and Rewind: root's only (program.go).
	if _, err := trustedProgram(s.Binary); err != nil {
		return res, err
	}
	// The snapshot folder is the instance's: its user owns it.
	if u := ownerUID(s.SnapshotDir); u >= 0 && !slices.Contains(meilisearchUIDs(s), u) {
		return res, fmt.Errorf("the snapshot folder %s belongs to %s, not to the user Meilisearch runs as: Rowsafe doesn't read snapshots from it",
			s.SnapshotDir, userName(u))
	}
	c, tls, err := probe(ctx, s.localPort(), masterKey, prodCheck(s))
	if err != nil {
		return res, err
	}
	defer c.close()
	s.TLS = tls && s.LocalPort == 0
	v, err := c.version(ctx)
	if err != nil {
		if isAuthError(err) && masterKey == "" {
			return res, ErrNeedMasterKey
		}
		if isAuthError(err) {
			return res, errors.New("Meilisearch refused that master key")
		}
		return res, err
	}
	res.Version, res.TLS = v.PkgVersion, s.TLS
	if why := tooOld(v.PkgVersion); why != "" {
		return res, errors.New(why)
	}
	if masterKey == "" {
		// It answered without any key: no master key is set.
		s.NoAuth = true
		res.NoAuth = true
		return res, saveServer(env, s)
	}
	// The key made before (a re-run) goes once the new one works.
	var old []string
	if prev, err := loadServer(env, opts.Port); err == nil && prev.KeyUID != "" {
		old = append(old, prev.KeyUID)
	}
	keys, err := c.keys(ctx)
	if err != nil {
		if isAuthError(err) {
			return res, errors.New("that key can't manage API keys: give Meilisearch's master key")
		}
		return res, err
	}
	for _, k := range keys {
		if k.name() == agentKeyName && k.Description != nil && strings.HasPrefix(*k.Description, "Rowsafe's agent") && !containsStr(old, k.UID) {
			old = append(old, k.UID)
		}
	}
	name, desc := agentKeyName, agentKeyDesc
	k, err := c.createKey(ctx, apiKey{Name: &name, Description: &desc, Actions: agentKeyActions, Indexes: []string{"*"}})
	if isCode(err, "invalid_api_key_actions") {
		// An older Meilisearch without the newest actions (compacting
		// indexes): the rest is what the agent needs.
		var older []string
		for _, a := range agentKeyActions {
			if a != "indexes.compact" {
				older = append(older, a)
			}
		}
		k, err = c.createKey(ctx, apiKey{Name: &name, Description: &desc, Actions: older, Indexes: []string{"*"}})
	}
	if err != nil {
		return res, fmt.Errorf("making Rowsafe's API key: %w", err)
	}
	s.Key, s.KeyUID = k.Key, k.UID
	if !keyRE.MatchString(s.Key) {
		return res, errors.New("Meilisearch gave an API key Rowsafe doesn't recognize")
	}
	check := c.withKey(s.Key)
	if _, err := check.stats(ctx); err != nil {
		_ = c.deleteKey(context.WithoutCancel(ctx), k.UID)
		return res, fmt.Errorf("Rowsafe's new key doesn't work: %w", err)
	}
	if err := saveServer(env, s); err != nil {
		_ = c.deleteKey(context.WithoutCancel(ctx), k.UID)
		return res, err
	}
	// Older keys of Rowsafe's go, each tried twice; one that stays is
	// reported (and tried again by the next run, found by its name).
	for _, uid := range old {
		if uid == k.UID {
			continue
		}
		err := c.deleteKey(ctx, uid)
		if err != nil && !isCode(err, "api_key_not_found") {
			time.Sleep(time.Second)
			err = c.deleteKey(ctx, uid)
		}
		if err != nil && !isCode(err, "api_key_not_found") {
			res.Leftover = append(res.Leftover, uid)
		}
	}
	res.KeyUID = k.UID
	return res, nil
}

// probe connects to 127.0.0.1:port with key, over plain HTTP or else TLS
// (the health check, which carries no key), once check passed.
func probe(ctx context.Context, port int, key string, check listenerCheck) (*client, bool, error) {
	c := newClient("http", port, key, check)
	err := c.health(ctx)
	if err == nil {
		return c, false, nil
	}
	c.close()
	t := newClient("https", port, key, check)
	if terr := t.health(ctx); terr == nil {
		return t, true, nil
	}
	t.close()
	return nil, false, err
}

// Status is what `rowsafe-agent meilisearch status` reports.
type Status struct {
	Answers bool
	TLS     bool
	Version string
	Login   string // ok, missing or refused
}

// ServerStatus checks the instance on port and Rowsafe's key for it.
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) Status {
	var st Status
	s, lerr := loadServer(env, port)
	local := port
	if lerr == nil {
		local = s.localPort()
	} else {
		s = server{Port: port}
	}
	c, tls, err := probe(ctx, local, "", prodCheck(s))
	if err != nil {
		return st
	}
	defer c.close()
	st.Answers, st.TLS = true, tls
	st.Login = "missing"
	if lerr != nil {
		return st
	}
	v, err := c.withKey(s.Key).version(ctx)
	if err != nil {
		st.Login = "refused"
		return st
	}
	st.Login, st.Version = "ok", v.PkgVersion
	return st
}

// tooOld says why a version is too old for Rowsafe ("" when it isn't):
// 1.12 brought the snapshot format and the task routes the agent uses.
func tooOld(v string) string {
	maj, minor, ok := majorMinor(v)
	if !ok {
		return ""
	}
	if maj < 1 || maj == 1 && minor < 12 {
		return fmt.Sprintf("Meilisearch %s is too old: Rowsafe needs Meilisearch 1.12 or newer", v)
	}
	return ""
}

func majorMinor(v string) (int, int, bool) {
	var maj, minor int
	if _, err := fmt.Sscanf(strings.TrimPrefix(v, "v"), "%d.%d", &maj, &minor); err != nil {
		return 0, 0, false
	}
	return maj, minor, true
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// readable reports whether the agent can read dir (the snapshot folder).
func readable(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
