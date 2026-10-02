package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// EngineFork is optionally implemented by an engine whose databases can be
// cloned (protocol.FeatureFork). The agent keeps the sealed handoff of the
// source's bucket settings; the engine restores.
type EngineFork interface {
	// ForkFacts runs on the source's server (fork_prepare): what the target
	// checks before it restores (ForkPrepareResult.Major, SizeBytes,
	// Settings).
	ForkFacts(ctx context.Context, env EngineEnv, source protocol.DatabaseSpec) (major int, sizeBytes int64, settings map[string]int, err error)
	// ForkRestore runs on the target server: it restores p.Source as it was
	// at p.Target into the place p names. env.Repo reads the source's
	// backups.
	ForkRestore(ctx context.Context, env EngineEnv, p protocol.ForkRestoreParams, log TaskLogger) (*protocol.ForkRestoreResult, error)
}

func engineFork(engine string) EngineFork {
	e := engineFor(protocol.NormalizeEngine(engine))
	if e == nil {
		return nil
	}
	f, _ := e.(EngineFork)
	return f
}

// engineForkFacts fills a fork_prepare result for another engine.
func (a *Agent) engineForkFacts(ctx context.Context, source protocol.DatabaseSpec, res *protocol.ForkPrepareResult) error {
	ef := engineFork(source.Engine)
	if ef == nil {
		return fmt.Errorf("clones of %s databases aren't available with this agent (%s)", protocol.EngineDisplayName(source.Engine), Version)
	}
	var err error
	res.Major, res.SizeBytes, res.Settings, err = ef.ForkFacts(ctx, a.engineEnvFor(source), source)
	return err
}

// engineForkRestore restores a fork of a database of another engine.
func (a *Agent) engineForkRestore(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (*protocol.ForkRestoreResult, error) {
	ef := engineFork(p.Source.Engine)
	if ef == nil {
		return nil, fmt.Errorf("clones of %s databases aren't available with this agent (%s)", protocol.EngineDisplayName(p.Source.Engine), Version)
	}
	if !forkIDRE.MatchString(p.ForkID) {
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	}
	if a.cfg.Sidecar() {
		return nil, errors.New("clones need the agent installed on the server itself; databases in Docker aren't supported yet")
	}
	env := a.engineEnv(protocol.NormalizeEngine(p.Source.Engine))
	if p.Box == nil {
		env.Repo = a.repoFor(p.Source)
		tl.Printf("the source %s runs on this server: its backups are read with this server's own settings; nothing leaves the server",
			cmp.Or(p.Source.Name, p.Source.Stanza))
	} else {
		rt := a.sb()
		if rt.key == nil {
			return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
		}
		if err := a.peerAllowed(p.Box.SenderKey, "the source's server"); err != nil {
			return nil, err
		}
		plain, err := handoff.Open(rt.key, *p.Box, protocol.HandoffPurposeFork, protocol.ForkHandoffContext(p.Source.ID, p.ForkID), p.SenderKey)
		if err != nil {
			return nil, fmt.Errorf("opening the source server's sealed bucket settings: %w", err)
		}
		var sec protocol.ForkSecrets
		err = json.Unmarshal(plain, &sec)
		clear(plain)
		if err != nil {
			return nil, fmt.Errorf("reading the source server's handoff: %w", err)
		}
		r := sec.Repo
		env.Repo = pgbackrest.Repo{Endpoint: r.Endpoint, Bucket: r.Bucket, Region: r.Region, Key: r.Key, KeySecret: r.KeySecret,
			CipherPass: r.CipherPass, PathPrefix: r.PathPrefix, URIStyle: r.URIStyle, Port: r.Port, SkipTLSVerify: r.SkipTLSVerify}
		if r.CAPEM != "" {
			if err := os.MkdirAll(a.standbyDir(), 0o700); err != nil {
				return nil, err
			}
			ca := filepath.Join(a.standbyDir(), "fork-"+safeFileID(p.ForkID)+"-ca.pem")
			if err := writeFileAtomic(ca, []byte(r.CAPEM), 0o600); err != nil {
				return nil, err
			}
			defer os.Remove(ca)
			env.Repo.CAFile = ca
		}
		tl.Printf("opened the source server's sealed bucket settings (read access to %s's backups)", cmp.Or(p.Source.Name, p.Source.Stanza))
	}
	if err := env.Repo.Validate(); err != nil {
		return nil, fmt.Errorf("the source's backup settings: %w", err)
	}
	return ef.ForkRestore(ctx, env, p, tl)
}
