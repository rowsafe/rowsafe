package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/internal/objstore"
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

// lostSourceErr adds why to an error reading a lost source's backups with
// this server's own settings (a wrong passphrase, no backups where this
// server's storage looks).
func lostSourceErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if errors.Is(err, objstore.ErrBadPassphrase) || errors.Is(err, objstore.ErrNotFound) ||
		strings.Contains(msg, "no backup") || strings.Contains(msg, "decrypt") || strings.Contains(msg, "nosuchkey") {
		return fmt.Errorf("%w (%s)", err, lostSourceHint)
	}
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
	repo, cleanup, err := a.engineForkRepo(ctx, p, tl) // fork_verify.go
	defer cleanup()
	if err != nil {
		return nil, err
	}
	env.Repo = repo
	if p.Box == nil && p.OwnRepo {
		// The source's server is lost: its backups are read with this
		// server's own storage settings (lostSourceRepo).
		res, err := ef.ForkRestore(ctx, env, p, tl)
		return res, lostSourceErr(err)
	}
	if err := env.Repo.Validate(); err != nil {
		return nil, fmt.Errorf("the source's backup settings: %w", err)
	}
	return ef.ForkRestore(ctx, env, p, tl)
}
