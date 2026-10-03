package mysql

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Clones (protocol.FeatureFork): the source as it was at a moment (or a
// Mark), restored privately on the target server from the source's backups
// and loaded into an empty server there (protocol.ForkEmptyServer: the same
// servers that can hold a standby). The control plane then adds it as a new
// database with its own backups.

var _ agent.EngineFork = (*Engine)(nil)

// ForkFacts reads the source's version and size.
func (e *Engine) ForkFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (int, int64, map[string]int, error) {
	s := e.server(env, source)
	conn, err := s.open(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	defer conn.Close()
	f, err := s.readFacts(ctx, conn)
	if err != nil {
		return 0, 0, nil, err
	}
	_, num := numericVersion(f.Version)
	return num / 100, totalSize(ctx, s), map[string]int{settingLowerCase: f.LowerCase, settingVersion: num}, nil
}

// ForkRestore restores the source at p.Target and loads it into the empty
// server on p.Port.
func (e *Engine) ForkRestore(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, log agent.TaskLogger) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	if p.Placement != protocol.ForkEmptyServer || p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("a %s clone goes into an empty %s server (placement %q, port %d)", e.flavor.display(), e.flavor.display(), p.Placement, p.Port)
	}
	if p.Source.Stanza == "" {
		return nil, errors.New("the clone names no source database")
	}
	// The source's backups (its stanza), loaded into the server on p.Port.
	spec := protocol.DatabaseSpec{ID: p.Source.ID, Name: p.Source.Name, Stanza: p.Source.Stanza, Engine: string(e.flavor),
		Port: p.Port, SocketDir: p.SocketDir}
	s := e.server(env, spec)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.checkCloneTarget(ctx, conn, p); err != nil {
		return nil, err
	}
	st, err := openStore(env.Repo, string(e.flavor), p.Source.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	target, err := s.rewindTarget(ctx, st, p.Target)
	if err != nil {
		return nil, err
	}
	if p.SizeBytes > 0 {
		if err := checkSpace(env.Config.RewindDir, p.SizeBytes); err != nil {
			return nil, err
		}
	}
	log.Printf("restoring %s as it was at %s from its backups, next to the %s server on port %d", p.Source.Name, target.describe(), e.flavor.display(), p.Port)
	var loadedSchemas, loadedUsers []string
	// A masked clone is masked on the private restore, before any of it is
	// loaded into the target server.
	var prepare func(context.Context, *sql.DB) error
	var maskReport *protocol.ForkMaskReport
	if p.Masking != nil {
		prepare = func(ctx context.Context, sdb *sql.DB) error {
			r, err := maskFork(ctx, env, sdb, e.flavor.mariadb(), *p.Masking, log)
			maskReport = &r
			return err
		}
	}
	loaded, err := s.loadCopy(ctx, "fork-"+p.ForkID, target, false, func(schemas, users []string) {
		loadedSchemas, loadedUsers = schemas, users
	}, prepare, log)
	if err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if uerr := s.undoStandby(cctx, conn, standbyRecord{Schemas: loadedSchemas, Users: loadedUsers}, log); uerr != nil {
			log.Printf("emptying the server again: %v", uerr)
		}
		return nil, err
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: p.Port, SocketDir: p.SocketDir, Major: p.Major,
		RecoveredTo: loaded.RecoveredTo, DurationMs: time.Since(start).Milliseconds(), Masking: maskReport}
	if dbs, _, err := schemaSizes(ctx, conn); err == nil {
		res.Databases = dbs
		for _, d := range dbs {
			res.SizeBytes += d.SizeBytes
		}
	}
	var logBin int
	if conn.QueryRowContext(ctx, "SELECT @@global.log_bin").Scan(&logBin) == nil && logBin == 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("The binary log is off on this %s server: the clone's restores to any second need it on "+
			"(Rowsafe's plan for its backups turns it on; it takes a restart).", e.flavor.display()))
	}
	when := "its latest backup"
	if loaded.RecoveredTo != nil {
		when = loaded.RecoveredTo.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	res.Summary = fmt.Sprintf("Cloned %s as it was at %s into the %s server on port %d (%s, %s).", p.Source.Name, when, e.flavor.display(), p.Port,
		plural(int64(len(loaded.Schemas)), "database", "databases"), plural(int64(len(loaded.Users)), "login", "logins"))
	log.Printf("%s", res.Summary)
	return res, nil
}

// checkCloneTarget makes sure the server can take the clone.
func (s *server) checkCloneTarget(ctx context.Context, conn *sql.DB, p protocol.ForkRestoreParams) error {
	f, err := s.readFacts(ctx, conn)
	if err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(f.Version), "mariadb") != s.flavor.mariadb() {
		return fmt.Errorf("the server on port %d isn't %s", s.db.Port, s.flavor.display())
	}
	if _, num := numericVersion(f.Version); p.Major > 0 && num/100 != p.Major {
		return fmt.Errorf("the %s server on port %d is version %s; the source runs %d.%d: a clone needs the same version series",
			s.flavor.display(), s.db.Port, f.Version, p.Major/100, p.Major%100)
	}
	if ok, err := standbyRights(ctx, conn); err != nil {
		return err
	} else if !ok {
		return s.errNoStandbyRights()
	}
	schemas, err := userSchemas(ctx, conn)
	if err != nil {
		return err
	}
	if len(schemas) > 0 {
		return fmt.Errorf("the %s server on port %d isn't empty (databases: %s): a clone needs an empty server; nothing was changed",
			s.flavor.display(), s.db.Port, strings.Join(schemas, ", "))
	}
	if st, err := s.readReplicaStatus(ctx, conn); err == nil && st.Configured {
		return fmt.Errorf("the %s server on port %d replicates from %s (it is a standby); nothing was changed", s.flavor.display(), s.db.Port, st.SourceHost)
	}
	if lc, ok := p.Settings[settingLowerCase]; ok && lc != f.LowerCase {
		return fmt.Errorf("lower_case_table_names is %d here and %d on the source; they must be the same", f.LowerCase, lc)
	}
	return nil
}

// maskFork masks a clone's private restore with the source's rules (and
// the suggestions when asked), like a safe copy.
func maskFork(ctx context.Context, env agent.EngineEnv, db *sql.DB, mariadb bool, fm protocol.ForkMasking, log agent.TaskLogger) (protocol.ForkMaskReport, error) {
	key, err := forkMaskKey(env)
	if err != nil {
		return protocol.ForkMaskReport{}, err
	}
	schema, err := readCopySchema(ctx, db)
	if err != nil {
		return protocol.ForkMaskReport{}, err
	}
	var report protocol.MaskingReport
	plan := masking.PlanFork(schema, fm, &report)
	log.Printf("masking the clone: %d tables", len(plan))
	err = maskTables(ctx, db, mariadb, plan, key, log, &report)
	return masking.ForkReport(report, plan), err
}

// forkMaskKey is the host's masking key (a random one outside the agent).
func forkMaskKey(env agent.EngineEnv) ([]byte, error) {
	if env.Copies != nil {
		return env.Copies.MaskKey()
	}
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}
