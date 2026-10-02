package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for MySQL, MariaDB, MongoDB and ClickHouse: the
// engine reads its own settings (EngineSecurityChecker) and runs the few
// fixes that are safe from a click; the agent adds what every engine
// shares (this server's addresses, Docker) and sends the report with
// PostgreSQL's.

// EngineSecurityChecker is optionally implemented by an engine with the
// security check.
type EngineSecurityChecker interface {
	// SecurityReport reads the server's security settings: listening
	// addresses, TLS, users and the kind of their passwords (never a hash),
	// the clients connected over the network and EngineSecurity. The agent
	// fills DatabaseID, CollectedAt, Engine, HostAddresses and Docker.
	SecurityReport(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (protocol.SecurityReport, error)
	// SecurityFix runs one fix (protocol.Sec*) the engine supports.
	SecurityFix(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.SecurityFixParams, log TaskLogger) (*protocol.SecurityFixResult, error)
}

// engineSecurity is db's engine's security checker (nil when it has none).
func engineSecurity(db protocol.DatabaseSpec) EngineSecurityChecker {
	c, _ := engineFor(protocol.NormalizeEngine(db.Engine)).(EngineSecurityChecker)
	return c
}

// scanEngineSecurity reads a non-PostgreSQL database's security settings.
func (a *Agent) scanEngineSecurity(ctx context.Context, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	name := protocol.NormalizeEngine(db.Engine)
	c := engineSecurity(db)
	if c == nil {
		return protocol.SecurityReport{Engine: name}, fmt.Errorf("this agent can't check the security of %s yet; update the agent (this is %s)",
			protocol.EngineDisplayName(name), Version)
	}
	rep, err := c.SecurityReport(ctx, a.engineEnv(name), db)
	rep.Engine = name
	rep.Docker = a.cfg.Sidecar()
	if rep.Port == 0 {
		rep.Port = db.Port
	}
	if !a.cfg.Sidecar() {
		rep.HostAddresses = nil
		for _, ip := range hostIPs() {
			rep.HostAddresses = append(rep.HostAddresses, ip.String())
		}
	}
	return rep, err
}

// runEngineSecurityTask runs a security_scan or security_fix task for a
// non-PostgreSQL database.
func (a *Agent) runEngineSecurityTask(ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	if task.Type == protocol.TaskSecurityScan {
		rep := a.securityReport(ctx, db)
		if rep.Error != "" {
			return &rep, errors.New(rep.Error)
		}
		tl.Printf("security check: %d users, %d clients connected over the network", len(rep.Roles), len(rep.Clients))
		return &rep, nil
	}
	var p protocol.SecurityFixParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid security_fix params: %w", err)
	}
	start := time.Now()
	c := engineSecurity(db)
	if c == nil {
		return nil, unsupportedEngine(db.Engine)
	}
	name := protocol.NormalizeEngine(db.Engine)
	res, err := c.SecurityFix(ctx, a.engineEnv(name), db, p, tl)
	if res == nil {
		res = &protocol.SecurityFixResult{Action: p.Action}
	}
	res.DurationMs = time.Since(start).Milliseconds()
	rep := a.securityReport(context.WithoutCancel(ctx), db)
	res.Report = &rep
	if err != nil {
		err = sentence(err)
		tl.Printf("failed: %v", err)
		return res, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}
