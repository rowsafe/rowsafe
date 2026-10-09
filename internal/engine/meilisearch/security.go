package meilisearch

import (
	"context"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Security for Meilisearch: who can reach it (its address, TLS), whether
// it asks for a key at all (a master key), and its API keys (users, with
// those that can do everything marked as administrators). The firewall fix
// is the agent's, as for every engine.

// SecurityReport reads the instance's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	es := &protocol.EngineSecurity{}
	rep := protocol.SecurityReport{Port: db.Port, EngineSecurity: es}
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return rep, err
	}
	defer c.close()
	v, err := c.version(ctx)
	if err != nil {
		return rep, err
	}
	rep.ServerVersion, rep.VersionNum = v.PkgVersion, versionNum(v.PkgVersion)
	rep.ListenAddresses = s.Listen
	if rep.ListenAddresses == "" {
		rep.ListenAddresses = "unknown"
		rep.Notes = append(rep.Notes, "Rowsafe doesn't know which addresses Meilisearch listens on: run the Rowsafe installer on the server again.")
	}
	// TLS: Rowsafe's TLS front (servers Rowsafe creates) or Meilisearch's own.
	rep.SSL = s.LocalPort > 0 || s.TLS
	es.RequireTLS = rep.SSL
	// Without a master key Meilisearch answers anyone, with no key at all.
	open := newClient(map[bool]string{true: "https", false: "http"}[s.TLS && s.LocalPort == 0], s.localPort(), "", prodCheck(s))
	defer open.close()
	if _, err := open.version(ctx); err == nil {
		es.AuthDisabled = true
	} else if !isAuthError(err) {
		rep.Notes = append(rep.Notes, "Rowsafe couldn't check whether Meilisearch asks for a key: "+firstLine(err.Error()))
	}
	if !es.AuthDisabled && s.Key != "" {
		keys, err := c.keys(ctx)
		if err != nil {
			rep.Notes = append(rep.Notes, "API keys could not be read: "+firstLine(err.Error()))
		}
		now := time.Now()
		for _, k := range keys {
			if len(rep.Roles) >= 200 {
				break
			}
			canLogin := k.ExpiresAt == nil || k.ExpiresAt.After(now)
			rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: keyLabel(k), Superuser: isAdminKey(k),
				CanLogin: canLogin, Password: protocol.PasswordSet, ValidUntil: k.ExpiresAt})
		}
	}
	return rep, nil
}

// SecurityFix: Meilisearch has no fix of its own here (the firewall is the
// agent's; a master key or TLS changes how apps connect, so a person sets
// them).
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SecurityFixParams, tl agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	return nil, fmt.Errorf("%s has no %q fix", display, p.Action)
}

// keyLabel is how a key is named in lists: its name, else the start of
// its uid.
func keyLabel(k apiKey) string {
	if n := k.name(); n != "" {
		return n
	}
	if len(k.UID) > 8 {
		return k.UID[:8]
	}
	return k.UID
}
