package mysql

import (
	"context"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The agent's side of safe copies (agent.EngineSafeCopies): states for the
// heartbeat, and the control plane's instructions.

var _ agent.EngineSafeCopies = (*Engine)(nil)

// safeStates are the store's safe copies.
func (cs *copyStore) safeStates() []protocol.CopyState {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	var out []protocol.CopyState
	for _, r := range cs.recs {
		if r.Kind != protocol.CopyKindSafe {
			continue
		}
		exp := r.Expires
		out = append(out, protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.CopyKindSafe, Status: r.Status,
			SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, Expires: &exp, RecoveredTo: r.RecoveredTo, Listen: r.Listen,
			Port: r.Port, PasswordVersion: r.PasswordVersion})
	}
	slices.SortFunc(out, func(a, b protocol.CopyState) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// CopyStates reports the safe copies; it also deletes expired ones and
// starts copies again after the agent restarted (housekeeping).
func (e *Engine) CopyStates(env agent.EngineEnv) []protocol.CopyState {
	cs := rewinds(env)
	cs.housekeeping(env)
	return cs.safeStates()
}

// CopyPorts are the ports the safe copies listen on.
func (e *Engine) CopyPorts(env agent.EngineEnv) []int {
	var out []int
	for _, s := range rewinds(env).safeStates() {
		out = append(out, s.Port)
	}
	return out
}

// DropCopy deletes a safe copy (cancelling its preparation).
func (e *Engine) DropCopy(ctx context.Context, env agent.EngineEnv, id string) bool {
	cs := rewinds(env)
	r, ok := cs.get(id)
	if !ok || r.Kind != protocol.CopyKindSafe {
		return false
	}
	cs.mu.Lock()
	cancel, restoring := cs.restoring[id]
	cs.mu.Unlock()
	if restoring {
		cancel() // the task removes what it made
		return true
	}
	freed := removeCopy(r)
	cs.delete(id)
	env.Log.Info("deleted a safe copy", "copy_id", id, "freed", humanBytes(freed))
	return true
}

// SetCopyExpiries applies Extend.
func (e *Engine) SetCopyExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	var mine []protocol.RewindExpiry
	cs := rewinds(env)
	for _, x := range exp {
		if r, ok := cs.get(x.ID); ok && r.Kind == protocol.CopyKindSafe {
			mine = append(mine, x)
		}
	}
	cs.setExpiries(mine)
}

// SetCopyPassword sets a new password on a ready safe copy's login (on
// every allowed host) and unlocks it.
func (e *Engine) SetCopyPassword(ctx context.Context, env agent.EngineEnv, p protocol.CopyPassword) bool {
	cs := rewinds(env)
	r, ok := cs.get(p.ID)
	if !ok || r.Kind != protocol.CopyKindSafe {
		return false
	}
	if r.Status != protocol.CopyReady || p.Version <= r.PasswordVersion || !copyRoleRE.MatchString(r.Role) {
		return true
	}
	if !protocol.ValidCopyVerifier(r.Engine, p.Verifier) {
		env.Log.Warn("ignoring an invalid password for a copy", "copy_id", p.ID)
		return true
	}
	s := &server{flavor: flavor(r.Engine)}
	db, err := r.scratch().connect(ctx)
	if err != nil {
		env.Log.Error("setting a copy's password: the copy is not answering", "copy_id", p.ID, "err", err)
		return true
	}
	defer db.Close()
	for _, h := range r.Hosts {
		if _, err := db.ExecContext(ctx, "ALTER USER "+quoteAccount(r.Role, h)+" "+s.identified(p.Verifier)+" ACCOUNT UNLOCK"); err != nil {
			env.Log.Error("setting a copy's password failed", "copy_id", p.ID, "err", err)
			return true
		}
	}
	cs.mu.Lock()
	if rec, ok := cs.recs[p.ID]; ok {
		rec.PasswordVersion = max(rec.PasswordVersion, p.Version)
		_ = cs.saveLocked()
	}
	cs.mu.Unlock()
	env.Log.Info("set a new password on a safe copy", "copy_id", p.ID, "version", p.Version)
	return true
}
