package agent

import (
	"context"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies of other engines: an engine with safe copies implements
// EngineSafeCopies; the agent reports its copies with every heartbeat next
// to PostgreSQL's and hands it the control plane's instructions (delete,
// extend, new password). The engines share the agent's copy helpers
// (EngineEnv.Copies): the server's addresses, the allowed-address rules,
// free ports, the TLS certificate and the masking key, so every engine's
// copies follow the same rules.

// EngineSafeCopies is optionally implemented by an engine with safe
// copies.
type EngineSafeCopies interface {
	// CopyStates are the engine's copies (heartbeat).
	CopyStates(env EngineEnv) []protocol.CopyState
	// CopyPorts are the TCP ports its copies use.
	CopyPorts(env EngineEnv) []int
	// DropCopy deletes copy id now; false when it isn't the engine's.
	DropCopy(ctx context.Context, env EngineEnv, id string) bool
	// SetCopyExpiries moves expiry times (Extend).
	SetCopyExpiries(env EngineEnv, exp []protocol.RewindExpiry)
	// SetCopyPassword sets a new password verifier on a ready copy; false
	// when the copy isn't the engine's.
	SetCopyPassword(ctx context.Context, env EngineEnv, p protocol.CopyPassword) bool
}

// CopyTools are the agent's safe copy helpers for engines.
type CopyTools struct {
	cfg  Config
	used func() map[int]bool
}

// NewCopyTools returns copy helpers for cfg (tests; the agent sets
// EngineEnv.Copies itself).
func NewCopyTools(cfg Config) *CopyTools { return &CopyTools{cfg: cfg} }

// MaxSafeCopies is the most safe copies one server holds.
const MaxSafeCopies = maxSafeCopies

// Addresses are the server's own addresses a copy may listen on.
func (t *CopyTools) Addresses() []protocol.HostAddress { return copyAddresses() }

// ResolveListen checks a listen choice ("*" or one of Addresses).
func (t *CopyTools) ResolveListen(listen string) ([]string, error) {
	return resolveListen(listen, copyAddresses())
}

// AllowRules parses the allowed addresses (IPs or CIDRs).
func (t *CopyTools) AllowRules(allow []string) ([]netip.Prefix, error) { return allowRules(allow) }

// FreePort picks a port in ROWSAFE_COPY_PORTS that no copy uses and
// nothing listens on (want first, when it is in the range).
func (t *CopyTools) FreePort(listen []string, want int) (int, error) {
	used := map[int]bool{}
	if t.used != nil {
		used = t.used()
	}
	return freeCopyPortIn(t.cfg.Copies, used, listen, want)
}

// Cert writes the copy's TLS certificate and key into dir (server.crt,
// server.key): the host's own when configured, else a new self-signed
// one. It returns the certificate (PEM) and whether it is the host's.
func (t *CopyTools) Cert(dir string, hosts []string) (string, bool, error) {
	return (&Agent{cfg: t.cfg}).copyCert(dir, hosts)
}

// Expiry is a copy's expiry time for a requested one (default 24 hours,
// at most 7 days).
func (t *CopyTools) Expiry(requested time.Time) time.Time {
	return copyExpiry(requested, time.Now().UTC())
}

// MaskKey is the host's masking key (the same email is masked the same
// way in every copy of every engine).
func (t *CopyTools) MaskKey() ([]byte, error) {
	path := filepath.Join(t.cfg.StateDir, "masking.key")
	if key, err := os.ReadFile(path); err == nil && len(key) >= 32 {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return key, writeFileAtomic(path, key, 0o600)
}

// copyTools are the helpers the agent gives its engines: ports used by
// PostgreSQL's copies and every engine's count.
func (a *Agent) copyTools() *CopyTools {
	return &CopyTools{cfg: a.cfg, used: func() map[int]bool {
		used := a.copyState().usedPorts()
		for _, e := range registeredEngines() {
			if c, ok := e.(EngineSafeCopies); ok {
				for _, p := range c.CopyPorts(engineEnv(a.cfg, a.runner, a.log, e.Name())) {
					used[p] = true
				}
			}
		}
		return used
	}}
}

// engineCopyStates are the engines' safe copies (heartbeat).
func (a *Agent) engineCopyStates() []protocol.CopyState {
	var out []protocol.CopyState
	for _, e := range registeredEngines() {
		if c, ok := e.(EngineSafeCopies); ok {
			out = append(out, c.CopyStates(a.engineEnv(e.Name()))...)
		}
	}
	return out
}

// engineCopiesUpdate hands the heartbeat's copy instructions the agent's
// own store doesn't know to the engines.
func (a *Agent) engineCopiesUpdate(ctx context.Context, u *protocol.CopiesUpdate) {
	for _, e := range registeredEngines() {
		c, ok := e.(EngineSafeCopies)
		if !ok {
			continue
		}
		env := a.engineEnv(e.Name())
		if len(u.Expires) > 0 {
			c.SetCopyExpiries(env, u.Expires)
		}
		for _, id := range u.Drop {
			if _, mine := a.copyState().get(id); !mine && copyIDRE.MatchString(id) {
				go c.DropCopy(context.WithoutCancel(ctx), env, id)
			}
		}
		for _, p := range u.Passwords {
			if _, mine := a.copyState().get(p.ID); !mine && copyIDRE.MatchString(p.ID) {
				go c.SetCopyPassword(context.WithoutCancel(ctx), env, p)
			}
		}
	}
}
