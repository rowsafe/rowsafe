package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Guard copies: migration previews and safe copies. They are restored like
// Rewind copies (drill.go, rewind_copy.go) into their own directories under
// ROWSAFE_COPIES_DIR and recorded in <state dir>/copies.json, so the agent
// reports them in every heartbeat, deletes them when they expire even if
// the control plane is unreachable, and starts or cleans them up after a
// restart.

// copyIDRE is the shape of copy and preview IDs (short: they become
// directory names inside a Unix socket path).
var copyIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// guardCopyMarker is written into every Guard copy directory first; only
// directories carrying it are ever removed as copies.
const guardCopyMarker = ".rowsafe-guard-copy"

// maxSafeCopies caps safe copies per host whatever the plan says.
const maxSafeCopies = 20

// CopiesConfig configures Guard copies.
type CopiesConfig struct {
	// Dir holds preview and safe copies, one directory each
	// (ROWSAFE_COPIES_DIR, default <state dir>/copies).
	Dir string
	// PortMin and PortMax bound the TCP ports safe copies listen on
	// (ROWSAFE_COPY_PORTS, default 55440-55539).
	PortMin, PortMax int
	// TLSCert and TLSKey are a certificate for safe copies
	// (ROWSAFE_COPY_TLS_CERT, ROWSAFE_COPY_TLS_KEY); without them each copy
	// makes its own self-signed certificate.
	TLSCert, TLSKey string
	// PreviewKeep is how long a preview copy is kept after a preview so the
	// next one starts fast (ROWSAFE_PREVIEW_KEEP, default 1h; 0 deletes it
	// right away).
	PreviewKeep time.Duration
}

func copiesConfigFromEnv(stateDir string) (CopiesConfig, error) {
	c := CopiesConfig{
		Dir:     env("ROWSAFE_COPIES_DIR", filepath.Join(stateDir, "copies")),
		TLSCert: env("ROWSAFE_COPY_TLS_CERT", ""),
		TLSKey:  env("ROWSAFE_COPY_TLS_KEY", ""),
	}
	if !filepath.IsAbs(c.Dir) {
		return c, fmt.Errorf("ROWSAFE_COPIES_DIR must be absolute")
	}
	lo, hi, ok := strings.Cut(env("ROWSAFE_COPY_PORTS", "55440-55539"), "-")
	var err1, err2 error
	c.PortMin, err1 = strconv.Atoi(strings.TrimSpace(lo))
	c.PortMax, err2 = strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || c.PortMin < 1024 || c.PortMax > 65535 || c.PortMax < c.PortMin {
		return c, fmt.Errorf("ROWSAFE_COPY_PORTS must be a range like 55440-55539 (ports 1024 to 65535)")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return c, fmt.Errorf("set both ROWSAFE_COPY_TLS_CERT and ROWSAFE_COPY_TLS_KEY, or neither")
	}
	keep, err := time.ParseDuration(env("ROWSAFE_PREVIEW_KEEP", "1h"))
	if err != nil || keep < 0 || keep > 24*time.Hour {
		return c, fmt.Errorf("ROWSAFE_PREVIEW_KEEP must be a duration between 0 and 24h")
	}
	c.PreviewKeep = keep
	return c, nil
}

// copyRecord is one preview or safe copy.
type copyRecord struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"` // protocol.CopyKind*
	DatabaseID  string                `json:"database_id"`
	Status      string                `json:"status"` // protocol.CopyRestoring, CopyMasking, CopyReady
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
	Database    protocol.DatabaseSpec `json:"database"`
	Dir         string                `json:"dir"`
	Major       int                   `json:"major"`
	Port        int                   `json:"port"`
	Preload     string                `json:"preload,omitempty"`
	// Prepared: the roles a preview or safe copy runs as exist (prepareRoles).
	Prepared bool `json:"prepared,omitempty"`
	// Safe copies: where they listen and the login role.
	Listen string `json:"listen,omitempty"`
	Role   string `json:"role,omitempty"`
	// Preview copies: last used; InUse while a preview runs on it (a copy
	// found in use after a crash may be half-migrated and is removed).
	LastUsed time.Time `json:"last_used,omitzero"`
	InUse    bool      `json:"in_use,omitempty"`
}

func (r *copyRecord) state() protocol.CopyState {
	s := protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: r.Kind, Status: r.Status, SizeBytes: r.SizeBytes,
		CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Listen: r.Listen}
	if r.Kind == protocol.CopyKindSafe {
		s.Port = r.Port
	}
	if !r.Expires.IsZero() {
		e := r.Expires
		s.Expires = &e
	}
	return s
}

// copyStore holds the records, persisted after every change.
type copyStore struct {
	mu   sync.Mutex
	path string
	recs map[string]*copyRecord
	// running cancels a copy's task (a Delete cancels a restore); done is
	// closed when the task has cleaned up.
	running map[string]*runningRewind
	// removing are copies being deleted right now.
	removing map[string]bool
}

func loadCopyStore(path string) (*copyStore, error) {
	s := &copyStore{path: path, recs: map[string]*copyRecord{}, running: map[string]*runningRewind{}, removing: map[string]bool{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var recs []*copyRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return s, fmt.Errorf("reading %s: %w", path, err)
	}
	for _, r := range recs {
		if r != nil && copyIDRE.MatchString(r.ID) {
			s.recs[r.ID] = r
		}
	}
	return s, nil
}

func (s *copyStore) saveLocked() error {
	recs := make([]*copyRecord, 0, len(s.recs))
	for _, r := range s.recs {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b *copyRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

func (s *copyStore) get(id string) (copyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return copyRecord{}, false
	}
	return *r, true
}

func (s *copyStore) put(r copyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[r.ID] = &r
	return s.saveLocked()
}

func (s *copyStore) update(id string, fn func(*copyRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return fmt.Errorf("no copy %s", id)
	}
	fn(r)
	return s.saveLocked()
}

func (s *copyStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[id]; !ok {
		return nil
	}
	delete(s.recs, id)
	return s.saveLocked()
}

func (s *copyStore) all() []copyRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]copyRecord, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b copyRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// claimPreview marks the database's ready preview copy in use and returns
// it; ok is false when there is none (or it is being removed).
func (s *copyStore) claimPreview(databaseID string) (copyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.Kind == protocol.CopyKindPreview && r.DatabaseID == databaseID && r.Status == protocol.CopyReady && !r.InUse && !s.removing[r.ID] {
			r.InUse = true
			if err := s.saveLocked(); err != nil {
				r.InUse = false
				return copyRecord{}, false
			}
			return *r, true
		}
	}
	return copyRecord{}, false
}

// usedPorts are the TCP ports of the recorded safe copies.
func (s *copyStore) usedPorts() map[int]bool {
	out := map[int]bool{}
	for _, r := range s.all() {
		if r.Kind == protocol.CopyKindSafe {
			out[r.Port] = true
		}
	}
	return out
}

func (s *copyStore) startRunning(id string, cancel context.CancelFunc) *runningRewind {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr := &runningRewind{cancel: cancel, done: make(chan struct{})}
	s.running[id] = rr
	return rr
}

func (s *copyStore) finishRunning(id string, rr *runningRewind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[id] == rr {
		delete(s.running, id)
	}
	close(rr.done)
}

// cancelRunning cancels a copy's running task and waits (up to wait) for
// it to clean up. It reports whether one was running.
func (s *copyStore) cancelRunning(id string, wait time.Duration) bool {
	s.mu.Lock()
	rr := s.running[id]
	s.mu.Unlock()
	if rr == nil {
		return false
	}
	rr.cancel()
	select {
	case <-rr.done:
	case <-time.After(wait):
	}
	return true
}

// beginRemove marks a copy as being removed; false if it already is, or is
// in use by a preview.
func (s *copyStore) beginRemove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removing[id] {
		return false
	}
	if r, ok := s.recs[id]; ok && r.InUse {
		return false
	}
	s.removing[id] = true
	return true
}

func (s *copyStore) endRemove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.removing, id)
}

// setExpiries applies Extend from the control plane, clamped to 7 days
// from now. A past expiry never deletes anything (Drop does).
func (s *copyStore) setExpiries(exps []protocol.RewindExpiry, now time.Time) {
	if len(exps) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, e := range exps {
		r, ok := s.recs[e.ID]
		if !ok || r.Kind != protocol.CopyKindSafe || e.Expires.Before(now) {
			continue
		}
		exp := e.Expires.UTC()
		if limit := now.Add(maxCopyLifetime); exp.After(limit) {
			exp = limit
		}
		if !exp.Equal(r.Expires) {
			r.Expires = exp
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}

func (a *Agent) copyStorePath() string { return filepath.Join(a.cfg.StateDir, "copies.json") }

// copyState returns the agent's copy store, loading it on first use.
func (a *Agent) copyState() *copyStore {
	a.copiesOnce.Do(func() {
		st, err := loadCopyStore(a.copyStorePath())
		if err != nil && a.log != nil {
			a.log.Error("reading the copies state; starting empty (copies listed there are not managed until fixed)", "err", err)
		}
		a.copies = st
	})
	return a.copies
}

// copiesReport is what the heartbeat says about copies.
func (a *Agent) copiesReport() *protocol.CopiesReport {
	r := &protocol.CopiesReport{OwnTLSCert: a.cfg.Copies.TLSCert != ""}
	if !a.cfg.Sidecar() {
		r.PortMin, r.PortMax = a.cfg.Copies.PortMin, a.cfg.Copies.PortMax
	}
	for _, c := range a.copyState().all() {
		r.Copies = append(r.Copies, c.state())
	}
	if !a.cfg.Sidecar() {
		r.Addresses = hostAddresses()
	}
	return r
}

// onCopiesUpdate applies the heartbeat response's copy instructions.
func (a *Agent) onCopiesUpdate(ctx context.Context, u *protocol.CopiesUpdate) {
	if u == nil {
		return
	}
	st := a.copyState()
	st.setExpiries(u.Expires, time.Now())
	for _, id := range u.Drop {
		if !copyIDRE.MatchString(id) {
			continue
		}
		if _, ok := st.get(id); !ok {
			continue
		}
		go a.dropCopy(context.WithoutCancel(ctx), id, "deleted from Rowsafe")
	}
}

// dropCopy deletes a copy now: a running task on it is cancelled first.
func (a *Agent) dropCopy(ctx context.Context, id, why string) {
	st := a.copyState()
	r, ok := st.get(id)
	if !ok {
		return
	}
	if r.Status != protocol.CopyReady && st.cancelRunning(id, 3*time.Minute) {
		a.log.Info("stopped a copy being prepared", "copy_id", id, "why", why)
		return // the task removes what it made
	}
	if r.InUse {
		st.cancelRunning(id, 3*time.Minute)
	}
	if !st.beginRemove(id) {
		return
	}
	defer st.endRemove(id)
	if r, ok = st.get(id); !ok {
		return
	}
	freed, err := a.removeGuardCopy(r)
	if err != nil {
		a.log.Error("deleting a copy failed", "copy_id", id, "err", err)
		return
	}
	a.log.Info("deleted a copy", "copy_id", id, "kind", r.Kind, "why", why, "freed", humanBytes(freed))
	_ = ctx
}

// guardCopyDirOK checks that dir is the directory of copy id: under
// ROWSAFE_COPIES_DIR, a real directory, carrying the marker.
func (a *Agent) guardCopyDirOK(id, dir string) error {
	want, err := scratchDir(a.cfg.Copies.Dir, id, "/nonexistent-production-data-dir", "copy")
	if err != nil {
		return err
	}
	if filepath.Clean(dir) != want {
		return fmt.Errorf("refusing to remove %s: it is not the copy directory %s", dir, want)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to remove %s: not a directory", dir)
	}
	if _, err := os.Lstat(filepath.Join(dir, guardCopyMarker)); err != nil {
		return fmt.Errorf("refusing to remove %s: it has no copy marker", dir)
	}
	return nil
}

// removeGuardCopy stops a copy's PostgreSQL, deletes its directory and
// forgets it.
func (a *Agent) removeGuardCopy(r copyRecord) (int64, error) {
	err := a.guardCopyDirOK(r.ID, r.Dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		pgCtl := "pg_ctl"
		if r.Major > 0 {
			pgCtl = a.cfg.pgBin(r.Major, "pg_ctl")
		}
		if err := a.removeDrill(r.Dir, pgCtl); err != nil {
			return 0, err
		}
	}
	return r.SizeBytes, a.copyState().remove(r.ID)
}

// copiesHousekeeping deletes expired copies every minute. It needs nothing
// from the control plane.
func (a *Agent) copiesHousekeeping(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		a.expireCopies(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) expireCopies(now time.Time) {
	st := a.copyState()
	for _, r := range st.all() {
		if r.Status != protocol.CopyReady || r.InUse || r.Expires.IsZero() || now.Before(r.Expires) {
			continue
		}
		if !st.beginRemove(r.ID) {
			continue
		}
		freed, err := a.removeGuardCopy(r)
		st.endRemove(r.ID)
		if err != nil {
			a.log.Error("removing an expired copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		a.log.Info("removed an expired copy", "copy_id", r.ID, "kind", r.Kind, "database_id", r.DatabaseID, "freed", humanBytes(freed))
	}
}

// recoverCopies runs once at agent start: copies whose preparation was
// interrupted (or a preview copy a preview was using) are removed, safe
// copies are started again, and leftovers nobody knows are removed.
func (a *Agent) recoverCopies(ctx context.Context) {
	st := a.copyState()
	known := map[string]bool{}
	for _, r := range st.all() {
		known[r.ID] = true
		switch {
		case r.Status != protocol.CopyReady || r.InUse:
			if _, err := a.removeGuardCopy(r); err != nil {
				a.log.Error("removing an interrupted copy failed", "copy_id", r.ID, "err", err)
			} else {
				a.log.Warn("removed a copy whose preparation or preview was interrupted by an agent restart", "copy_id", r.ID)
			}
		case !r.Expires.IsZero() && time.Now().After(r.Expires):
			// expireCopies removes it.
		default:
			go func() {
				if err := a.startGuardCopy(ctx, r); err != nil {
					a.log.Error("starting a copy again after an agent restart failed; it stays until it expires or is deleted",
						"copy_id", r.ID, "err", err)
				} else {
					a.log.Info("started a copy again after an agent restart", "copy_id", r.ID)
				}
			}()
		}
	}
	entries, err := os.ReadDir(a.cfg.Copies.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !copyIDRE.MatchString(e.Name()) || known[e.Name()] {
			continue
		}
		dir := filepath.Join(a.cfg.Copies.Dir, e.Name())
		if err := a.guardCopyDirOK(e.Name(), dir); err != nil {
			a.log.Warn("leaving an unrecognised directory in the copies directory alone", "dir", dir)
			continue
		}
		pgCtl := "pg_ctl"
		if v, err := os.ReadFile(filepath.Join(dir, "data", "PG_VERSION")); err == nil {
			if major, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil {
				pgCtl = a.cfg.pgBin(major, "pg_ctl")
			}
		}
		if err := a.removeDrill(dir, pgCtl); err != nil {
			a.log.Error("removing a leftover copy failed", "dir", dir, "err", err)
		} else {
			a.log.Warn("removed a leftover copy", "dir", dir)
		}
	}
}

// hostAddresses are the server's own unicast addresses (no loopback or
// link-local), private ones first.
func hostAddresses() []protocol.HostAddress {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []protocol.HostAddress
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			pfx, err := netip.ParsePrefix(ad.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, protocol.HostAddress{IP: ip.String(), Interface: ifc.Name, Private: privateAddr(ip)})
		}
	}
	slices.SortStableFunc(out, func(x, y protocol.HostAddress) int {
		switch {
		case x.Private == y.Private:
			return 0
		case x.Private:
			return -1
		}
		return 1
	})
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// privateAddr: RFC 1918, IPv6 ULA, or CGNAT (Tailscale and friends).
func privateAddr(ip netip.Addr) bool {
	return ip.IsPrivate() || cgnat.Contains(ip)
}
