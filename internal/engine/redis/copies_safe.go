package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies (Guard) for Redis and Valkey: the newest point in the bucket
// restored into a temporary server like a Rewind copy (Unix socket only, in
// a private directory), masked there, or emptied to its structure, then
// opened to the allowed addresses through the agent: Redis has no
// per-address access rules, so the agent listens on the chosen address and
// port itself, lets in only connections from the allowed addresses,
// speaks TLS to them, and passes each one to the copy's socket. On the copy,
// the default user is off and the only login is the copy's, with the
// SHA-256 of the password the requester made; it may run everything but
// administration commands (no CONFIG, MODULE, DEBUG, SAVE, REPLICAOF,
// MIGRATE...). Production's users aren't in a copy (they live outside the
// data).

var copyRoleRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// copyUserRules are the copy login's rights.
const copyUserRules = "~* &* +@all -@admin -migrate -debug"

// copyAgentUser is the agent's own login on its copies (the default user
// is off once a copy opens).
const copyAgentUser = "rowsafe-copy-agent"

var _ agent.EngineSafeCopies = (*Engine)(nil)

// safeRecord is a safe copy (<state>/safe.json).
type safeRecord struct {
	ID              string     `json:"id"`
	DatabaseID      string     `json:"database_id"`
	Dir             string     `json:"dir"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	Expires         time.Time  `json:"expires"`
	RecoveredTo     *time.Time `json:"recovered_to,omitempty"`
	Listen          []string   `json:"listen"`
	Port            int        `json:"port"`
	AllowFrom       []string   `json:"allow_from"`
	Role            string     `json:"role"`
	Verifier        string     `json:"verifier,omitempty"` // "#<sha256>": what ACL SETUSER takes
	PasswordVersion int        `json:"password_version,omitempty"`
	AgentPassword   string     `json:"agent_password"`
	SizeBytes       int64      `json:"size_bytes"`
	Structure       bool       `json:"structure,omitempty"`
}

type safeStore struct {
	mu      sync.Mutex
	path    string
	records map[string]safeRecord
	running map[string]context.CancelFunc
	proxies map[string]*copyProxy
}

var (
	safeStoresMu sync.Mutex
	safeStores   = map[string]*safeStore{}
)

func safeState(env agent.EngineEnv) *safeStore {
	p := filepath.Join(env.StateDir, "safe.json")
	safeStoresMu.Lock()
	defer safeStoresMu.Unlock()
	if s := safeStores[p]; s != nil {
		return s
	}
	s := &safeStore{path: p, records: map[string]safeRecord{}, running: map[string]context.CancelFunc{}, proxies: map[string]*copyProxy{}}
	var list []safeRecord
	if err := loadJSONFile(p, &list); err != nil && !notExist(err) {
		env.Log.Error("reading the safe copies' state; starting empty", "err", err)
	}
	for _, r := range list {
		s.records[r.ID] = r
	}
	safeStores[p] = s
	return s
}

func (s *safeStore) saveLocked() error {
	list := make([]safeRecord, 0, len(s.records))
	for _, r := range s.records {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b safeRecord) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(s.path, list)
}

func (s *safeStore) put(r safeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.ID] = r
	return s.saveLocked()
}

func (s *safeStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return s.saveLocked()
}

func (s *safeStore) get(id string) (safeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	return r, ok
}

func (s *safeStore) all() []safeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]safeRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b safeRecord) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func safeRoot(env agent.EngineEnv, engine string) string {
	return filepath.Join(env.Config.RewindDir, engine+"-safe")
}

func (e *Engine) safeCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SafeCopyParams, tl agent.TaskLogger) (*protocol.SafeCopyResult, error) {
	tools := env.Copies
	switch {
	case tools == nil:
		return nil, errors.New("safe copies need the Rowsafe agent")
	case env.Config.Sidecar() || inDocker():
		return nil, errors.New("safe copies need the Rowsafe agent installed on the database server itself: a copy made by the Docker sidecar can't be reached from outside its container")
	case !idRE.MatchString(p.CopyID) || len(p.CopyID) > 32:
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	case !copyRoleRE.MatchString(p.Access.Role) || p.Access.Role == "default" || p.Access.Role == LoginUser || p.Access.Role == copyAgentUser:
		return nil, fmt.Errorf("invalid login name %q", p.Access.Role)
	case p.Access.PasswordVerifier != "" && !protocol.ValidCopyVerifier(e.name, p.Access.PasswordVerifier):
		return nil, fmt.Errorf("the password must come as %s", protocol.CopyVerifierForm(e.name))
	case p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone && p.Masking.Mode != protocol.MaskingStructure:
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	listen, err := tools.ResolveListen(p.Access.Listen)
	if err != nil {
		return nil, err
	}
	allow, err := tools.AllowRules(p.Access.AllowFrom)
	if err != nil {
		return nil, err
	}
	ss := safeState(env)
	if n := len(ss.all()); n >= agent.MaxSafeCopies {
		return nil, fmt.Errorf("this server already has %d safe copies, the most it can hold; delete one first", n)
	}
	if _, ok := ss.get(p.CopyID); ok {
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	bind := listen
	if listen[0] == "*" {
		bind = []string{"0.0.0.0"}
	}
	port, err := tools.FreePort(bind, p.Access.Port)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var executable string
	if c, err := connectDB(ctx, env, db); err == nil {
		if in, err := inspect(ctx, c); err == nil {
			executable = in.Executable
		}
		c.Close()
	}
	agentPass, err := randomPassword()
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	s, err := newScratch(env, safeRoot(env, e.name), p.CopyID)
	if err != nil {
		return nil, err
	}
	var allowS []string
	for _, a := range allow {
		allowS = append(allowS, a.String())
	}
	rec := safeRecord{ID: p.CopyID, DatabaseID: db.ID, Dir: s.Dir, Status: protocol.CopyRestoring, CreatedAt: time.Now().UTC(),
		Expires: tools.Expiry(p.Expires), Listen: bind, Port: port, AllowFrom: allowS, Role: p.Access.Role,
		Verifier: p.Access.PasswordVerifier, AgentPassword: agentPass, Structure: p.Masking.Mode == protocol.MaskingStructure}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ss.mu.Lock()
	ss.running[rec.ID] = cancel
	ss.mu.Unlock()
	defer func() {
		ss.mu.Lock()
		delete(ss.running, rec.ID)
		ss.mu.Unlock()
	}()
	if err := ss.put(rec); err != nil {
		_, _ = s.remove()
		return nil, err
	}
	fail := func(err error) (*protocol.SafeCopyResult, error) {
		e.stopProxy(env, rec.ID)
		_, _ = s.remove()
		_ = ss.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}
	tl.Printf("restoring the newest point in your bucket into a temporary %s server (Unix socket only, no network)", e.display())
	out, c, err := e.restoreInto(cctx, env, r, restoreTarget{Latest: true}, &s, executable, tl)
	if err != nil {
		return fail(err)
	}
	rt := out.RecoveredTo
	rec.RecoveredTo = &rt
	rec.Status = protocol.CopyMasking
	_ = ss.put(rec)
	report := protocol.MaskingReport{Mode: p.Masking.Mode, Strategies: map[string]int{}}
	started := time.Now()
	if p.Masking.Mode != protocol.MaskingNone {
		key, err := tools.MaskKey()
		if err != nil {
			c.Close()
			return fail(err)
		}
		km := newKeyMasker(key, p.Masking.Rules, true, &report)
		if rec.Structure {
			tl.Printf("keeping every key's type and time to live, replacing every value with a placeholder")
		} else {
			tl.Printf("masking the copy: by your rules, the names of keys and fields, and values that look like emails, phone numbers or tokens")
		}
		st, err := maskServer(cctx, c, km, rec.Structure, tl)
		if err != nil {
			c.Close()
			return fail(fmt.Errorf("masking the copy: %w", err))
		}
		report.Skipped = append(report.Skipped, maskNotes(st, rec.Structure)...)
		if rec.Structure {
			report.Rows, report.Tables = st.Keys, 0
		}
	}
	report.DurationMs = time.Since(started).Milliseconds()
	c.timeout = time.Hour
	if _, err := c.do(cctx, "SAVE"); err != nil {
		c.Close()
		return fail(fmt.Errorf("saving the copy: %w", err))
	}
	m, _ := c.info(cctx, "keyspace")
	c.Close()

	// Open it.
	cert, own, err := tools.Cert(s.Dir, append([]string{"127.0.0.1", "localhost"}, listen...))
	if err != nil {
		return fail(err)
	}
	if err := e.lockCopy(cctx, env, rec); err != nil {
		return fail(err)
	}
	if err := e.startProxy(env, rec); err != nil {
		return fail(fmt.Errorf("opening the copy on port %d: %w", port, err))
	}
	if p.Access.PasswordVerifier != "" {
		rec.PasswordVersion = 1
	}
	rec.SizeBytes = dirSize(s.Dir)
	rec.Status = protocol.CopyReady
	if err := ss.put(rec); err != nil {
		return fail(err)
	}
	var names []string
	for n := range infoFrom(m).Keyspace {
		names = append(names, "db"+strconv.Itoa(n))
	}
	slices.Sort(names)
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Listen: strings.Join(listen, ","), Port: port, Role: rec.Role, Databases: names,
		SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo, Expires: rec.Expires, TLSCert: cert, TLSOwnCert: own, Masking: report}
	what := fmt.Sprintf("%s values masked under %s", commas(report.Rows), plural(int64(report.Columns), "pattern and field", "patterns and fields"))
	switch p.Masking.Mode {
	case protocol.MaskingStructure:
		what = fmt.Sprintf("structure only: %s keys with their types and times to live, every value a placeholder", commas(report.Rows))
	case protocol.MaskingNone:
		what = "not masked (real data)"
	}
	res.Summary = fmt.Sprintf("The safe copy is ready: %s, data as of %s, %s. It listens on port %d (TLS) for %s and is deleted by itself at %s.",
		humanBytes(rec.SizeBytes), rt.UTC().Format("2006-01-02 15:04:05 UTC"), what, port, strings.Join(p.Access.AllowFrom, ", "),
		rec.Expires.Format("15:04 UTC on 2006-01-02"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// lockCopy turns the default user off and leaves two logins on the copy:
// the agent's and the copy's (without a password until one is set). ACL
// changes aren't saved by the server: they are applied again whenever the
// copy starts.
func (e *Engine) lockCopy(ctx context.Context, env agent.EngineEnv, rec safeRecord) error {
	s := scratchAt(env, rec.Dir)
	c, err := e.copyConn(ctx, s, rec)
	if err != nil {
		return err
	}
	defer c.Close()
	agentArgs := []any{"ACL", "SETUSER", copyAgentUser, "reset", "on", ">" + rec.AgentPassword, "~*", "&*", "+@all"}
	if _, err := c.do(ctx, agentArgs...); err != nil {
		return fmt.Errorf("creating the agent's login on the copy: %w", err)
	}
	role := []any{"ACL", "SETUSER", rec.Role, "reset"}
	if rec.Verifier != "" {
		role = append(role, "on", rec.Verifier)
	} else {
		role = append(role, "off")
	}
	for _, r := range strings.Fields(copyUserRules) {
		role = append(role, r)
	}
	if _, err := c.do(ctx, role...); err != nil {
		return fmt.Errorf("creating the copy's login: %w", err)
	}
	if _, err := c.do(ctx, "ACL", "SETUSER", "default", "off", "resetpass", "nopass"); err != nil {
		return err
	}
	return nil
}

// copyConn connects to a copy as the agent (or as the default user before
// it is locked).
func (e *Engine) copyConn(ctx context.Context, s scratch, rec safeRecord) (*conn, error) {
	c, err := dial(ctx, s.sock())
	if err != nil {
		return nil, err
	}
	if _, err := c.do(ctx, "AUTH", copyAgentUser, rec.AgentPassword); err != nil {
		if !isRespError(err, "WRONGPASS", "ERR") {
			c.Close()
			return nil, err
		}
		// Not locked yet: the default user (the socket is private).
	}
	if err := waitReady(ctx, c, time.Minute); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ---- the agent's TLS entrance to a copy

type copyProxy struct {
	lns    []net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// maxCopyConns caps a copy's connections through the agent.
const maxCopyConns = 256

func (e *Engine) startProxy(env agent.EngineEnv, rec safeRecord) error {
	ss := safeState(env)
	e.stopProxy(env, rec.ID)
	s := scratchAt(env, rec.Dir)
	cert, err := tls.LoadX509KeyPair(filepath.Join(s.Dir, "server.crt"), filepath.Join(s.Dir, "server.key"))
	if err != nil {
		return fmt.Errorf("the copy's certificate: %w", err)
	}
	var allow []netip.Prefix
	for _, a := range rec.AllowFrom {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return err
		}
		allow = append(allow, p)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithCancel(e.baseCtx())
	px := &copyProxy{cancel: cancel}
	for _, addr := range rec.Listen {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(rec.Port)))
		if err != nil {
			cancel()
			for _, l := range px.lns {
				l.Close()
			}
			return err
		}
		px.lns = append(px.lns, ln)
	}
	slots := make(chan struct{}, maxCopyConns)
	for _, ln := range px.lns {
		px.wg.Add(1)
		go func() {
			defer px.wg.Done()
			context.AfterFunc(ctx, func() { ln.Close() })
			for {
				nc, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if !allowedPeer(nc.RemoteAddr(), allow) {
					nc.Close()
					continue
				}
				select {
				case slots <- struct{}{}:
				default:
					nc.Close()
					continue
				}
				go func() {
					defer func() { <-slots }()
					serveCopyConn(ctx, nc, cfg, s.sock())
				}()
			}
		}()
	}
	ss.mu.Lock()
	ss.proxies[rec.ID] = px
	ss.mu.Unlock()
	return nil
}

func allowedPeer(a net.Addr, allow []netip.Prefix) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func serveCopyConn(ctx context.Context, nc net.Conn, cfg *tls.Config, sock string) {
	defer nc.Close()
	tc := tls.Server(nc, cfg)
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return
	}
	var d net.Dialer
	uc, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return
	}
	defer uc.Close()
	stop := context.AfterFunc(ctx, func() { tc.Close(); uc.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(uc, tc); done <- struct{}{} }()
	go func() { _, _ = io.Copy(tc, uc); done <- struct{}{} }()
	<-done
}

func (e *Engine) stopProxy(env agent.EngineEnv, id string) {
	ss := safeState(env)
	ss.mu.Lock()
	px := ss.proxies[id]
	delete(ss.proxies, id)
	ss.mu.Unlock()
	if px != nil {
		px.cancel()
		for _, l := range px.lns {
			l.Close()
		}
		px.wg.Wait()
	}
}

// ---- heartbeat and lifecycle

// CopyStates reports the safe copies.
func (e *Engine) CopyStates(env agent.EngineEnv) []protocol.CopyState {
	var out []protocol.CopyState
	for _, r := range safeState(env).all() {
		exp := r.Expires
		out = append(out, protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.CopyKindSafe, Status: r.Status,
			SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, Expires: &exp, RecoveredTo: r.RecoveredTo, Listen: strings.Join(r.Listen, ","),
			Port: r.Port, PasswordVersion: r.PasswordVersion})
	}
	return out
}

// CopyPorts are the ports the safe copies listen on.
func (e *Engine) CopyPorts(env agent.EngineEnv) []int {
	var out []int
	for _, r := range safeState(env).all() {
		out = append(out, r.Port)
	}
	return out
}

// DropCopy deletes a safe copy (cancelling its preparation).
func (e *Engine) DropCopy(ctx context.Context, env agent.EngineEnv, id string) bool {
	ss := safeState(env)
	r, ok := ss.get(id)
	if !ok {
		return false
	}
	ss.mu.Lock()
	cancel, running := ss.running[id]
	ss.mu.Unlock()
	if running {
		cancel()
		return true
	}
	e.removeSafe(env, r)
	return true
}

func (e *Engine) removeSafe(env agent.EngineEnv, r safeRecord) {
	e.stopProxy(env, r.ID)
	s := scratchAt(env, r.Dir)
	if s.pid() != 0 {
		// The default user is off: shut it down as the agent.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if c, err := e.copyConn(ctx, s, r); err == nil {
			_, _ = c.do(ctx, "SHUTDOWN", "NOSAVE")
			c.Close()
		}
		cancel()
	}
	freed, err := s.remove()
	if err != nil {
		env.Log.Error("deleting a safe copy failed", "copy_id", r.ID, "err", err)
		return
	}
	_ = safeState(env).remove(r.ID)
	env.Log.Info("deleted a safe copy", "copy_id", r.ID, "freed", humanBytes(freed))
}

// SetCopyExpiries applies Extend.
func (e *Engine) SetCopyExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	ss := safeState(env)
	now := time.Now()
	for _, x := range exp {
		if r, ok := ss.get(x.ID); ok && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = ss.put(r)
		}
	}
}

// SetCopyPassword sets the copy login's password (and lets it in).
func (e *Engine) SetCopyPassword(ctx context.Context, env agent.EngineEnv, p protocol.CopyPassword) bool {
	ss := safeState(env)
	r, ok := ss.get(p.ID)
	if !ok {
		return false
	}
	if r.Status != protocol.CopyReady || p.Version <= r.PasswordVersion {
		return true
	}
	if !protocol.ValidCopyVerifier(e.name, p.Verifier) {
		env.Log.Warn("ignoring an invalid password for a copy", "copy_id", p.ID)
		return true
	}
	c, err := e.copyConn(ctx, scratchAt(env, r.Dir), r)
	if err != nil {
		env.Log.Error("setting a copy's password: the copy doesn't answer", "copy_id", p.ID, "err", err)
		return true
	}
	defer c.Close()
	if _, err := c.do(ctx, "ACL", "SETUSER", r.Role, "on", "resetpass", p.Verifier); err != nil {
		env.Log.Error("setting a copy's password failed", "copy_id", p.ID, "err", err)
		return true
	}
	r.Verifier, r.PasswordVersion = p.Verifier, max(r.PasswordVersion, p.Version)
	_ = ss.put(r)
	env.Log.Info("set a new password on a safe copy", "copy_id", p.ID, "version", p.Version)
	return true
}

// recoverSafeCopies starts the safe copies again after an agent restart
// (as they were made: changes made on a copy last until it stops) and
// removes those whose preparation was interrupted.
func (e *Engine) recoverSafeCopies(ctx context.Context, env agent.EngineEnv) {
	ss := safeState(env)
	for _, r := range ss.all() {
		s := scratchAt(env, r.Dir)
		if r.Status != protocol.CopyReady {
			e.removeSafe(env, r)
			continue
		}
		if time.Now().After(r.Expires) {
			continue
		}
		if s.pid() == 0 {
			c, err := s.restart(ctx, env)
			if err != nil {
				env.Log.Error("starting a safe copy again failed; it stays until it expires or is deleted", "copy_id", r.ID, "err", err)
				continue
			}
			c.Close()
		}
		if err := e.lockCopy(ctx, env, r); err != nil {
			env.Log.Error("locking a safe copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		if err := e.startProxy(env, r); err != nil {
			env.Log.Error("opening a safe copy again failed", "copy_id", r.ID, "err", err)
		}
	}
}

// expireSafeCopies deletes safe copies past their expiry.
func (e *Engine) expireSafeCopies(env agent.EngineEnv, now time.Time) {
	for _, r := range safeState(env).all() {
		if r.Status == protocol.CopyReady && now.After(r.Expires) {
			e.removeSafe(env, r)
		}
	}
}
