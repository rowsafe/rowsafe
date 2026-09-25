package dockerctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Compose labels identifying a container's project and service.
const (
	labelProject = "com.docker.compose.project"
	labelService = "com.docker.compose.service"
)

// Rate limits (variables for tests).
var (
	// restartEvery is the least time between two restarts.
	restartEvery = time.Minute
	// maxPerHour caps stops and restarts together.
	maxPerHour = 20
	// readTimeout bounds how long a peer may take to send its request.
	readTimeout = 10 * time.Second
	// maxConns bounds concurrent connections.
	maxConns = 8
)

// Config is the service's policy. Only the operator sets it (environment
// of the control container); nothing a peer sends changes it.
type Config struct {
	// DockerSocket is the Docker Engine socket.
	DockerSocket string
	// Service is the compose service to control, in this service's own
	// compose project (default "postgres"). Ignored when Container is set.
	Service string
	// Container is the name of the container to control, for setups
	// without compose (docker run).
	Container string
	// StopTimeout is how long Docker waits for PostgreSQL to shut down
	// before killing it (the postgres images stop with SIGINT: a fast,
	// clean shutdown).
	StopTimeout time.Duration
	// AllowedUIDs are the peer uids that may connect (the postgres user of
	// the images the agent runs as: 999 Debian, 70 Alpine).
	AllowedUIDs []int
	Log         *slog.Logger

	// For tests.
	now    func() time.Time
	selfID func() string
	peer   func(net.Conn) (Peer, error)
	engine *engine
}

// Peer is who is on the other end of a connection.
type Peer struct {
	UID, PID int
}

// target is the container this service controls.
type target struct {
	ID, Name, Project, Service string
}

// Server enforces the policy.
type Server struct {
	cfg Config
	eng *engine
	log *slog.Logger

	// actMu serializes stop, start and restart.
	actMu sync.Mutex

	mu        sync.Mutex
	self      string // this container's ID ("" if unknown)
	project   string // this container's compose project
	target    target
	resolved  bool
	restarts  []time.Time // restart times, last hour
	mutations []time.Time // stop and restart times, last hour
}

// New checks cfg and returns a server. It doesn't talk to Docker yet.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.selfID == nil {
		cfg.selfID = ownContainerID
	}
	if cfg.peer == nil {
		cfg.peer = peerCred
	}
	if cfg.Container == "" && cfg.Service == "" {
		cfg.Service = "postgres"
	}
	if cfg.Container != "" && !nameRE.MatchString(cfg.Container) {
		return nil, fmt.Errorf("ROWSAFE_CONTROL_CONTAINER %q is not a container name", cfg.Container)
	}
	if cfg.Container == "" && !nameRE.MatchString(cfg.Service) {
		return nil, fmt.Errorf("ROWSAFE_CONTROL_SERVICE %q is not a compose service name", cfg.Service)
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = 2 * time.Minute
	}
	if cfg.StopTimeout > 10*time.Minute {
		return nil, errors.New("the stop timeout can be at most 10 minutes")
	}
	if len(cfg.AllowedUIDs) == 0 {
		cfg.AllowedUIDs = []int{999, 70}
	}
	eng := cfg.engine
	if eng == nil {
		if cfg.DockerSocket == "" {
			cfg.DockerSocket = "/var/run/docker.sock"
		}
		eng = newEngine(cfg.DockerSocket)
	}
	return &Server{cfg: cfg, eng: eng, log: cfg.Log}, nil
}

// describe is the configured target, for messages.
func (s *Server) describe() string {
	if s.cfg.Container != "" {
		return fmt.Sprintf("the container %q", s.cfg.Container)
	}
	if s.project != "" {
		return fmt.Sprintf("the compose service %q in project %q", s.cfg.Service, s.project)
	}
	return fmt.Sprintf("the compose service %q", s.cfg.Service)
}

// Resolve finds the target container and pins its ID. It runs at start and
// again when the pinned container is gone (compose recreated it).
func (s *Server) Resolve(ctx context.Context) (target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolveLocked(ctx)
}

func (s *Server) resolveLocked(ctx context.Context) (target, error) {
	if s.self == "" {
		s.self = s.cfg.selfID()
		if s.self != "" {
			if me, err := s.eng.inspect(ctx, s.self); err == nil {
				s.self = me.ID
				s.project = me.Config.Labels[labelProject]
			} else {
				s.log.Warn("could not inspect this container itself", "err", err)
			}
		}
	}
	var t target
	if s.cfg.Container != "" {
		c, err := s.eng.inspect(ctx, s.cfg.Container)
		if err != nil {
			var nf errNotFound
			if errors.As(err, &nf) {
				return t, fmt.Errorf("there is no container named %q", s.cfg.Container)
			}
			return t, err
		}
		t = targetOf(c)
		// A container named the same in another compose project is not ours.
		if s.project != "" && t.Project != s.project {
			return target{}, fmt.Errorf("the container %q belongs to compose project %q, not %q (this service's own); refusing it",
				s.cfg.Container, t.Project, s.project)
		}
	} else {
		if s.project == "" {
			return t, errors.New("this service isn't running in a compose project, so it can't find the compose service " +
				fmt.Sprintf("%q; set ROWSAFE_CONTROL_CONTAINER to the PostgreSQL container's name", s.cfg.Service))
		}
		list, err := s.eng.listByLabels(ctx, labelProject+"="+s.project, labelService+"="+s.cfg.Service)
		if err != nil {
			return t, err
		}
		// Docker filtered by label; check again rather than trust it.
		list = slices.DeleteFunc(list, func(e listEntry) bool {
			return e.Labels[labelProject] != s.project || e.Labels[labelService] != s.cfg.Service || !containerIDRE.MatchString(e.ID)
		})
		switch len(list) {
		case 0:
			return t, fmt.Errorf("found no container for %s: check ROWSAFE_CONTROL_SERVICE is your PostgreSQL service's name", s.describe())
		case 1:
		default:
			return t, fmt.Errorf("found %d containers for %s; Rowsafe controls exactly one PostgreSQL container", len(list), s.describe())
		}
		c, err := s.eng.inspect(ctx, list[0].ID)
		if err != nil {
			return t, err
		}
		t = targetOf(c)
	}
	if s.self != "" && t.ID == s.self {
		return target{}, errors.New("the configured target is this control container itself; refusing it")
	}
	if !s.resolved || s.target.ID != t.ID {
		s.log.Info("controlling container", "container", t.Name, "id", short(t.ID), "project", t.Project, "service", t.Service)
	}
	s.target, s.resolved = t, true
	return t, nil
}

func targetOf(c containerJSON) target {
	return target{ID: c.ID, Name: strings.TrimPrefix(c.Name, "/"), Project: c.Config.Labels[labelProject], Service: c.Config.Labels[labelService]}
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// matches checks an inspected container is still the configured target.
func (s *Server) matches(c containerJSON) bool {
	t := targetOf(c)
	if s.self != "" && t.ID == s.self {
		return false
	}
	if s.cfg.Container != "" {
		return t.Name == s.cfg.Container && (s.project == "" || t.Project == s.project)
	}
	return t.Project == s.project && t.Service == s.cfg.Service
}

// current inspects the pinned target, re-resolving once if it is gone or
// no longer matches (compose recreated it).
func (s *Server) current(ctx context.Context) (target, containerJSON, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.resolved {
		if _, err := s.resolveLocked(ctx); err != nil {
			return target{}, containerJSON{}, err
		}
	}
	c, err := s.eng.inspect(ctx, s.target.ID)
	var nf errNotFound
	if err == nil && s.matches(c) {
		return s.target, c, nil
	}
	if err != nil && !errors.As(err, &nf) {
		return target{}, containerJSON{}, err
	}
	s.log.Info("the controlled container is gone or changed; looking for it again", "was", short(s.target.ID))
	s.resolved = false
	t, err := s.resolveLocked(ctx)
	if err != nil {
		return target{}, containerJSON{}, err
	}
	c, err = s.eng.inspect(ctx, t.ID)
	if err != nil {
		return target{}, containerJSON{}, err
	}
	if !s.matches(c) {
		return target{}, containerJSON{}, errors.New("the container changed while Rowsafe was looking at it; try again")
	}
	return t, c, nil
}

// response fills the container's state.
func (s *Server) response(req Request, t target, c containerJSON) Response {
	r := Response{OK: true, ID: req.ID, Action: req.Action, Container: t.Name, ContainerID: short(t.ID), Project: t.Project,
		Service: t.Service, State: c.State.Status, ExitCode: c.State.ExitCode, Actions: Actions}
	if c.State.Health != nil {
		r.Health = c.State.Health.Status
	}
	if at, err := time.Parse(time.RFC3339Nano, c.State.StartedAt); err == nil && at.Year() > 1 {
		r.StartedAt = &at
	}
	return r
}

// allow applies the rate limits to action, recording it when allowed. The
// caller holds actMu.
func (s *Server) allow(action string) (time.Duration, error) {
	if action != ActionStop && action != ActionRestart {
		return 0, nil // start and inspect are never limited
	}
	now := s.cfg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	hourAgo := now.Add(-time.Hour)
	s.mutations = slices.DeleteFunc(s.mutations, func(t time.Time) bool { return t.Before(hourAgo) })
	s.restarts = slices.DeleteFunc(s.restarts, func(t time.Time) bool { return t.Before(hourAgo) })
	if action == ActionRestart && len(s.restarts) > 0 {
		if wait := s.restarts[len(s.restarts)-1].Add(restartEvery).Sub(now); wait > 0 {
			return wait, fmt.Errorf("the container was restarted less than %s ago; try again in %d seconds", restartEvery, int(wait.Seconds()+0.999))
		}
	}
	if len(s.mutations) >= maxPerHour {
		wait := s.mutations[0].Add(time.Hour).Sub(now)
		return wait, fmt.Errorf("the container was stopped or restarted %d times in the last hour, the most this service allows; try again in %d minutes",
			len(s.mutations), int(wait.Minutes()+0.999))
	}
	s.mutations = append(s.mutations, now)
	if action == ActionRestart {
		s.restarts = append(s.restarts, now)
	}
	return 0, nil
}

// Do runs one request from peer: the policy in one place.
func (s *Server) Do(ctx context.Context, peer Peer, req Request) (res Response) {
	start := s.cfg.now()
	defer func() {
		level := slog.LevelInfo
		if !res.OK {
			level = slog.LevelWarn
		}
		s.log.Log(ctx, level, "request", "peer_uid", peer.UID, "peer_pid", peer.PID, "id", req.ID, "action", req.Action,
			"container", res.Container, "ok", res.OK, "state", res.State, "error", res.Error,
			"duration_ms", s.cfg.now().Sub(start).Milliseconds())
	}()
	fail := func(msg string) Response {
		return Response{ID: req.ID, Action: req.Action, Error: msg, Actions: Actions}
	}
	if !requestIDRE.MatchString(req.ID) {
		req.ID = ""
		return fail("invalid request id")
	}
	if !slices.Contains(Actions, req.Action) {
		return fail(fmt.Sprintf("action %q is not allowed (allowed: %s)", req.Action, strings.Join(Actions, ", ")))
	}
	if req.Action != ActionInspect {
		s.actMu.Lock()
		defer s.actMu.Unlock()
	}
	t, c, err := s.current(ctx)
	if err != nil {
		return fail(err.Error())
	}
	if req.Action == ActionInspect {
		return s.response(req, t, c)
	}
	if wait, err := s.allow(req.Action); err != nil {
		r := fail(err.Error())
		r.Container, r.ContainerID = t.Name, short(t.ID)
		r.RetryAfterSeconds = int(wait.Seconds() + 0.999)
		return r
	}
	s.log.Info("acting", "id", req.ID, "action", req.Action, "container", t.Name, "container_id", short(t.ID))
	if err := s.eng.lifecycle(ctx, t.ID, req.Action, s.cfg.StopTimeout); err != nil {
		r := fail(err.Error())
		r.Container, r.ContainerID = t.Name, short(t.ID)
		return r
	}
	c, err = s.eng.inspect(ctx, t.ID)
	if err != nil {
		r := fail(fmt.Sprintf("%s done, but inspecting the container afterwards failed: %v", req.Action, err))
		r.Container, r.ContainerID = t.Name, short(t.ID)
		return r
	}
	return s.response(req, t, c)
}

// Serve accepts connections on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // too many at once
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, conn)
		}()
	}
}

// handle reads one request, answers it and closes the connection.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	answer := func(r Response) {
		data, _ := json.Marshal(r)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = conn.Write(append(data, '\n'))
	}
	peer, err := s.cfg.peer(conn)
	if err != nil {
		s.log.Warn("refused a connection: can't tell who is connecting", "err", err)
		answer(Response{Error: "can't identify the connecting process"})
		return
	}
	if !slices.Contains(s.cfg.AllowedUIDs, peer.UID) {
		s.log.Warn("refused a connection from a user that isn't allowed", "peer_uid", peer.UID, "peer_pid", peer.PID, "allowed", s.cfg.AllowedUIDs)
		answer(Response{Error: fmt.Sprintf("uid %d may not use this service (allowed: %v; set ROWSAFE_CONTROL_ALLOW_UIDS)", peer.UID, s.cfg.AllowedUIDs)})
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest+1)).ReadBytes('\n')
	if len(line) == 0 && err != nil {
		return // closed without asking anything (e.g. a connection check)
	}
	if len(line) > maxRequest {
		s.log.Warn("refused an oversized request", "peer_uid", peer.UID, "peer_pid", peer.PID)
		answer(Response{Error: "request too large"})
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		if err == nil {
			err = errors.New("trailing data")
		}
		s.log.Warn("refused a malformed request", "peer_uid", peer.UID, "peer_pid", peer.PID, "err", err)
		answer(Response{Error: "malformed request: " + err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	answer(s.Do(ctx, peer, req))
}

// Listen creates the control socket at path: its directory if missing, a
// stale socket from an earlier run removed (never any other kind of file),
// and mode 0666 so the agent's uid can connect. Who may actually use it is
// decided per connection (AllowedUIDs); the directory is a volume only the
// agent container shares.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; refusing to replace it", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "/"
}
