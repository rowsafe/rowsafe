package dockerctl

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/release/agentimages"
)

// Updating the Rowsafe agent's own container (opt-in:
// ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE=1).
//
// The agent can't replace its container itself (it would stop itself), so
// it asks this service, passing the release's images document and its
// signature from the control plane. This service:
//
//  1. verifies the signature with the release key built into it, and picks
//     the digest for the agent image's variant (pg17, pg17-alpine: from the
//     current image's label or tag); nothing else from the request is used;
//  2. finds the agent container: the AgentService (default rowsafe-agent)
//     of its own compose project, exactly one, running an image of
//     ghcr.io/rowsafe/agent, never PostgreSQL's container or itself;
//  3. pulls ghcr.io/rowsafe/agent@<digest> (Docker checks the content
//     against the digest) and checks the image's labels agree;
//  4. creates the new container, under a temporary name, with the old one's
//     configuration (recreate.go) and only the image changed;
//  5. stops the old container, renames it aside, gives the new one its
//     name and starts it;
//  6. waits until the new container runs (healthy, with its health check)
//     and the new agent says so over the socket (agent_ready, with the new
//     version), at most agentReadyTimeout;
//  7. removes the old container (never its volumes).
//
// If anything fails from step 5 on, it stops and removes the new container,
// gives the old one its name back and starts it. PostgreSQL's container is
// never part of it. Until step 5 nothing has changed; one update at a time,
// at most maxAgentUpdatesPerHour.

var (
	// agentReadyTimeout bounds step 6.
	agentReadyTimeout = 5 * time.Minute
	// agentPoll is how often step 6 looks.
	agentPoll = 2 * time.Second
	// agentStopTimeout is how long the old agent gets to shut down.
	agentStopTimeout = time.Minute
	// maxAgentUpdatesPerHour caps updates.
	maxAgentUpdatesPerHour = 4
)

// Suffixes of the temporary names, on the agent container's own name.
const (
	newSuffix = "-rowsafe-new"
	oldSuffix = "-rowsafe-old"
)

// versionLabel is the OCI label the release workflow sets on every image.
const versionLabel = "org.opencontainers.image.version"

// agentPlan is a verified request.
type agentPlan struct {
	id, version, variant, digest, ref string
	from                              string // the running version, from the image label ("" unknown)
	oldID                             string
}

// agentUpdateStatus is a copy of the update in progress or the last one.
func (s *Server) agentUpdateStatus() *AgentUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upd == nil {
		return nil
	}
	u := *s.upd
	return &u
}

func (s *Server) setUpdate(f func(u *AgentUpdate)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s.upd)
}

// startAgentUpdate checks a request and starts the update in the
// background; the answer says it started (the asking agent is replaced
// before the update ends).
func (s *Server) startAgentUpdate(ctx context.Context, req Request) Response {
	fail := func(msg string) Response {
		return Response{ID: req.ID, Action: req.Action, Error: msg, Actions: s.actions()}
	}
	if req.Images == nil {
		return fail("the request has no signed images document")
	}
	if s.pub == nil {
		return fail("this build of rowsafe-docker-control has no release key to check images with; use the published image")
	}
	doc, err := agentimages.Verify(s.pub, []byte(req.Images.Document), req.Images.Signature)
	if err != nil {
		return fail("refusing the update: " + err.Error())
	}
	if doc.Version != req.Version {
		return fail(fmt.Sprintf("refusing the update: the request says %s but the signed document is for %s", req.Version, doc.Version))
	}
	s.mu.Lock()
	busy := s.upd != nil && !s.upd.Finished()
	now := s.cfg.now()
	s.updTimes = slices.DeleteFunc(s.updTimes, func(t time.Time) bool { return t.Before(now.Add(-time.Hour)) })
	tooMany := len(s.updTimes) >= maxAgentUpdatesPerHour
	s.mu.Unlock()
	if busy {
		return fail("an update of the agent container is already running")
	}
	if tooMany {
		return fail(fmt.Sprintf("the agent container was updated %d times in the last hour, the most this service allows", maxAgentUpdatesPerHour))
	}
	c, _, oldImg, err := s.agentContainer(ctx)
	if err != nil {
		return fail(err.Error())
	}
	variant := agentVariant(c, oldImg)
	if variant == "" {
		return fail(fmt.Sprintf("can't tell which agent image %s runs (%s): give it a tag like %s:pg17", strings.TrimPrefix(c.Name, "/"),
			c.Config.Image, agentimages.Repository))
	}
	ref, ok := doc.Ref(variant)
	if !ok {
		return fail(fmt.Sprintf("release %s has no %s image", doc.Version, variant))
	}
	from := oldImg.labels()[versionLabel]
	if cmp, ok := agentimages.CompareVersions(doc.Version, from); ok && cmp <= 0 {
		return fail(fmt.Sprintf("the agent container already runs %s; refusing to go to %s", from, doc.Version))
	}
	p := agentPlan{id: req.ID, version: doc.Version, variant: variant, digest: doc.Images[variant], ref: ref, from: from, oldID: c.ID}
	s.mu.Lock()
	if s.upd != nil && !s.upd.Finished() {
		s.mu.Unlock()
		return fail("an update of the agent container is already running")
	}
	s.upd = &AgentUpdate{ID: p.id, State: AgentUpdatePulling, FromVersion: from, Version: p.version, Variant: variant, Image: ref,
		StartedAt: now.UTC()}
	s.updReady = false
	s.updTimes = append(s.updTimes, now)
	base := s.baseCtx
	s.mu.Unlock()
	s.log.Info("agent update accepted", "id", p.id, "from", from, "to", p.version, "variant", variant, "image", ref,
		"container", strings.TrimPrefix(c.Name, "/"))
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		s.runAgentUpdate(base, p)
	}()
	return Response{OK: true, ID: req.ID, Action: req.Action, Container: strings.TrimPrefix(c.Name, "/"), ContainerID: short(c.ID),
		Project: c.Config.Labels[labelProject], Service: c.Config.Labels[labelService], State: c.State.Status, Actions: s.actions()}
}

// agentReady records that the new agent runs (only the version being
// installed counts).
func (s *Server) agentReady(req Request) Response {
	s.mu.Lock()
	if s.upd != nil && !s.upd.Finished() && req.Version != "" && req.Version == s.upd.Version {
		s.updReady = true
	}
	s.mu.Unlock()
	return Response{OK: true, ID: req.ID, Action: req.Action, Actions: s.actions()}
}

// agentVariant is the image variant of the agent container: the image's
// label, else its tag.
func agentVariant(c containerJSON, img imageJSON) string {
	if v := img.labels()[agentimages.VariantLabel]; agentimages.ValidVariant(v) {
		return v
	}
	if v := agentimages.VariantOfRef(c.Config.Image); v != "" {
		return v
	}
	for _, t := range img.RepoTags {
		if v := agentimages.VariantOfRef(t); v != "" {
			return v
		}
	}
	return ""
}

// isAgentImage reports whether ref names the agent repository.
func isAgentImage(ref string) bool {
	return strings.HasPrefix(ref, agentimages.Repository+":") || strings.HasPrefix(ref, agentimages.Repository+"@")
}

// agentContainer finds the agent's container (with its inspect answer and
// image), checking it is the agent's and not PostgreSQL's or this one.
func (s *Server) agentContainer(ctx context.Context) (containerJSON, []byte, imageJSON, error) {
	s.mu.Lock()
	s.identifySelfLocked(ctx)
	if s.cfg.UpdateOnly && !s.resolved {
		// Only to refuse the database's container below, when it is found.
		_, _ = s.resolveLocked(ctx)
	}
	self, project, pgID := s.self, s.project, s.target.ID
	s.mu.Unlock()
	var c containerJSON
	var raw []byte
	var err error
	if s.cfg.AgentContainer != "" {
		c, raw, err = s.eng.inspectRaw(ctx, s.cfg.AgentContainer)
		if errors.As(err, new(errNotFound)) {
			return c, nil, imageJSON{}, fmt.Errorf("there is no container named %q (ROWSAFE_CONTROL_AGENT_CONTAINER)", s.cfg.AgentContainer)
		}
		if err != nil {
			return c, nil, imageJSON{}, err
		}
		if project != "" && c.Config.Labels[labelProject] != project {
			return c, nil, imageJSON{}, fmt.Errorf("the container %q belongs to compose project %q, not %q; refusing it",
				s.cfg.AgentContainer, c.Config.Labels[labelProject], project)
		}
	} else {
		if project == "" {
			return c, nil, imageJSON{}, errors.New("this service isn't running in a compose project, so it can't find the agent's service; " +
				"set ROWSAFE_CONTROL_AGENT_CONTAINER to the agent container's name")
		}
		list, err := s.eng.listByLabels(ctx, labelProject+"="+project, labelService+"="+s.cfg.AgentService)
		if err != nil {
			return c, nil, imageJSON{}, err
		}
		list = slices.DeleteFunc(list, func(e listEntry) bool {
			return e.Labels[labelProject] != project || e.Labels[labelService] != s.cfg.AgentService || !containerIDRE.MatchString(e.ID) ||
				slices.ContainsFunc(e.Names, func(n string) bool { return strings.HasSuffix(n, newSuffix) || strings.HasSuffix(n, oldSuffix) })
		})
		switch len(list) {
		case 0:
			return c, nil, imageJSON{}, fmt.Errorf("found no container for the agent's compose service %q in project %q: set ROWSAFE_CONTROL_AGENT_SERVICE "+
				"to the agent's service name", s.cfg.AgentService, project)
		case 1:
		default:
			return c, nil, imageJSON{}, fmt.Errorf("found %d containers for the agent's service %q; Rowsafe updates exactly one", len(list), s.cfg.AgentService)
		}
		c, raw, err = s.eng.inspectRaw(ctx, list[0].ID)
		if err != nil {
			return c, nil, imageJSON{}, err
		}
		if c.Config.Labels[labelProject] != project || c.Config.Labels[labelService] != s.cfg.AgentService {
			return c, nil, imageJSON{}, errors.New("the agent container changed while Rowsafe was looking at it; try again")
		}
	}
	switch {
	case c.ID == self && self != "":
		return c, nil, imageJSON{}, errors.New("the configured agent container is this control container itself; refusing it")
	case c.ID == pgID && pgID != "":
		return c, nil, imageJSON{}, errors.New("the configured agent container is the database's; refusing it")
	case !isAgentImage(c.Config.Image):
		return c, nil, imageJSON{}, fmt.Errorf("the agent container runs %q, not an image of %s, so Rowsafe doesn't replace it: update it yourself",
			c.Config.Image, agentimages.Repository)
	case !nameRE.MatchString(strings.TrimPrefix(c.Name, "/")):
		return c, nil, imageJSON{}, fmt.Errorf("unexpected container name %q", c.Name)
	}
	img, err := s.eng.imageInspect(ctx, c.Image)
	if err != nil {
		return c, nil, imageJSON{}, err
	}
	return c, raw, img, nil
}

// runAgentUpdate does steps 3 to 7, rolling back on failure.
func (s *Server) runAgentUpdate(ctx context.Context, p agentPlan) {
	s.actMu.Lock()
	defer s.actMu.Unlock()
	log := s.log.With("id", p.id, "to", p.version, "image", p.ref)
	finish := func(state, msg string) {
		at := s.cfg.now().UTC()
		s.setUpdate(func(u *AgentUpdate) { u.State, u.Error, u.FinishedAt = state, msg, &at })
		if state == AgentUpdateDone {
			log.Info("agent update done")
		} else {
			log.Error("agent update "+state, "error", msg)
		}
	}
	failed := func(format string, args ...any) { finish(AgentUpdateFailed, fmt.Sprintf(format, args...)) }

	// 3. The image, by digest.
	log.Info("pulling the agent image")
	if err := s.eng.pull(ctx, p.digest); err != nil {
		failed("%v", err)
		return
	}
	img, err := s.eng.imageInspect(ctx, p.ref)
	if err != nil {
		failed("%v", err)
		return
	}
	if !slices.Contains(img.RepoDigests, p.ref) {
		failed("Docker's image %s doesn't carry the digest %s; refusing it", img.ID, p.digest)
		return
	}
	labels := img.labels()
	if v := labels[agentimages.VariantLabel]; v != "" && v != p.variant {
		failed("the image for %s says it is %s; refusing it", p.variant, v)
		return
	}
	if v := labels[versionLabel]; v != "" && v != p.version {
		failed("the image for %s says it is version %s; refusing it", p.version, v)
		return
	}

	// 4. The new container, beside the old one.
	c, raw, oldImg, err := s.agentContainer(ctx)
	if err != nil {
		failed("%v", err)
		return
	}
	if c.ID != p.oldID {
		failed("the agent container changed since the update was asked for; try again")
		return
	}
	body, err := replacement(raw, oldImg, p.ref)
	if err != nil {
		failed("%v", err)
		return
	}
	name := strings.TrimPrefix(c.Name, "/")
	tmpName, oldName := aside(name, newSuffix), aside(name, oldSuffix)
	for _, n := range []string{tmpName, oldName} {
		if err := s.clearLeftover(ctx, n, c); err != nil {
			failed("%v", err)
			return
		}
	}
	newID, err := s.eng.create(ctx, tmpName, body)
	if err != nil {
		failed("%v", err)
		return
	}
	log.Info("created the new agent container", "container", tmpName, "container_id", short(newID))

	// 5. Switch.
	s.setUpdate(func(u *AgentUpdate) { u.State = AgentUpdateSwitching })
	renamed := false
	rollback := func(reason string) {
		log.Warn("putting the old agent container back", "reason", reason)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		var errs []string
		if err := s.eng.lifecycle(rctx, newID, ActionStop, 30*time.Second); err != nil && !errors.As(err, new(errNotFound)) {
			errs = append(errs, "stopping the new container: "+err.Error())
		}
		if err := s.eng.remove(rctx, newID); err != nil && !errors.As(err, new(errNotFound)) {
			errs = append(errs, "removing the new container: "+err.Error())
		}
		if renamed {
			if err := s.eng.rename(rctx, c.ID, name); err != nil {
				errs = append(errs, "renaming the old container back: "+err.Error())
			}
		}
		if err := s.eng.lifecycle(rctx, c.ID, ActionStart, 0); err != nil {
			errs = append(errs, "starting the old container: "+err.Error())
		}
		if len(errs) > 0 {
			finish(AgentUpdateFailed, fmt.Sprintf("%s; putting the old agent container back failed too (%s): start it with `docker start %s`",
				reason, strings.Join(errs, "; "), name))
			return
		}
		finish(AgentUpdateRolledBack, reason+"; the old agent container runs again")
	}
	if err := s.eng.lifecycle(ctx, c.ID, ActionStop, agentStopTimeout); err != nil {
		rollback("stopping the old agent container: " + err.Error())
		return
	}
	if err := s.eng.rename(ctx, c.ID, oldName); err != nil {
		rollback(err.Error())
		return
	}
	renamed = true
	if err := s.eng.rename(ctx, newID, name); err != nil {
		rollback(err.Error())
		return
	}
	if err := s.eng.lifecycle(ctx, newID, ActionStart, 0); err != nil {
		rollback("starting the new agent container: " + err.Error())
		return
	}
	log.Info("started the new agent container; waiting for the agent", "container", name, "container_id", short(newID))

	// 6. Wait for the new agent.
	s.setUpdate(func(u *AgentUpdate) { u.State = AgentUpdateWaiting })
	if err := s.waitAgent(ctx, newID, p.version); err != nil {
		rollback(err.Error())
		return
	}

	// 7. The old container goes; its volumes stay.
	if err := s.eng.remove(context.WithoutCancel(ctx), c.ID); err != nil {
		log.Warn("removing the old agent container failed; remove it yourself", "container", oldName, "err", err)
	}
	finish(AgentUpdateDone, "")
}

// waitAgent waits until the new container runs, is healthy if it has a
// health check, and the new agent said it runs.
func (s *Server) waitAgent(ctx context.Context, id, version string) error {
	deadline := time.Now().Add(agentReadyTimeout)
	for {
		c, err := s.eng.inspect(ctx, id)
		if err != nil {
			return fmt.Errorf("inspecting the new agent container: %w", err)
		}
		health := ""
		if c.State.Health != nil {
			health = c.State.Health.Status
		}
		switch {
		case c.State.Status == "exited" || c.State.Status == "dead":
			return fmt.Errorf("the new agent container stopped right after starting (exit code %d); its log says why", c.State.ExitCode)
		case health == "unhealthy":
			return errors.New("the new agent container's health check failed")
		}
		s.mu.Lock()
		ready := s.updReady
		s.mu.Unlock()
		if ready && c.State.Status == "running" && (health == "" || health == "healthy") {
			return nil
		}
		if time.Now().After(deadline) {
			state := c.State.Status
			if health != "" {
				state += ", " + health
			}
			if !ready {
				state += "; the agent never said it runs version " + version
			}
			return fmt.Errorf("the new agent wasn't up within %s (%s)", agentReadyTimeout, state)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("rowsafe-docker-control is stopping: %w", ctx.Err())
		case <-time.After(agentPoll):
		}
	}
}

// clearLeftover removes a container an interrupted update left under one of
// the temporary names: only a stopped container of the agent's own service
// running the agent image. Anything else under that name stops the update.
func (s *Server) clearLeftover(ctx context.Context, name string, agent containerJSON) error {
	c, err := s.eng.inspect(ctx, name)
	if errors.As(err, new(errNotFound)) {
		return nil
	}
	if err != nil {
		return err
	}
	ours := c.ID != agent.ID && isAgentImage(c.Config.Image) &&
		c.Config.Labels[labelProject] == agent.Config.Labels[labelProject] &&
		c.Config.Labels[labelService] == agent.Config.Labels[labelService]
	if !ours || c.State.Status == "running" || c.State.Status == "restarting" {
		return fmt.Errorf("a container named %s is in the way; remove it (docker rm %s) and try again", name, name)
	}
	s.log.Warn("removing a container an interrupted agent update left behind", "container", name, "container_id", short(c.ID))
	return s.eng.remove(ctx, c.ID)
}

// aside is name with suffix, within Docker's name length.
func aside(name, suffix string) string {
	if max := 128 - len(suffix); len(name) > max {
		name = name[:max]
	}
	return name + suffix
}
