package dockerctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/release/agentimages"
)

// The Docker Engine API calls only the agent update makes (agent_update.go),
// each with the one kind of reference it accepts. AUDIT: see engine.

var imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// validImageRef: an image ID Docker returned, or the agent repository at a
// digest.
func validImageRef(ref string) bool {
	if imageIDRE.MatchString(ref) {
		return true
	}
	dg, ok := strings.CutPrefix(ref, agentimages.Repository+"@")
	return ok && agentimages.ValidDigest(dg)
}

// imageJSON is the part of GET /images/{ref}/json the update reads; Config
// is kept whole to tell the image's defaults from the container's settings.
type imageJSON struct {
	ID          string                     `json:"Id"`
	RepoTags    []string                   `json:"RepoTags"`
	RepoDigests []string                   `json:"RepoDigests"`
	Config      map[string]json.RawMessage `json:"Config"`
}

func (i imageJSON) labels() map[string]string {
	var l map[string]string
	_ = json.Unmarshal(i.Config["Labels"], &l)
	return l
}

// imageInspect: GET /images/{ref}/json.
func (e *engine) imageInspect(ctx context.Context, ref string) (imageJSON, error) {
	var im imageJSON
	if !validImageRef(ref) {
		return im, fmt.Errorf("refusing image reference %q", ref)
	}
	status, body, err := e.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, 30*time.Second)
	if err != nil {
		return im, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return im, fmt.Errorf("Docker has no image %s", ref)
	default:
		return im, fmt.Errorf("inspecting the image: %s", dockerMessage(status, body))
	}
	if err := json.Unmarshal(body, &im); err != nil {
		return im, fmt.Errorf("reading Docker's answer: %w", err)
	}
	if !imageIDRE.MatchString(im.ID) {
		return im, fmt.Errorf("unexpected image ID %q from Docker", im.ID)
	}
	return im, nil
}

// pullTimeout bounds downloading an agent image (a few hundred MB).
var pullTimeout = 20 * time.Minute

// pull: POST /images/create?fromImage=ghcr.io/rowsafe/agent&tag=sha256:...
// The repository is the constant; only the digest varies. Docker checks
// the content against the digest as it downloads.
func (e *engine) pull(ctx context.Context, digest string) error {
	if !agentimages.ValidDigest(digest) {
		return fmt.Errorf("refusing digest %q", digest)
	}
	ctx, cancel := context.WithTimeout(ctx, pullTimeout)
	defer cancel()
	q := url.Values{"fromImage": {agentimages.Repository}, "tag": {digest}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	res, err := e.hc.Do(req)
	if err != nil {
		return fmt.Errorf("Docker API: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		return fmt.Errorf("downloading %s@%s: %s", agentimages.Repository, digest, dockerMessage(res.StatusCode, body))
	}
	// A stream of JSON progress lines; a failure is a line with "error".
	// Read it to the end: closing it early would cancel the download.
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var last string
	for sc.Scan() {
		var m struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && m.Error != "" {
			last = m.Error
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("downloading %s@%s: %w", agentimages.Repository, digest, err)
	}
	if last != "" {
		return fmt.Errorf("downloading %s@%s: %s", agentimages.Repository, digest, last)
	}
	return nil
}

// create: POST /containers/create?name=NAME. The body must run the agent
// repository at a digest (checked here again, whatever the caller built).
func (e *engine) create(ctx context.Context, name string, body map[string]any) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("refusing container name %q", name)
	}
	img, _ := body["Image"].(string)
	if dg, ok := strings.CutPrefix(img, agentimages.Repository+"@"); !ok || !agentimages.ValidDigest(dg) {
		return "", fmt.Errorf("refusing to create a container from %q", img)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	status, resp, err := e.doBody(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, data, 2*time.Minute)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("Docker couldn't create the new agent container: %s", dockerMessage(status, resp))
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || !containerIDRE.MatchString(out.ID) {
		return "", fmt.Errorf("unexpected answer from Docker creating the container: %s", resp)
	}
	return out.ID, nil
}

// rename: POST /containers/{id}/rename?name=NAME.
func (e *engine) rename(ctx context.Context, id, name string) error {
	if !containerIDRE.MatchString(id) || !nameRE.MatchString(name) {
		return fmt.Errorf("refusing to rename %q to %q", id, name)
	}
	status, body, err := e.do(ctx, http.MethodPost, "/containers/"+id+"/rename", url.Values{"name": {name}}, 30*time.Second)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("Docker couldn't rename the container to %s: %s", name, dockerMessage(status, body))
	}
	return nil
}

// remove: DELETE /containers/{id}, without force and without its volumes
// (Docker keeps every volume, named or anonymous).
func (e *engine) remove(ctx context.Context, id string) error {
	if !containerIDRE.MatchString(id) {
		return fmt.Errorf("refusing container reference %q", id)
	}
	status, body, err := e.do(ctx, http.MethodDelete, "/containers/"+id, nil, time.Minute)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errNotFound{id}
	}
	return errors.New("Docker couldn't remove the container: " + dockerMessage(status, body))
}
