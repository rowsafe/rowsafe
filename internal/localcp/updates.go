package localcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

// Without an account the agent still gets updates: the control plane
// fetches the stable release Rowsafe promoted (after the staged rollout on
// the hosted fleet) and offers it in heartbeats. The manifest and signature
// pass through unchanged and the agent checks them with the key built into
// it, so nothing here can forge a release; ROWSAFE_AUTO_UPDATE=false on the
// agent still turns updates off. Only these two files are fetched; nothing
// is sent.

// stableURL is where the promoted release's signed manifest is published
// (ROWSAFE_RELEASES_URL overrides the base, e.g. a mirror).
func stableURL() string {
	base := strings.TrimRight(os.Getenv("ROWSAFE_RELEASES_URL"), "/")
	if base == "" {
		base = "https://releases.rowsafe.sh"
	}
	return base + "/agent/stable/manifest.json"
}

const updateCheckEvery = 6 * time.Hour

// updates is the newest stable release seen.
type updates struct {
	mu    sync.Mutex
	offer *protocol.UpdateOffer
	http  *http.Client
}

func (u *updates) current() *protocol.UpdateOffer {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.offer
}

// check fetches the stable manifest and its signature.
func (u *updates) check(ctx context.Context) error {
	url := stableURL()
	manifest, err := fetch(ctx, u.http, url)
	if err != nil {
		return err
	}
	sig, err := fetch(ctx, u.http, url+".sig")
	if err != nil {
		return err
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return fmt.Errorf("reading %s: %w", url, err)
	}
	v, err := release.ParseVersion(m.Version)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	signature := strings.TrimSpace(string(sig))
	if _, err := base64.StdEncoding.DecodeString(signature); err != nil {
		return fmt.Errorf("%s.sig is not base64", url)
	}
	u.mu.Lock()
	u.offer = &protocol.UpdateOffer{Version: v.String(), Manifest: string(manifest), Signature: signature}
	u.mu.Unlock()
	return nil
}

func fetch(ctx context.Context, h *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// offerFor is the update to offer an agent on version running ("" when it
// is up to date, or the version can't be read: a build from source).
func (u *updates) offerFor(running string) *protocol.UpdateOffer {
	o := u.current()
	if o == nil {
		return nil
	}
	cur, err := release.ParseVersion(running)
	if err != nil {
		return nil
	}
	next, err := release.ParseVersion(o.Version)
	if err != nil || next.Compare(cur) <= 0 {
		return nil
	}
	return o
}

// runUpdates checks for a newer stable release now and every few hours.
func (s *Server) runUpdates(ctx context.Context) {
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err := s.updates.check(cctx); err != nil {
			s.log.Warn("checking for agent updates", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(updateCheckEvery):
		}
	}
}
