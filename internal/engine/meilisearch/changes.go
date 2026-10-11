package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"
)

// Meilisearch's snapshots are whole copies (it has nothing incremental), so
// the cheap part is not taking one when nothing changed. Every change to
// indexes, documents and settings is a task with a growing uid; API keys,
// experimental features, webhooks, the network and chat workspaces' settings
// change outside tasks. A snapshot holds everything the tasks before its own
// did: when the newest task is still that snapshot's own and the rest is the
// same, the instance holds exactly what the snapshot holds. A snapshot is
// named again for a day at most (reuseMaxAge).

// changeMark identifies a state of the instance.
type changeMark struct {
	// TaskUID and TaskEnqueuedAt are the snapshot's own task (enqueued at
	// tells instances apart: a task uid alone repeats after a restore).
	TaskUID        int64  `json:"task_uid"`
	TaskEnqueuedAt string `json:"task_enqueued_at"`
	// Keys is a fingerprint of the API keys (never their values).
	Keys string `json:"keys"`
	// Settings is a fingerprint of what else changes outside tasks
	// (instanceSettingsMark; never the settings themselves).
	Settings string `json:"settings,omitempty"`
}

// reuseMaxAge: a snapshot is named again by later backups at most this long
// after it was taken; then a new one is taken even if nothing seems to have
// changed (what no fingerprint sees, and bucket lifecycle rules never meet
// an old object a new backup still names).
const reuseMaxAge = 24 * time.Hour

// instanceSettings are what changes outside tasks and is in a snapshot,
// besides the API keys: read for a fingerprint only.
var instanceSettings = []string{"/experimental-features", "/network", "/webhooks"}

// instanceSettingsMark fingerprints the experimental features, the network,
// the webhooks and every chat workspace's settings. A route the instance
// lacks or keeps off (an older Meilisearch, a feature not turned on)
// counts as its answer; one Rowsafe's key may not read (a key made before
// Rowsafe read them: the installer makes a new one) counts the same each
// time, and reuseMaxAge bounds what that can miss.
func instanceSettingsMark(ctx context.Context, c *client) string {
	part := func(path string) any {
		var v any
		if err := c.do(ctx, "GET", path, nil, nil, &v); err != nil {
			var ae *apiError
			if errors.As(err, &ae) {
				return fmt.Sprintf("%d %s", ae.Status, ae.Code)
			}
			return nil
		}
		return v
	}
	all := map[string]any{}
	for _, p := range instanceSettings {
		v := part(p)
		if v == nil {
			return "" // unreadable this time: no fingerprint
		}
		all[p] = v
	}
	chats := part("/chats")
	if chats == nil {
		return ""
	}
	all["/chats"] = chats
	if m, ok := chats.(map[string]any); ok {
		res, _ := m["results"].([]any)
		for i, w := range res {
			ws, _ := w.(map[string]any)
			uid, _ := ws["uid"].(string)
			if i >= 50 || uid == "" {
				continue
			}
			path := "/chats/" + url.PathEscape(uid) + "/settings"
			v := part(path)
			if v == nil {
				return ""
			}
			all[path] = v
		}
	}
	b, err := json.Marshal(all) // map keys come out sorted
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newestTask is the instance's newest task (uid -1 when it has none).
func (c *client) newestTask(ctx context.Context) (int64, string, error) {
	ts, _, err := c.taskPage(ctx, url.Values{"limit": {"1"}})
	if err != nil || len(ts) == 0 {
		return -1, "", err
	}
	return ts[0].id(), enqueuedText(ts[0].EnqueuedAt), nil
}

func enqueuedText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// keysMark fingerprints the API keys: their uid, rights and when they last
// changed, never their values. "" when they can't be read.
func keysMark(ctx context.Context, c *client, s server) string {
	if s.Key == "" {
		return "no keys" // no master key: no keys either
	}
	keys, err := c.keys(ctx)
	if err != nil {
		return ""
	}
	type k struct {
		UID     string     `json:"u"`
		Name    *string    `json:"n"`
		Desc    *string    `json:"d"`
		Actions []string   `json:"a"`
		Indexes []string   `json:"i"`
		Expires *time.Time `json:"e"`
		Updated *time.Time `json:"t"`
	}
	list := make([]k, 0, len(keys))
	for _, key := range keys {
		list = append(list, k{key.UID, key.Name, key.Description, key.Actions, key.Indexes, key.ExpiresAt, key.UpdatedAt})
	}
	slices.SortFunc(list, func(a, b k) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// unchangedSince reports whether the instance still holds exactly what the
// snapshot marked m holds: its task is the newest and the keys and the
// other settings are the same. keys and settings are keysMark and
// instanceSettingsMark now.
func unchangedSince(ctx context.Context, c *client, m *changeMark, keys, settings string) bool {
	if m == nil || m.TaskUID < 0 || m.TaskEnqueuedAt == "" || keys == "" || m.Keys != keys || settings == "" || m.Settings != settings {
		return false
	}
	uid, at, err := c.newestTask(ctx)
	return err == nil && uid == m.TaskUID && at == m.TaskEnqueuedAt
}
