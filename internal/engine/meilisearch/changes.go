package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"time"
)

// Meilisearch's snapshots are whole copies (it has nothing incremental), so
// the cheap part is not taking one when nothing changed. Every change to
// indexes, documents and settings is a task with a growing uid; API keys
// change outside tasks. A snapshot holds everything the tasks before its
// own did: when the newest task is still that snapshot's own and the keys
// are the same, the instance holds exactly what the snapshot holds.

// changeMark identifies a state of the instance.
type changeMark struct {
	// TaskUID and TaskEnqueuedAt are the snapshot's own task (enqueued at
	// tells instances apart: a task uid alone repeats after a restore).
	TaskUID        int64  `json:"task_uid"`
	TaskEnqueuedAt string `json:"task_enqueued_at"`
	// Keys is a fingerprint of the API keys (never their values).
	Keys string `json:"keys"`
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
// snapshot marked m holds: its task is the newest and the keys are the same.
// keys is keysMark now.
func unchangedSince(ctx context.Context, c *client, m *changeMark, keys string) bool {
	if m == nil || m.TaskUID < 0 || m.TaskEnqueuedAt == "" || keys == "" || m.Keys != keys {
		return false
	}
	uid, at, err := c.newestTask(ctx)
	return err == nil && uid == m.TaskUID && at == m.TaskEnqueuedAt
}
