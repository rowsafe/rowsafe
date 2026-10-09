package qdrant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The keys made in Databases & users, and why removing one holds.
//
// A key's token is valid only while a point in Rowsafe's collection
// (protocol.QdrantKeysCollection) holds its name and nonce (Qdrant's
// value_exists). That collection lives in Qdrant, where an admin token (or
// the server's own api_key) can write it, so it can't be the record of which
// keys exist. The record is the agent's own list (keyList), in its state
// directory, readable and writable only by the agent: reconcile makes the
// collection match it exactly, deleting every point the list doesn't hold
// (unknown names, another nonce, a second point for a name) and writing back
// the ones that went missing. It runs before and after every change, on
// every list, on the security check and on every monitoring pass.
//
// Read-only and read-write tokens can't write the collection, so removing
// one ends it at once. An admin token can, between two passes: admin keys
// therefore always expire (Qdrant checks the token's exp itself), and what
// reconcile undoes is reported (protocol.QdrantKeyRepair) for Pulse.

// keyEntry is one key the agent made.
type keyEntry struct {
	Name        string     `json:"name"`
	Nonce       string     `json:"nonce"`
	Access      string     `json:"access"`
	Collections []string   `json:"collections,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresDays int        `json:"expires_days,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func (k keyEntry) admin() bool { return k.Access == protocol.DBAccessOwner }

func (k keyEntry) expired(now time.Time) bool { return k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) }

// keyList is the agent's record of the keys on one server.
type keyList struct {
	Keys []keyEntry `json:"keys"`
	// Repair is the last time reconcile undid someone else's change.
	Repair *protocol.QdrantKeyRepair `json:"repair,omitempty"`
}

func (l *keyList) find(name string) int {
	return slices.IndexFunc(l.Keys, func(k keyEntry) bool { return k.Name == name })
}

func (l keyList) adminCount() int {
	n := 0
	for _, k := range l.Keys {
		if k.admin() {
			n++
		}
	}
	return n
}

// keysMu serializes changes to every server's list and collection.
var keysMu sync.Mutex

func keysDir(env agent.EngineEnv) string { return filepath.Join(env.SharedStateDir(), "keys") }

func keyListPath(env agent.EngineEnv, port int) string {
	return filepath.Join(keysDir(env), strconv.Itoa(port)+".json")
}

// loadKeyList reads the list (ok false: there is none yet).
func loadKeyList(env agent.EngineEnv, port int) (keyList, bool, error) {
	var l keyList
	data, err := os.ReadFile(keyListPath(env, port))
	if errors.Is(err, os.ErrNotExist) {
		return l, false, nil
	}
	if err != nil {
		return l, false, err
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return l, false, fmt.Errorf("reading Rowsafe's list of Qdrant keys: %w", err)
	}
	return l, true, nil
}

func saveKeyList(env agent.EngineEnv, port int, l keyList) error {
	if err := os.MkdirAll(keysDir(env), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(l, "", "  ")
	f, err := os.CreateTemp(keysDir(env), ".keys-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, keyListPath(env, port))
}

// keyPointID is a key's point: a UUID made from its name.
func keyPointID(name string) string {
	h := sha256.Sum256([]byte("rowsafe-key:" + name))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x50 // version 5-like
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureKeysCollection creates Rowsafe's keys collection (no vectors) and
// its payload indexes when missing.
func ensureKeysCollection(ctx context.Context, c *client) error {
	_, err := c.collection(ctx, protocol.QdrantKeysCollection)
	if err == nil {
		return nil
	}
	if !isStatus(err, http.StatusNotFound) {
		return err
	}
	if err := c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection), nil,
		map[string]any{"vectors": map[string]any{}, "on_disk_payload": false}, nil); err != nil {
		return fmt.Errorf("creating Rowsafe's keys collection: %w", err)
	}
	for _, f := range []string{"key", "nonce"} {
		if err := c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection)+"/index", url.Values{"wait": {"true"}},
			map[string]any{"field_name": f, "field_schema": "keyword"}, nil); err != nil {
			return err
		}
	}
	return nil
}

// keyPoint is one point of the keys collection as Qdrant holds it.
type keyPoint struct {
	ID    json.RawMessage // a UUID string or a number: sent back as is
	Key   string
	Nonce string
}

func (p keyPoint) id() string {
	var s string
	if json.Unmarshal(p.ID, &s) == nil {
		return s
	}
	return string(p.ID)
}

// keyPointsPage caps one scroll request.
const keyPointsPage = 256

// keyPoints reads every point of the keys collection, page by page (nil,
// false: there is no collection).
func keyPoints(ctx context.Context, c *client) ([]keyPoint, bool, error) {
	var out []keyPoint
	var offset json.RawMessage
	for range 10_000 {
		body := map[string]any{"limit": keyPointsPage, "with_payload": true, "with_vector": false}
		if len(offset) > 0 && string(offset) != "null" {
			body["offset"] = offset
		}
		var page struct {
			Points []struct {
				ID      json.RawMessage `json:"id"`
				Payload map[string]any  `json:"payload"`
			} `json:"points"`
			Next json.RawMessage `json:"next_page_offset"`
		}
		err := c.call(ctx, http.MethodPost, collPath(protocol.QdrantKeysCollection)+"/points/scroll", nil, body, &page)
		if isStatus(err, http.StatusNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, true, err
		}
		for _, p := range page.Points {
			kp := keyPoint{ID: p.ID}
			kp.Key, _ = p.Payload["key"].(string)
			kp.Nonce, _ = p.Payload["nonce"].(string)
			out = append(out, kp)
		}
		if len(page.Next) == 0 || string(page.Next) == "null" {
			return out, true, nil
		}
		offset = page.Next
	}
	return out, true, errors.New("Rowsafe's keys collection has too many points to read")
}

// putKeyPoints writes the keys' points (their name and nonce only).
func putKeyPoints(ctx context.Context, c *client, keys []keyEntry) error {
	if len(keys) == 0 {
		return nil
	}
	var pts []any
	for _, k := range keys {
		pts = append(pts, map[string]any{"id": keyPointID(k.Name), "vector": map[string]any{},
			"payload": map[string]any{"key": k.Name, "nonce": k.Nonce}})
	}
	return c.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection)+"/points", url.Values{"wait": {"true"}},
		map[string]any{"points": pts}, nil)
}

// deleteKeyPoints deletes points by id.
func deleteKeyPoints(ctx context.Context, c *client, ids []json.RawMessage) error {
	if len(ids) == 0 {
		return nil
	}
	return c.call(ctx, http.MethodPost, collPath(protocol.QdrantKeysCollection)+"/points/delete", url.Values{"wait": {"true"}},
		map[string]any{"points": ids}, nil)
}

// deleteKeyByName deletes every point that names the key, whatever its id.
func deleteKeyByName(ctx context.Context, c *client, name string) error {
	err := c.call(ctx, http.MethodPost, collPath(protocol.QdrantKeysCollection)+"/points/delete", url.Values{"wait": {"true"}},
		map[string]any{"filter": map[string]any{"must": []any{map[string]any{"key": "key", "match": map[string]any{"value": name}}}}}, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// reconcileResult is what reconcile did.
type reconcileResult struct {
	Removed  int
	Restored int
	Keys     []string // the keys the removed or restored entries named
	Expired  []string // keys past their expiry, dropped from the list
}

// reconcile makes the keys collection match the agent's list, under
// keysMu. With no list yet (a new agent) there are no keys: every point is
// removed. The list is the only record (it is never rebuilt from Qdrant)
// list (none: no key exists). Keys past their expiry leave the list. Every
// change by someone else is recorded in the list's Repair for Pulse.
func reconcile(ctx context.Context, env agent.EngineEnv, port int, c *client) (keyList, reconcileResult, error) {
	keysMu.Lock()
	defer keysMu.Unlock()
	return reconcileLocked(ctx, env, port, c)
}

func reconcileLocked(ctx context.Context, env agent.EngineEnv, port int, c *client) (keyList, reconcileResult, error) {
	var res reconcileResult
	l, exists, err := loadKeyList(env, port)
	if err != nil {
		return l, res, err
	}
	points, haveColl, err := keyPoints(ctx, c)
	if err != nil {
		return l, res, err
	}
	now := time.Now().UTC()
	// No list yet: no key exists. Points already in the collection are never
	// taken as keys (anyone with an admin key could have written them).
	changed := !exists
	// Expired keys: Qdrant refuses their tokens already; they leave the list.
	kept := l.Keys[:0]
	for _, k := range l.Keys {
		if k.expired(now) {
			res.Expired = append(res.Expired, k.Name)
			changed = true
			continue
		}
		kept = append(kept, k)
	}
	l.Keys = kept
	want := map[string]keyEntry{}
	for _, k := range l.Keys {
		want[keyPointID(k.Name)] = k
	}
	var strays []json.RawMessage
	good := map[string]bool{}
	for _, p := range points {
		k, ok := want[p.id()]
		if ok && p.Key == k.Name && p.Nonce == k.Nonce {
			good[k.Name] = true
			continue
		}
		strays = append(strays, p.ID)
		if !slices.Contains(res.Expired, p.Key) {
			res.Removed++
			if p.Key != "" && !slices.Contains(res.Keys, p.Key) {
				res.Keys = append(res.Keys, p.Key)
			}
		}
	}
	var missing []keyEntry
	for _, k := range l.Keys {
		if !good[k.Name] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 && !haveColl {
		if err := ensureKeysCollection(ctx, c); err != nil {
			return l, res, err
		}
	}
	if err := deleteKeyPoints(ctx, c, strays); err != nil {
		return l, res, fmt.Errorf("removing entries Rowsafe didn't write from its list of keys: %w", err)
	}
	if err := putKeyPoints(ctx, c, missing); err != nil {
		return l, res, fmt.Errorf("writing back Rowsafe's list of keys: %w", err)
	}
	if exists {
		// A key written back was changed or deleted by someone else; on a
		// new list nothing is "back" (it is the first write).
		res.Restored = len(missing)
		for _, k := range missing {
			if !slices.Contains(res.Keys, k.Name) {
				res.Keys = append(res.Keys, k.Name)
			}
		}
	}
	if res.Removed > 0 || res.Restored > 0 {
		names := res.Keys
		if len(names) > 20 {
			names = names[:20]
		}
		l.Repair = &protocol.QdrantKeyRepair{At: now, Removed: res.Removed, Restored: res.Restored, Keys: slices.Clone(names), AdminKeys: l.adminCount()}
		changed = true
	}
	if changed {
		if err := saveKeyList(env, port, l); err != nil {
			return l, res, err
		}
	}
	return l, res, nil
}

// repairReported is how long a repair stays in the monitoring status.
const repairReported = 7 * 24 * time.Hour

// recentRepair is the list's last repair while it is reported.
func recentRepair(l keyList, now time.Time) *protocol.QdrantKeyRepair {
	if l.Repair == nil || now.Sub(l.Repair.At) > repairReported {
		return nil
	}
	r := *l.Repair
	return &r
}

// keyClaims are the token's claims for k.
func keyClaims(k keyEntry) map[string]any {
	var access any
	switch {
	case k.admin():
		access = "m"
	case len(k.Collections) == 0:
		access = "r"
	default:
		mode := "r"
		if k.Access == protocol.DBAccessReadWrite {
			mode = "rw"
		}
		var list []map[string]any
		for _, c := range k.Collections {
			list = append(list, map[string]any{"collection": c, "access": mode})
		}
		access = list
	}
	claims := map[string]any{
		"access":  access,
		"subject": k.Name,
		"value_exists": map[string]any{"collection": protocol.QdrantKeysCollection,
			"matches": []map[string]any{{"key": "key", "value": k.Name}, {"key": "nonce", "value": k.Nonce}}},
	}
	if k.ExpiresAt != nil {
		claims["exp"] = k.ExpiresAt.Unix()
	}
	return claims
}

func accessWords(k keyEntry) string {
	switch {
	case k.admin():
		return "admin access to every collection"
	case len(k.Collections) == 0:
		return "read-only access to every collection"
	case k.Access == protocol.DBAccessReadWrite:
		return "read-write access to " + strings.Join(k.Collections, ", ")
	}
	return "read-only access to " + strings.Join(k.Collections, ", ")
}

// expiryDays is how long a key's token lasts: asked, kept from the key, or
// QdrantAdminKeyDefaultDays for admin keys (0: never).
func expiryDays(k keyEntry, asked int) (int, error) {
	d := asked
	if d == 0 {
		d = k.ExpiresDays
	}
	if k.admin() {
		if d == 0 {
			d = protocol.QdrantAdminKeyDefaultDays
		}
		if d > protocol.QdrantAdminKeyMaxDays {
			return 0, fmt.Errorf("an admin key expires within %d days", protocol.QdrantAdminKeyMaxDays)
		}
	}
	if d < 0 || d > protocol.QdrantKeyMaxDays {
		return 0, fmt.Errorf("a key expires in 1 to %d days", protocol.QdrantKeyMaxDays)
	}
	return d, nil
}

func dateWords(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2 January 2006, 15:04 UTC")
}
