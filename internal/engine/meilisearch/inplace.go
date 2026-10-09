package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind in place, through Meilisearch itself and without a restart:
//
//  1. the snapshot is started as a temporary Meilisearch on 127.0.0.1, and
//     its indexes are renamed there to rowsafe-restore-<x>-<uid>;
//  2. it exports them into production (Meilisearch's own export, with a
//     key made for this alone: only those names, for a few hours), so
//     production builds them next to the live indexes, which go on
//     answering;
//  3. one swap of indexes, which Meilisearch applies at once, puts every
//     restored index in place: the live one takes its temporary name;
//     indexes the snapshot didn't have are renamed aside, indexes only the
//     snapshot had are renamed in.
//
// The indexes as they were stay in production under the temporary names
// until Undo (the same swap again) or the end of KeepDays. API keys are left
// as they are (keys name indexes, which keep their names).

// Kept record phases (agent.KeptRecord.Phase).
const (
	phaseCopying = "copying" // restored indexes are being exported under temporary names
	phaseSwapped = "swapped" // the swap is done
)

// restorePrefix is the temporary names' prefix for a rewind.
func restorePrefix(rewindID string) string {
	sum := sha256.Sum256([]byte(rewindID))
	return protocol.MeilisearchRestorePrefix + hex.EncodeToString(sum[:4]) + "-"
}

// swapPlan is what the swap does, per index.
type swapPlan struct {
	Swapped []string // in both: swapped with its temporary twin
	Added   []string // only in the snapshot: renamed in
	Removed []string // only in production: renamed aside
}

func (sp swapPlan) request(prefix string, undo bool) []map[string]any {
	var out []map[string]any
	for _, uid := range sp.Swapped {
		out = append(out, map[string]any{"indexes": []string{uid, prefix + uid}})
	}
	for _, uid := range sp.Added {
		from, to := prefix+uid, uid
		if undo {
			from, to = uid, prefix+uid
		}
		out = append(out, map[string]any{"indexes": []string{from, to}, "rename": true})
	}
	for _, uid := range sp.Removed {
		from, to := uid, prefix+uid
		if undo {
			from, to = prefix+uid, uid
		}
		out = append(out, map[string]any{"indexes": []string{from, to}, "rename": true})
	}
	return out
}

func (sp swapPlan) extra(prefix string) map[string]string {
	return map[string]string{"prefix": prefix, "swapped": strings.Join(sp.Swapped, ","), "added": strings.Join(sp.Added, ","),
		"removed": strings.Join(sp.Removed, ",")}
}

func planFromExtra(x map[string]string) (string, swapPlan) {
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	return x["prefix"], swapPlan{Swapped: split(x["swapped"]), Added: split(x["added"]), Removed: split(x["removed"])}
}

func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	kept := env.Kept()
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	pc, s, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer pc.close()
	if s.TLS {
		return nil, errors.New("Meilisearch serves TLS itself on this server, so it can't receive the restored indexes from a temporary " +
			"Meilisearch here: restore a copy and bring documents back instead")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	doc, err := pick(ctx, r, p.Target)
	if err != nil {
		return nil, err
	}
	prefix := restorePrefix(p.RewindID)
	prod, err := inspect(ctx, pc)
	if err != nil {
		return nil, err
	}
	for _, t := range prod.Temporary {
		if strings.HasPrefix(t, prefix) {
			return nil, fmt.Errorf("production already has indexes named %s*: remove them first", prefix)
		}
	}
	for _, i := range doc.Indexes {
		if len(prefix+i.UID) > 400 {
			return nil, fmt.Errorf("the index name %s is too long to set aside under a temporary name", i.UID)
		}
	}
	taken := doc.TakenAt
	keepDays := p.KeepDays
	if keepDays <= 0 {
		keepDays = 7
	}
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		RecoveredTo: &taken, Target: p.Target, KeepDays: keepDays, Phase: phaseCopying, Database: db,
		Extra: map[string]string{"prefix": prefix}}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: &taken}
	fail := func(err error) (*protocol.RewindInPlaceResult, error) {
		// Nothing was swapped: production is as it was. The temporary
		// indexes go.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
		defer cancel()
		if n := deletePrefixed(cctx, pc, prefix); n > 0 {
			tl.Printf("removed the %s copied so far; production was not changed", plural(int64(n), "temporary index", "temporary indexes"))
		}
		_ = kept.Remove(p.RewindID)
		res.RolledBack = true
		res.DurationMs = time.Since(start).Milliseconds()
		return res, err
	}

	e.copyMu.Lock()
	sc, err := restoreScratch(ctx, env, r, s, doc, copyRoot(env), "inplace-"+p.RewindID, tl)
	e.copyMu.Unlock()
	if err != nil {
		return fail(err)
	}
	defer func() {
		sc.stop()
		_ = sc.remove()
	}()
	sc2 := sc.client()
	defer sc2.close()
	snap, err := inspect(ctx, sc2)
	if err != nil {
		return fail(err)
	}

	// 1. Temporary names in the temporary instance.
	var renames []map[string]any
	for _, i := range snap.Indexes {
		renames = append(renames, map[string]any{"indexes": []string{i.UID, prefix + i.UID}, "rename": true})
	}
	if len(renames) > 0 {
		t, err := sc2.enqueue(ctx, http.MethodPost, "/swap-indexes", nil, renames)
		if err == nil {
			_, err = sc2.waitTask(ctx, t, 10*time.Minute)
		}
		if err != nil {
			return fail(fmt.Errorf("renaming the restored indexes: %w", err))
		}

		// 2. Export into production with a key for those names only.
		name, desc := "Rowsafe rewind "+p.RewindID, "Rowsafe: copies the restored indexes into place for a rewind; removed afterwards."
		exp := time.Now().Add(6 * time.Hour).UTC()
		tk, err := pc.createKey(ctx, apiKey{Name: &name, Description: &desc, ExpiresAt: &exp, Indexes: []string{prefix + "*"},
			Actions: []string{"indexes.create", "indexes.get", "indexes.update", "documents.add", "settings.update", "settings.get", "tasks.get"}})
		if err != nil {
			return fail(fmt.Errorf("making a key for the copy: %w", err))
		}
		defer func() { _ = pc.deleteKey(context.WithoutCancel(ctx), tk.UID) }()
		tl.Printf("copying %s (%s) into production under temporary names; production keeps answering meanwhile",
			plural(int64(len(snap.Indexes)), "index", "indexes"), plural(snap.documents(), "document", "documents"))
		body := map[string]any{"url": "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(s.localPort())), "apiKey": tk.Key,
			"indexes": map[string]any{prefix + "*": map[string]any{"overrideSettings": true}}}
		t, err = sc2.enqueue(ctx, http.MethodPost, "/export", nil, body)
		if err == nil {
			_, err = sc2.waitTask(ctx, t, 24*time.Hour)
		}
		if err != nil {
			return fail(fmt.Errorf("copying the restored indexes into production: %w", err))
		}
		var tmp []string
		for _, i := range snap.Indexes {
			tmp = append(tmp, prefix+i.UID)
		}
		if err := pc.waitIdle(ctx, tmp, 24*time.Hour); err != nil {
			return fail(fmt.Errorf("waiting for production to index the restored documents: %w", err))
		}
		got, err := pc.stats(ctx)
		if err != nil {
			return fail(err)
		}
		for _, i := range snap.Indexes {
			if n := got.Indexes[prefix+i.UID].NumberOfDocuments; n != i.Stats.NumberOfDocuments {
				return fail(fmt.Errorf("production indexed %s of the index %s, the snapshot has %s", plural(n, "document", "documents"),
					i.UID, commas(i.Stats.NumberOfDocuments)))
			}
		}
	}

	// 3. One swap puts everything in place.
	var sp swapPlan
	inProd := map[string]bool{}
	for _, i := range prod.Indexes {
		inProd[i.UID] = true
	}
	inSnap := map[string]bool{}
	for _, i := range snap.Indexes {
		inSnap[i.UID] = true
		if inProd[i.UID] {
			sp.Swapped = append(sp.Swapped, i.UID)
		} else {
			sp.Added = append(sp.Added, i.UID)
		}
	}
	// Indexes created since the snapshot (re-read: one may have appeared).
	now, err := inspect(ctx, pc)
	if err != nil {
		return fail(err)
	}
	for _, i := range now.Indexes {
		if !inSnap[i.UID] {
			sp.Removed = append(sp.Removed, i.UID)
		} else if !inProd[i.UID] {
			sp.Added = slices.DeleteFunc(sp.Added, func(u string) bool { return u == i.UID })
			sp.Swapped = append(sp.Swapped, i.UID)
		}
	}
	rec.Phase, rec.Extra = phaseCopying, sp.extra(prefix)
	_ = kept.Put(rec)
	if req := sp.request(prefix, false); len(req) > 0 {
		t, err := pc.enqueue(ctx, http.MethodPost, "/swap-indexes", nil, req)
		if err == nil {
			_, err = pc.waitTask(ctx, t, time.Hour)
		}
		if err != nil {
			return fail(fmt.Errorf("swapping the restored indexes into place: %w", err))
		}
	}
	until := agent.KeepUntil(keepDays, time.Now())
	rec.Status, rec.Phase, rec.Expires = protocol.RewindKeptBefore, phaseSwapped, until
	rec.SizeBytes = prefixedSize(ctx, pc, prefix)
	if err := kept.Put(rec); err != nil {
		tl.Printf("note: recording the kept indexes failed (%v)", err)
	}
	res.KeptUntil = &until
	res.OldDataDir = "the indexes as they were, in Meilisearch as " + prefix + "<index>"
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s is back to %s (snapshot %s): %s put in place at once, without a restart. "+
		"The indexes as they were are kept until %s for Undo.", db.Name, taken.Format("2006-01-02 15:04:05 UTC"), doc.Label,
		plural(int64(len(sp.Swapped)+len(sp.Added)), "index", "indexes"), until.Format("2006-01-02"))
	if len(sp.Removed) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s created after the snapshot (%s) set aside with the rest, until Undo or %s.",
			plural(int64(len(sp.Removed)), "index", "indexes"), joinAnd(firstN(sp.Removed, 5)), until.Format("2006-01-02")))
	}
	res.Warnings = append(res.Warnings, "API keys were left as they are.")
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rewindUndo swaps back: the indexes from before the rewind return, the
// rewound ones take the temporary names (kept until the same expiry).
func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, fmt.Errorf("nothing is kept from the rewind %s on this server (it expired or was cleaned up)", p.RewindID)
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, fmt.Errorf("the rewind %s can't be undone now (%s)", p.RewindID, rec.Status)
	}
	pc, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer pc.close()
	prefix, sp := planFromExtra(rec.Extra)
	if req := sp.request(prefix, true); len(req) > 0 {
		t, err := pc.enqueue(ctx, http.MethodPost, "/swap-indexes", nil, req)
		if err == nil {
			_, err = pc.waitTask(ctx, t, time.Hour)
		}
		if err != nil {
			return nil, fmt.Errorf("swapping the indexes back: %w", err)
		}
	}
	rec.Status, rec.Undo = protocol.RewindKeptAfterUndo, true
	rec.SizeBytes = prefixedSize(ctx, pc, prefix)
	_ = kept.Put(rec)
	exp := rec.Expires
	res := &protocol.RewindUndoResult{RewindID: p.RewindID, RewoundDataDir: "the rewound indexes, in Meilisearch as " + prefix + "<index>",
		KeptUntil: &exp, DurationMs: time.Since(start).Milliseconds()}
	res.Summary = fmt.Sprintf("Undone: %s is as it was before the rewind. The rewound indexes are kept until %s.", db.Name, exp.Format("2006-01-02"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	res := &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept any more."}
	if !ok {
		return res, nil
	}
	if rec.DatabaseID != db.ID {
		return nil, fmt.Errorf("the rewind %s isn't this database's", p.RewindID)
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	pc, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer pc.close()
	prefix, _ := planFromExtra(rec.Extra)
	res.FreedBytes = prefixedSize(ctx, pc, prefix)
	n := deletePrefixed(ctx, pc, prefix)
	if err := kept.Remove(p.RewindID); err != nil {
		return nil, err
	}
	res.Removed = true
	res.Summary = fmt.Sprintf("Removed the %s kept from the rewind (%s freed).", plural(int64(n), "index", "indexes"), humanBytes(res.FreedBytes))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// expireKept deletes kept indexes past their expiry, and finishes rewinds
// an agent restart interrupted before the swap (nothing was swapped: the
// temporary indexes go).
func (e *Engine) expireKept(ctx context.Context, env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		interrupted := rec.Status == protocol.RewindInProgress && rec.Phase == phaseCopying && now.Sub(rec.CreatedAt) > 25*time.Hour
		expired := rec.Status != protocol.RewindInProgress && !rec.Expires.IsZero() && now.After(rec.Expires)
		if !interrupted && !expired {
			continue
		}
		db := rec.Database
		pc, _, err := connect(ctx, env, db)
		if err != nil {
			continue
		}
		prefix, _ := planFromExtra(rec.Extra)
		n := deletePrefixed(ctx, pc, prefix)
		pc.close()
		_ = kept.Remove(rec.ID)
		env.Log.Info("removed the indexes kept from a rewind", "rewind_id", rec.ID, "indexes", n)
	}
}

// deletePrefixed deletes production's indexes named prefix* (Rowsafe's
// temporary ones only) and returns how many.
func deletePrefixed(ctx context.Context, c *client, prefix string) int {
	if !strings.HasPrefix(prefix, protocol.MeilisearchRestorePrefix) || len(prefix) <= len(protocol.MeilisearchRestorePrefix) {
		return 0
	}
	idx, err := c.indexes(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, i := range idx {
		if !strings.HasPrefix(i.UID, prefix) {
			continue
		}
		t, err := c.enqueue(ctx, http.MethodDelete, "/indexes/"+i.UID, nil, nil)
		if err == nil {
			_, err = c.waitTask(ctx, t, 10*time.Minute)
		}
		if err == nil {
			n++
		}
	}
	return n
}

func prefixedSize(ctx context.Context, c *client, prefix string) int64 {
	st, err := c.stats(ctx)
	if err != nil {
		return 0
	}
	var n int64
	for uid, s := range st.Indexes {
		if strings.HasPrefix(uid, prefix) {
			n += s.IndexSize
		}
	}
	return n
}
