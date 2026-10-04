package redis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Copying keys from one server to another (clones, moving a database in):
// SCAN on the source, DUMP and PTTL of each key, RESTORE on the target with
// its remaining time to live, a batch at a time, so memory stays bounded by
// one batch. Where it got to (logical database and SCAN cursor) is handed
// to a callback after every batch: a copy that stops continues from there
// (SCAN returns every key that existed the whole time at least once, so
// nothing is missed; a key seen twice is restored again).

// copyPos is where a key copy is: the logical database and SCAN cursor.
type copyPos struct {
	DB     int    `json:"db"`
	Cursor string `json:"cursor"`
	Done   bool   `json:"done,omitempty"`
}

// copyOpts shape a key copy.
type copyOpts struct {
	// DBs are the logical databases to copy, in order.
	DBs []int
	// From is where to start (a copy that stopped); zero: the beginning.
	From copyPos
	// Replace overwrites keys the target already has (a resumed copy, a
	// final pass); without it a key already there is an error.
	Replace bool
	// Batch is the keys per round trip (default 200).
	Batch int
	// Saved is called with the position after every batch.
	Saved func(copyPos, int64)
	// Throttle, when set, is waited after every batch (to spare a busy
	// source).
	Throttle time.Duration
}

// copyStats is what a key copy did.
type copyStats struct {
	Keys    int64
	Expired int64 // gone between SCAN and DUMP
	Bytes   int64 // DUMP payloads
}

var errBusyKey = errors.New("BUSYKEY")

// copyKeys copies every key of o.DBs from src to dst.
func copyKeys(ctx context.Context, src, dst *conn, o copyOpts) (copyStats, error) {
	var st copyStats
	batch := o.Batch
	if batch <= 0 {
		batch = 200
	}
	src.timeout, dst.timeout = 5*time.Minute, 5*time.Minute
	defer func() { src.timeout, dst.timeout = defaultIOTTL, defaultIOTTL }()
	started := o.From.DB < 0 || !slices.Contains(o.DBs, o.From.DB)
	for _, n := range o.DBs {
		cursor := "0"
		if !started {
			if n != o.From.DB {
				continue
			}
			started = true
			if o.From.Done {
				continue
			}
			cursor = cmpOr(o.From.Cursor, "0")
		}
		if _, err := src.do(ctx, "SELECT", n); err != nil {
			return st, err
		}
		if _, err := dst.do(ctx, "SELECT", n); err != nil {
			return st, fmt.Errorf("the target has no logical database %d (its databases setting is lower): %w", n, err)
		}
		for {
			v, err := src.do(ctx, "SCAN", cursor, "COUNT", batch)
			if err != nil {
				return st, err
			}
			parts := asArray(v)
			if len(parts) != 2 {
				return st, errors.New("unexpected SCAN reply")
			}
			next := asString(parts[0])
			keys := asArray(parts[1])
			if len(keys) > 0 {
				if err := copyBatch(ctx, src, dst, keys, o.Replace, &st); err != nil {
					return st, err
				}
			}
			cursor = next
			pos := copyPos{DB: n, Cursor: cursor, Done: cursor == "0"}
			if o.Saved != nil {
				o.Saved(pos, st.Keys)
			}
			if cursor == "0" {
				break
			}
			if err := ctx.Err(); err != nil {
				return st, err
			}
			if o.Throttle > 0 {
				select {
				case <-ctx.Done():
					return st, ctx.Err()
				case <-time.After(o.Throttle):
				}
			}
		}
	}
	_, _ = src.do(ctx, "SELECT", 0)
	_, _ = dst.do(ctx, "SELECT", 0)
	return st, nil
}

// copyBatch moves one batch of keys.
func copyBatch(ctx context.Context, src, dst *conn, keys []any, replace bool, st *copyStats) error {
	cmds := make([][]any, 0, 2*len(keys))
	for _, k := range keys {
		key := asString(k)
		cmds = append(cmds, []any{"PTTL", key}, []any{"DUMP", key})
	}
	replies, errs, err := src.pipeline(ctx, cmds)
	if err != nil {
		return err
	}
	var restores [][]any
	for i, k := range keys {
		if errs[2*i] != nil {
			return errs[2*i]
		}
		if errs[2*i+1] != nil {
			return fmt.Errorf("reading a key: %w", errs[2*i+1])
		}
		ttl := asInt(replies[2*i])
		payload := replies[2*i+1]
		if ttl == -2 || payload == nil {
			st.Expired++
			continue
		}
		if ttl < 0 {
			ttl = 0
		}
		p := asString(payload)
		st.Bytes += int64(len(p))
		args := []any{"RESTORE", asString(k), ttl, p}
		if replace {
			args = append(args, "REPLACE")
		}
		restores = append(restores, args)
	}
	if len(restores) == 0 {
		return nil
	}
	_, rerrs, err := dst.pipeline(ctx, restores)
	if err != nil {
		return err
	}
	for _, e := range rerrs {
		switch {
		case e == nil:
			st.Keys++
		case isRespError(e, "BUSYKEY"):
			return fmt.Errorf("%w: the target already holds some of these keys; it must be empty", errBusyKey)
		case strings.Contains(e.Error(), "payload version or checksum are wrong"), strings.Contains(e.Error(), "Bad data format"):
			return fmt.Errorf("the target can't read the source's data (%s): it must run the same version as the source or newer, with the same modules", firstLine(e.Error()))
		case isRespError(e, "OOM"):
			return fmt.Errorf("the target ran out of memory (its maxmemory) after %s keys: give it more memory, then start again", commas(st.Keys))
		default:
			return fmt.Errorf("writing a key to the target: %w", e)
		}
	}
	return nil
}
