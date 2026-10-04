package redis

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// The replication handshake, as a replica does it (and `redis-cli --rdb`):
//
//	REPLCONF listening-port 0, ip-address rowsafe-agent, capa eof psync2
//	PSYNC <replid> <offset>  ->  +FULLRESYNC <replid> <offset>, then a snapshot
//	                         or  +CONTINUE [<replid>], then the stream
//
// "capa eof" lets the server stream the snapshot straight from memory to
// the agent (diskless), so it never writes a file on the server's disk for
// Rowsafe.

// errReplicationRefused: the server won't let Rowsafe's user replicate
// (PSYNC/SYNC renamed or not allowed by its ACL).
var errReplicationRefused = errors.New("the server doesn't let Rowsafe follow it as a replica (its SYNC and PSYNC commands are renamed, " +
	"or Rowsafe's user isn't allowed to run them)")

// syncReply is the server's answer to PSYNC.
type syncReply struct {
	Full   bool   // +FULLRESYNC: a snapshot follows, the stream starts at Offset after it
	ReplID string // the stream's replication id
	Offset int64  // FULLRESYNC: where the snapshot is in the stream; CONTINUE: the offset asked for
}

// startSync runs the handshake and PSYNC on a signed-in connection. With
// rdbOnly the server sends the snapshot and nothing after it (Redis 7.0+;
// ignored by servers without it). replid "" asks for a whole snapshot.
func startSync(ctx context.Context, c *conn, replid string, offset int64, rdbOnly bool) (syncReply, error) {
	steps := [][]any{
		{"PING"},
		{"REPLCONF", "listening-port", "0"},
		{"REPLCONF", "ip-address", linkAddr},
		{"REPLCONF", "capa", "eof", "capa", "psync2"},
	}
	if rdbOnly {
		steps = append(steps, []any{"REPLCONF", "rdb-only", "1"})
	}
	for _, s := range steps {
		if _, err := c.do(ctx, s...); err != nil {
			if isRespError(err, "NOPERM") || isUnknownCommand(err) {
				return syncReply{}, errReplicationRefused
			}
			// An older server without rdb-only or ip-address: carry on.
			if isRespError(err) && len(s) > 1 && (s[1] == "rdb-only" || s[1] == "ip-address") {
				continue
			}
			return syncReply{}, err
		}
	}
	id, off := "?", "-1"
	if replid != "" {
		id, off = replid, strconv.FormatInt(offset+1, 10)
	}
	c.wmu.Lock()
	c.deadline(ctx)
	err := c.writeCommand("PSYNC", id, off)
	if err == nil {
		err = c.bw.Flush()
	}
	c.wmu.Unlock()
	if err != nil {
		return syncReply{}, err
	}
	// The server may send newlines to keep the link alive while it gets a
	// snapshot ready.
	_ = c.nc.SetReadDeadline(time.Now().Add(5 * time.Minute))
	if err := skipNewlines(c.br); err != nil {
		return syncReply{}, err
	}
	line, err := readLine(c.br)
	if err != nil {
		return syncReply{}, err
	}
	switch {
	case strings.HasPrefix(line, "+FULLRESYNC "):
		f := strings.Fields(line[1:])
		if len(f) != 3 || !replIDRE.MatchString(f[1]) {
			return syncReply{}, fmt.Errorf("unexpected answer to PSYNC: %q", clip(line, 80))
		}
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || n < 0 {
			return syncReply{}, fmt.Errorf("unexpected answer to PSYNC: %q", clip(line, 80))
		}
		return syncReply{Full: true, ReplID: f[1], Offset: n}, nil
	case line == "+CONTINUE" || strings.HasPrefix(line, "+CONTINUE "):
		r := syncReply{ReplID: replid, Offset: offset}
		if f := strings.Fields(line[1:]); len(f) == 2 && replIDRE.MatchString(f[1]) {
			r.ReplID = f[1] // the server's id changed (a failover), the offsets carry on
		}
		return r, nil
	case strings.HasPrefix(line, "-"):
		err := respError(line[1:])
		if isRespError(err, "NOPERM") || isUnknownCommand(err) {
			return syncReply{}, errReplicationRefused
		}
		return syncReply{}, fmt.Errorf("the server refused to send its data: %s", clip(line[1:], 200))
	}
	return syncReply{}, fmt.Errorf("unexpected answer to PSYNC: %q", clip(line, 80))
}

func isUnknownCommand(err error) bool {
	return isRespError(err, "ERR") && strings.Contains(strings.ToLower(err.Error()), "unknown command")
}

// skipNewlines discards the "\n" keepalives a server sends before a reply.
func skipNewlines(br *bufio.Reader) error {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return err
		}
		if b[0] != '\n' {
			return nil
		}
		_, _ = br.Discard(1)
	}
}

// errTooBig: the snapshot is larger than the room the agent has for it.
var errTooBig = errors.New("the snapshot is larger than the free disk space Rowsafe may use on this server")

// receiveRDB copies the snapshot that follows +FULLRESYNC into w (at most
// limit bytes) and returns its size. idle bounds the wait for each read.
func receiveRDB(ctx context.Context, c *conn, w io.Writer, limit int64, idle time.Duration) (int64, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.nc.SetReadDeadline(time.Now()) })
	defer stop()
	_ = c.nc.SetReadDeadline(time.Now().Add(idle))
	if err := skipNewlines(c.br); err != nil {
		return 0, ctxErr(ctx, err)
	}
	line, err := readLine(c.br)
	if err != nil {
		return 0, ctxErr(ctx, err)
	}
	if !strings.HasPrefix(line, "$") {
		return 0, fmt.Errorf("unexpected start of the snapshot: %q", clip(line, 80))
	}
	dr := &deadlineReader{c: c, idle: idle}
	if mark, ok := strings.CutPrefix(line, "$EOF:"); ok {
		if len(mark) != 40 {
			return 0, fmt.Errorf("unexpected start of the snapshot: %q", clip(line, 80))
		}
		n, err := copyUntilMark(w, dr, []byte(mark), limit)
		return n, ctxErr(ctx, err)
	}
	size, err := strconv.ParseInt(line[1:], 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("unexpected start of the snapshot: %q", clip(line, 80))
	}
	if size > limit {
		return 0, fmt.Errorf("%w (%s)", errTooBig, humanBytes(size))
	}
	n, err := io.CopyN(w, dr, size)
	return n, ctxErr(ctx, err)
}

func ctxErr(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// deadlineReader reads the connection, moving its read deadline forward
// before each read (a stalled server fails the copy instead of hanging it).
type deadlineReader struct {
	c    *conn
	idle time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	_ = d.c.nc.SetReadDeadline(time.Now().Add(d.idle))
	return d.c.br.Read(p)
}

// copyUntilMark copies r to w until the 40-byte mark that ends a diskless
// snapshot (the mark itself is not copied).
func copyUntilMark(w io.Writer, r io.Reader, mark []byte, limit int64) (int64, error) {
	const keep = 40
	buf := make([]byte, 256<<10)
	held := make([]byte, 0, keep) // the last bytes read, not written yet
	var n int64
	for {
		k, err := r.Read(buf)
		if k > 0 {
			data := append(held, buf[:k]...)
			if len(data) >= keep && bytes.Equal(data[len(data)-keep:], mark) {
				out := data[:len(data)-keep]
				if n+int64(len(out)) > limit {
					return n, errTooBig
				}
				if _, werr := w.Write(out); werr != nil {
					return n, werr
				}
				return n + int64(len(out)), nil
			}
			if len(data) > keep {
				out := data[:len(data)-keep]
				if n+int64(len(out)) > limit {
					return n, errTooBig
				}
				if _, werr := w.Write(out); werr != nil {
					return n, werr
				}
				n += int64(len(out))
				held = append(held[:0], data[len(data)-keep:]...)
			} else {
				held = append(held[:0], data...)
			}
		}
		if err != nil {
			if err == io.EOF {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}
	}
}
