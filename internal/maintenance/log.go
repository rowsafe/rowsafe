package maintenance

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// Log is where an action writes what it does (the agent's task log).
type Log interface {
	Printf(format string, args ...any)
}

// taskLog is the Log of a run outside the agent (the CLI's fixes), in the
// agent's task log format.
type taskLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *taskLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s ", time.Now().UTC().Format("15:04:05"))
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

func (l *taskLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
