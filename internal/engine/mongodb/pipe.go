package mongodb

import (
	"errors"
	"io"
	"os/exec"
	"sync/atomic"
	"time"
)

// pipeWaitDelay is how long a cancelled tool's output copying may go on
// after it is killed (exec.Cmd.WaitDelay): a cancel never hangs on a pipe.
const pipeWaitDelay = 10 * time.Second

// errRestoreStopped is what a dump writing into a restore that exited sees.
var errRestoreStopped = errors.New("mongorestore stopped reading")

// pipeTools runs dump | restore (mongodump --archive into mongorestore
// --archive). When the restore exits early (a refused login, a full disk),
// the pipe closes, so the dump stops too instead of blocking on a write no
// one reads. dumpErr is nil when the dump only stopped because the restore
// failed first: restoreErr then says why; and restoreErr is nil when the
// dump failed first (the restore then read a cut archive).
func pipeTools(dump, restore *exec.Cmd) (dumpErr, restoreErr error) {
	pr, pw := io.Pipe()
	dump.Stdout, restore.Stdin = pw, pr
	dump.WaitDelay, restore.WaitDelay = pipeWaitDelay, pipeWaitDelay
	if err := restore.Start(); err != nil {
		return nil, err
	}
	restored := make(chan error, 1)
	var restoreFirst atomic.Bool // the restore ended before the dump did
	go func() {
		err := restore.Wait()
		restoreFirst.Store(true) // before the pipe closes: the dump can only fail on it after
		pr.CloseWithError(errRestoreStopped)
		restored <- err
	}()
	if err := dump.Start(); err != nil {
		pw.CloseWithError(err)
		<-restored
		return err, nil
	}
	dumpErr = dump.Wait()
	first := restoreFirst.Load()
	pw.CloseWithError(dumpErr)
	restoreErr = <-restored
	switch {
	case dumpErr != nil && first && restoreErr != nil:
		dumpErr = nil // it stopped because the restore did
	case dumpErr != nil && !first:
		restoreErr = nil // it read a cut archive because the dump failed
	}
	return dumpErr, restoreErr
}
