package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// A server being set up talks to the control plane at a few points that
// can't simply fail when the control plane is away for a minute (a deploy
// restarts it, its proxy answers 502): the installer's self-test, the first
// enrollment and registering the database. Those calls are tried again
// while the control plane is briefly unavailable, instead of the install
// stopping on a server created a minute before.

// transientWait is the first pause between tries (doubling to 15s); tests
// shorten it.
var transientWait = 2 * time.Second

// transientControl reports whether err means the control plane didn't
// handle the request: no connection or no answer, its proxy reporting it
// down (502, 503), or too many requests (429). Anything it answered for
// itself (401, 409, 500...) is final.
func transientControl(err error) bool {
	if err == nil {
		return false
	}
	switch httpStatus(err) {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusTooManyRequests:
		return true
	case 0:
	default:
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	// A timeout, or a connection refused, reset or cut short; not, say, a
	// certificate that doesn't verify.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var oe *net.OpError
	return errors.As(err, &oe) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retryTransient calls fn until it succeeds, fails for good, ctx ends or
// within has passed, and returns its last error.
func retryTransient(ctx context.Context, within time.Duration, fn func(context.Context) error) error {
	deadline := time.Now().Add(within)
	wait := transientWait
	for {
		err := fn(ctx)
		if err == nil || !transientControl(err) || ctx.Err() != nil || time.Now().Add(wait).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		if wait *= 2; wait > 15*time.Second {
			wait = 15 * time.Second
		}
	}
}
