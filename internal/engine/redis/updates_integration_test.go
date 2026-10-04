//go:build redis_integration

package redis

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisUpdates: the running version (what the update compares) and
// the bundled program's (a sidecar's newest known release); in the
// official images they are the same server program.
func TestRedisUpdates(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	v, err := e.Version(ctx, env, db)
	if err != nil || strings.Count(v, ".") != 2 {
		t.Fatalf("version %q %v", v, err)
	}
	m, _ := a.info(ctx, "server")
	if eng, want := engineOf(m); v != want || eng != e.name {
		t.Fatalf("version %q, INFO says %s %q", v, eng, want)
	}
	if os.Getenv("ROWSAFE_REDIS_HOST") == "" {
		b, err := e.BundledVersion(ctx)
		if err != nil || b != v {
			t.Fatalf("bundled %q %v, running %q", b, err, v)
		}
	}
	t.Logf("%s %s", protocol.EngineDisplayName(e.name), v)
}
