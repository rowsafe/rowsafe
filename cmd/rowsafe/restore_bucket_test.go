package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFromBucket(t *testing.T) {
	for args, want := range map[string]bool{"shop --from-bucket": true, "shop --from-bucket=true --as x": true, "shop --to 14:04": false} {
		if got := fromBucket(strings.Fields(args)); got != want {
			t.Errorf("%q: %v, want %v", args, got, want)
		}
	}
	// Away from a server on its own, it says where it runs.
	onServer = false
	if err := restoreCmd(context.Background(), nil, []string{"shop", "--from-bucket", "--yes"}); !errors.Is(err, errFromBucketElsewhere) {
		t.Fatalf("off the server: %v", err)
	}
}

