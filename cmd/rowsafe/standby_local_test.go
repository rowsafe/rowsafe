package main

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe standby on a server on its own: this server's half of the pair.
func TestStandbyOnServer(t *testing.T) {
	c := localServer(t)
	ctx := t.Context()

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "shop"}) })
	if err != nil || !strings.Contains(out, "this server is the primary") || !strings.Contains(out, "sudo rowsafe standby create shop") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	// Commands of the other server's half say where to run them.
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "promote", "shop", "--yes"}) }); err == nil ||
		!strings.Contains(err.Error(), "standby's server") {
		t.Fatalf("promote on the primary: %v", err)
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "failover", "shop", "--on"}) }); err == nil ||
		!strings.Contains(err.Error(), "witness") {
		t.Fatalf("automatic failover: %v", err)
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "create", "shop", "--yes"}) }); err == nil ||
		!strings.Contains(err.Error(), "is the primary on this server") {
		t.Fatalf("create on the primary: %v", err)
	}
	// Without a terminal, a fence needs --yes.
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "fence", "shop"}) }); err == nil {
		t.Fatal("fenced without a confirmation")
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "fence", "shop", "--yes"}) })
	if err != nil || !strings.Contains(out, "sudo rowsafe standby promote shop") {
		t.Fatalf("fence: %v\n%s", err, out)
	}
	info, err := c.StandbyInfo(ctx, "shop")
	if err != nil || info.Local == nil || info.Local.Role != protocol.LocalRoleFenced || len(info.Fences) != 1 {
		t.Fatalf("after the fence: %+v %v", info, err)
	}
	out, _ = captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "shop"}) })
	if !strings.Contains(out, "old primary, stopped") || !strings.Contains(out, "unfence") {
		t.Fatalf("status when fenced:\n%s", out)
	}
}
