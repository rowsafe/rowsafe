package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// poolingCmd is rowsafe pooling on|off|status: PgBouncer in front of a
// database, installed and managed by Rowsafe where root allowed it.
func poolingCmd(ctx context.Context, c *client.Client, args []string) error {
	return group(ctx, c, "pooling", args, map[string]subcommand{
		"on": poolingOn, "off": poolingOff, "status": poolingStatus,
	})
}

func poolingOn(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("pooling on", flag.ContinueOnError)
	mode := fs.String("mode", "", "transaction (default) or session")
	poolSize := fs.Int("pool-size", 0, "server connections per database and user (default: picked from max_connections and CPUs)")
	maxClients := fs.Int("max-client-conn", 0, "client connections PgBouncer accepts (default 1000)")
	listen := fs.String("listen", "", "local, private (default) or public")
	port := fs.Int("port", 0, "PgBouncer's port (default 6432)")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	v, err := c.Pooling(ctx, name)
	if err != nil {
		return err
	}
	if !v.Allowed {
		return errors.New("pooling not turned on: " + v.Reason)
	}
	s := protocol.PoolingSettings{Mode: *mode, PoolSize: *poolSize, MaxClientConn: *maxClients, Listen: *listen, Port: *port}
	if v.State == "on" && s == (protocol.PoolingSettings{}) {
		fmt.Printf("Pooling is already on for %s.\n", name)
		return printPooling(v)
	}
	shown := s
	for _, f := range []struct {
		v   *string
		def string
	}{{&shown.Mode, v.Defaults.Mode}, {&shown.Listen, v.Defaults.Listen}} {
		if *f.v == "" {
			*f.v = f.def
		}
	}
	if shown.PoolSize == 0 {
		shown.PoolSize = v.Defaults.PoolSize
	}
	if shown.Port == 0 {
		shown.Port = v.Defaults.Port
	}
	verb := "Turn pooling on"
	if v.State == "on" {
		verb = "Change pooling"
	}
	fmt.Printf("%s for %s: PgBouncer in %s mode, %d server connections per pool, port %d, listening %s.\n",
		verb, name, shown.Mode, shown.PoolSize, shown.Port, listenText(shown.Listen))
	if v.State != "on" {
		fmt.Println("Rowsafe installs PgBouncer on the server if needed. Your apps keep connecting directly until you point them at the pooled address.")
	}
	if shown.Mode == protocol.PoolModeTransaction {
		fmt.Println("Transaction mode shares server connections between clients: session state (SET, LISTEN, advisory locks,\n" +
			"SQL PREPARE, temporary tables) doesn't carry over between transactions. Use --mode session if your app needs it.")
	}
	if shown.Listen == protocol.PoolerListenPublic {
		fmt.Println("PgBouncer will accept connections on every address, including public ones: make sure a firewall protects it.")
	}
	if !*yes && !confirm(verb+"?") {
		return errors.New("cancelled; nothing was changed")
	}
	t, err := c.SetPooling(ctx, name, protocol.PoolingRequest{Settings: s, Confirm: name})
	if err != nil {
		return poolingError(err)
	}
	if err := waitAndReport(ctx, c, t.ID, name); err != nil {
		return err
	}
	if v, err = c.Pooling(ctx, name); err == nil && v.Pooled != "" {
		fmt.Printf("\nConnect your apps through PgBouncer:\n  %s\n(each app keeps its own user and password)\n", v.Pooled)
	}
	return nil
}

func poolingOff(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("pooling off", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	fmt.Printf("Turning pooling off stops PgBouncer for %s: apps connected through it lose their connection and must\n"+
		"connect to PostgreSQL directly again. PgBouncer is removed if Rowsafe installed it.\n", name)
	if !*yes && !confirm("Turn pooling off?") {
		return errors.New("cancelled; nothing was changed")
	}
	t, err := c.PoolingOff(ctx, name, name)
	if err != nil {
		return poolingError(err)
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func poolingStatus(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("pooling status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	v, err := c.Pooling(ctx, name)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(v)
	}
	return printPooling(v)
}

func listenText(l string) string {
	switch l {
	case protocol.PoolerListenLocal:
		return "on this server only"
	case protocol.PoolerListenPublic:
		return "on every address"
	}
	return "on this server and its private network"
}

func printPooling(v protocol.PoolingView) error {
	state := map[string]string{"on": "on", "off": "off", "turning_on": "turning on...", "turning_off": "turning off...", "failed": "failed (see the last task)"}[v.State]
	if state == "" {
		state = v.State
	}
	if v.External {
		state = "monitored (PgBouncer not managed by Rowsafe)"
	}
	fmt.Printf("Pooling:     %s\n", state)
	if !v.Allowed && !v.External {
		fmt.Printf("             %s\n", v.Reason)
	}
	if v.State == "on" || v.External {
		running := "not answering"
		if v.Running {
			running = "running"
		}
		fmt.Printf("PgBouncer:   %s %s\n", strings.TrimSpace("PgBouncer "+v.Version), running)
	}
	if v.State == "on" {
		fmt.Printf("Mode:        %s, %d server connections per pool, up to %d clients\n", v.Settings.Mode, v.Settings.PoolSize, v.Settings.MaxClientConn)
		fmt.Printf("Listens on:  %s, port %d\n", strings.Join(v.Addresses, ", "), v.Settings.Port)
		fmt.Printf("Sends to:    %s\n", v.Target)
	}
	fmt.Printf("Direct:      %s\n", v.Direct)
	if v.Pooled != "" {
		fmt.Printf("Pooled:      %s\n", v.Pooled)
	}
	if s := v.Stats; s != nil && len(s.Pools) > 0 {
		fmt.Println()
		t := newTable("DATABASE", "USER", "CLIENTS", "WAITING", "SERVERS", "POOL", "MAX WAIT", "TX/S")
		for _, p := range s.Pools {
			t.row(p.Database, p.User, fmt.Sprint(p.ClientsActive), fmt.Sprint(p.ClientsWaiting),
				fmt.Sprintf("%d active, %d idle", p.ServersActive, p.ServersIdle), fmt.Sprint(p.PoolSize),
				fmt.Sprintf("%.1fs", p.MaxWaitSeconds), fmt.Sprintf("%.0f", p.XactPerSecond))
		}
		t.flush()
	}
	for _, w := range v.Warnings {
		fmt.Printf("\nNote: %s\n", w)
	}
	return nil
}

// poolingError turns API refusals into plain words.
func poolingError(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusConflict || ae.Status == http.StatusBadRequest) {
		return fmt.Errorf("nothing was changed: %s", ae.Msg)
	}
	return err
}

// poolingResult prints what a finished pooling task reported.
func poolingResult(t protocol.TaskView) {
	switch t.Type {
	case protocol.TaskPooling:
		var r protocol.PoolingResult
		if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
			fmt.Println(r.Summary)
			for _, w := range r.Warnings {
				fmt.Println("Note: " + w)
			}
		}
	case protocol.TaskPoolerRetarget:
		var r protocol.PoolerRetargetResult
		if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
			fmt.Println(r.Summary)
		}
	}
}
