package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// alertsCmd is rowsafe alerts [ack ID | rules].
func alertsCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "ack":
			return alertsAck(ctx, c, args[1:])
		case "rules":
			return alertRulesList(ctx, c, args[1:])
		}
	}
	return alertsList(ctx, c, args)
}

func alertTarget(a protocol.Alert) string {
	switch {
	case a.Database != nil:
		return a.Database.Name
	case a.Host != nil:
		return a.Host.Hostname
	}
	return "-"
}

func alertsList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("alerts", flag.ContinueOnError)
	all := fs.Bool("all", false, "include resolved alerts")
	resolved := fs.Bool("resolved", false, "only resolved alerts")
	limit := fs.Int("limit", 50, "maximum number of alerts")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	state := protocol.AlertFiring
	switch {
	case *resolved:
		state = protocol.AlertResolved
	case *all:
		state = "all"
	}
	alerts, err := c.Alerts(ctx, state, *limit)
	if err != nil {
		return err
	}
	if len(alerts) == 0 {
		if state == protocol.AlertFiring {
			fmt.Println("No alerts firing.")
		} else {
			fmt.Println("No alerts.")
		}
		return nil
	}
	t := newTable("ID", "SEVERITY", "STATE", "RULE", "TARGET", "SINCE", "ACK", "SUMMARY")
	for _, a := range alerts {
		state := strings.ToUpper(a.State)
		if a.ResolvedAt != nil {
			state += " " + ago(a.ResolvedAt)
		}
		ack := "-"
		if a.AcknowledgedAt != nil {
			ack = "yes"
		}
		started := a.StartedAt
		t.row(a.ID, a.Severity, state, a.Rule, alertTarget(a), ago(&started), ack, firstLine(a.Summary, 90))
	}
	t.flush()
	for _, a := range alerts {
		if a.State == protocol.AlertFiring && a.NextStep != "" && a.Severity == protocol.SeverityCritical {
			fmt.Printf("\n%s (%s): %s", a.ID, alertTarget(a), a.NextStep)
		}
	}
	fmt.Println()
	return nil
}

func alertsAck(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("alerts ack", flag.ContinueOnError), args, "ID")
	if err != nil {
		return err
	}
	a, err := c.AckAlert(ctx, pos[0])
	if err != nil {
		return err
	}
	fmt.Printf("Acknowledged %s (%s on %s). No more reminders are sent; you are notified when it resolves.\n",
		a.ID, a.Rule, alertTarget(a))
	return nil
}

func alertRulesList(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("alerts rules", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	rules, err := c.AlertRules(ctx)
	if err != nil {
		return err
	}
	t := newTable("RULE", "ENABLED", "SEVERITY", "THRESHOLD", "FOR", "SCOPE", "TITLE")
	for _, r := range rules {
		th := "-"
		if r.Threshold != nil {
			th = strconv.FormatFloat(*r.Threshold, 'f', -1, 64) + " " + r.Unit
		}
		enabled := "yes"
		if !r.Enabled {
			enabled = "no"
		}
		if r.Customized {
			enabled += "*"
		}
		t.row(r.Rule, enabled, r.Severity, th, (time.Duration(r.ForSeconds) * time.Second).String(), r.Scope, r.Title)
	}
	t.flush()
	fmt.Println("\n* customized for this organization (change rules in the dashboard or with PUT /v1/alert-rules/RULE)")
	return nil
}

func msText(ms float64) string {
	d := time.Duration(ms * float64(time.Millisecond))
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fms", ms)
	case d < time.Second:
		return fmt.Sprintf("%.0fms", ms)
	case d < time.Hour:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Minute).String()
}

func activityCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	width := fs.Int("width", 100, "characters of query text to show")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	a, err := c.Activity(ctx, name)
	if err != nil {
		return err
	}
	if a.CollectedAt.IsZero() {
		fmt.Printf("No activity reported for %s yet (the agent reports every minute).\n", name)
		return nil
	}
	fmt.Printf("Sessions of %s running one query or idle in a transaction for over a minute (collected %s)\n\n",
		name, ago(&a.CollectedAt))
	if len(a.Queries) == 0 {
		fmt.Println("None.")
		return nil
	}
	t := newTable("PID", "STATE", "QUERY TIME", "XACT TIME", "WAITING ON", "APPLICATION", "DATABASE", "USER", "QUERY")
	for _, q := range a.Queries {
		wait := "-"
		if q.WaitEventType != "" {
			wait = q.WaitEventType + ":" + q.WaitEvent
		}
		query := strings.Join(strings.Fields(q.Query), " ")
		if !a.QueryTextCollected {
			query = "(not collected)"
		}
		t.row(strconv.Itoa(q.PID), q.State, secsText(q.DurationSeconds), secsText(q.XactSeconds), wait,
			orDash(q.ApplicationName), orDash(q.Database), orDash(q.User), firstLine(orDash(query), max(*width, 20)))
	}
	t.flush()
	fmt.Printf("\nSessions that block others or stay idle in a transaction too long show up in `rowsafe fix %s`,\n"+
		"which cancels the query or ends the session for you (after checking it is still the same session).\n", name)
	return nil
}

func secsText(s float64) string {
	if s <= 0 {
		return "-"
	}
	return (time.Duration(s) * time.Second).String()
}

// ---- Notification channels ----

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func channelsList(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("channels list", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	chans, err := c.NotificationChannels(ctx)
	if err != nil {
		return err
	}
	if len(chans) == 0 {
		fmt.Println("No notification channels. Add one: rowsafe channels add --type email --name ops --address you@example.com")
		return nil
	}
	t := newTable("ID", "TYPE", "NAME", "MIN SEVERITY", "DESTINATION", "LAST SENT", "LAST ERROR")
	for _, ch := range chans {
		dest := ch.Config.URL
		if ch.Type == protocol.ChannelEmail {
			dest = strings.Join(ch.Config.Addresses, ", ")
		}
		lastErr := "-"
		if ch.LastError != "" && (ch.LastSentAt == nil || (ch.LastErrorAt != nil && ch.LastErrorAt.After(*ch.LastSentAt))) {
			lastErr = firstLine(ch.LastError, 60)
		}
		t.row(ch.ID, ch.Type, ch.Name, ch.MinSeverity, dest, ago(ch.LastSentAt), lastErr)
	}
	t.flush()
	return nil
}

func channelsAdd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("channels add", flag.ContinueOnError)
	typ := fs.String("type", "", "email, slack, discord or webhook")
	name := fs.String("name", "", "a name for the channel")
	url := fs.String("url", "", "incoming webhook URL (slack, discord, webhook; https only)")
	minSev := fs.String("min-severity", protocol.SeverityWarning, "send alerts of this severity and above: info, warning or critical")
	var addrs stringList
	fs.Var(&addrs, "address", "email address (repeat for several)")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	if *typ == "" || *name == "" {
		return errors.New("--type and --name are required")
	}
	req := protocol.CreateNotificationChannelRequest{Type: *typ, Name: *name, MinSeverity: *minSev,
		Config: protocol.ChannelConfig{Addresses: addrs, URL: *url}}
	ch, err := c.CreateNotificationChannel(ctx, req)
	if err != nil {
		return err
	}
	fmt.Printf("Added %s channel %q (%s); alerts of severity %s and above go there.\n", ch.Type, ch.Name, ch.ID, ch.MinSeverity)
	if ch.SigningSecret != "" {
		fmt.Printf("\nSigning secret (shown once; verify the %s header with it, see https://rowsafe.sh/docs/reference/webhooks):\n  %s\n",
			"X-Rowsafe-Signature", ch.SigningSecret)
	}
	fmt.Printf("\nSend a test notification: rowsafe channels test %s\n", ch.ID)
	return nil
}

func channelsRemove(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("channels remove", flag.ContinueOnError), args, "ID")
	if err != nil {
		return err
	}
	if err := c.DeleteNotificationChannel(ctx, pos[0]); err != nil {
		return err
	}
	fmt.Println("Removed", pos[0])
	return nil
}

func channelsTest(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("channels test", flag.ContinueOnError), args, "ID")
	if err != nil {
		return err
	}
	res, err := c.TestNotificationChannel(ctx, pos[0])
	if err != nil {
		return err
	}
	if !res.OK {
		fmt.Println("Test notification failed:", res.Error)
		return exitError(1)
	}
	fmt.Println("Test notification sent.")
	return nil
}
