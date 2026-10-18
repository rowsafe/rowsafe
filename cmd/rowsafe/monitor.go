package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	neturl "net/url"
	"slices"
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
			if len(args) > 1 {
				switch args[1] {
				case "set":
					return alertRulesSet(ctx, c, args[2:])
				case "reset":
					return alertRulesReset(ctx, c, args[2:])
				}
			}
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
	if jsonMode {
		return printJSON(orEmpty(alerts))
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
	if jsonMode {
		return printJSON(a)
	}
	fmt.Printf("Acknowledged %s (%s on %s). No more reminders are sent; you are notified when it resolves.\n",
		a.ID, a.Rule, alertTarget(a))
	return nil
}

func alertRulesList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("alerts rules", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	rules, err := c.AlertRules(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(rules)
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
	fmt.Println("\n* customized for this organization (rowsafe alerts rules set RULE ..., or reset RULE)")
	return nil
}

// alertRuleOverride is the organization's current override of r: the
// fields that differ from the defaults (the API replaces the whole override).
func alertRuleOverride(r protocol.AlertRule) protocol.UpdateAlertRuleRequest {
	var req protocol.UpdateAlertRuleRequest
	if !r.Enabled {
		off := false
		req.Enabled = &off
	}
	if r.Threshold != nil && (r.Defaults.Threshold == nil || *r.Threshold != *r.Defaults.Threshold) {
		th := *r.Threshold
		req.Threshold = &th
	}
	if r.ForSeconds != r.Defaults.ForSeconds {
		f := r.ForSeconds
		req.ForSeconds = &f
	}
	if r.Severity != "" && r.Severity != r.Defaults.Severity {
		sev := r.Severity
		req.Severity = &sev
	}
	return req
}

func findAlertRule(ctx context.Context, c *client.Client, name string) (protocol.AlertRule, error) {
	rules, err := c.AlertRules(ctx)
	if err != nil {
		return protocol.AlertRule{}, err
	}
	var names []string
	for _, r := range rules {
		if r.Rule == name {
			return r, nil
		}
		names = append(names, r.Rule)
	}
	return protocol.AlertRule{}, fmt.Errorf("no alert rule %q; the rules: %s", name, strings.Join(names, ", "))
}

func printAlertRule(r protocol.AlertRule) {
	state := "on"
	if !r.Enabled {
		state = "off"
	}
	fmt.Printf("%s: %s, %s", r.Rule, state, r.Severity)
	if r.Threshold != nil {
		fmt.Printf(", threshold %s %s", strconv.FormatFloat(*r.Threshold, 'f', -1, 64), r.Unit)
	}
	fmt.Printf(", for %s", time.Duration(r.ForSeconds)*time.Second)
	if r.Customized {
		fmt.Print(" (customized)")
	}
	fmt.Println()
}

// alertRulesSet: rowsafe alerts rules set RULE [--on|--off] [--threshold N]
// [--for 5m] [--severity warning|critical] [--json]. What isn't given stays.
func alertRulesSet(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("alerts rules set", flag.ContinueOnError)
	on := fs.Bool("on", false, "turn the rule on")
	off := fs.Bool("off", false, "turn the rule off")
	threshold := fs.Float64("threshold", 0, "the threshold, in the rule's unit")
	dur := fs.Duration("for", 0, "how long it must last before the alert fires (e.g. 5m)")
	severity := fs.String("severity", "", "warning or critical")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseN(fs, args, "RULE")
	if err != nil {
		return err
	}
	if *on && *off {
		return newUsageError("--on or --off, not both")
	}
	r, err := findAlertRule(ctx, c, pos[0])
	if err != nil {
		return err
	}
	req := alertRuleOverride(r)
	changed, noThreshold := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "on", "off":
			v := *on
			req.Enabled, changed = &v, true
			if v {
				req.Enabled = nil // on is the default
			}
		case "threshold":
			if r.Threshold == nil && r.Defaults.Threshold == nil {
				noThreshold = true
				return
			}
			v := *threshold
			req.Threshold, changed = &v, true
		case "for":
			v := int(dur.Seconds())
			req.ForSeconds, changed = &v, true
		case "severity":
			v := *severity
			req.Severity, changed = &v, true
		}
	})
	if noThreshold {
		return fmt.Errorf("%s has no threshold to change", r.Rule)
	}
	if !changed {
		return errors.New("nothing to change: pass --on, --off, --threshold, --for or --severity")
	}
	out, err := c.UpdateAlertRule(ctx, r.Rule, req)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(out)
	}
	printAlertRule(out)
	return nil
}

// alertRulesReset: rowsafe alerts rules reset RULE [--json]: back to the
// defaults.
func alertRulesReset(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("alerts rules reset", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseN(fs, args, "RULE")
	if err != nil {
		return err
	}
	out, err := c.UpdateAlertRule(ctx, pos[0], protocol.UpdateAlertRuleRequest{})
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(out)
	}
	printAlertRule(out)
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
	if jsonMode {
		return printJSON(a)
	}
	printActivity(name, a, *width, "rowsafe fix "+name)
	return nil
}

// printActivity shows long-running and idle-in-transaction sessions;
// fixCmd is the command that ends one ("rowsafe fix NAME").
func printActivity(name string, a protocol.Activity, width int, fixCmd string) {
	if a.CollectedAt.IsZero() {
		fmt.Printf("No activity reported for %s yet (the agent reports every minute).\n", name)
		return
	}
	fmt.Printf("Sessions of %s running one query or idle in a transaction for over a minute (collected %s)\n\n",
		name, ago(&a.CollectedAt))
	if len(a.Queries) == 0 {
		fmt.Println("None.")
		return
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
			orDash(q.ApplicationName), orDash(q.Database), orDash(q.User), firstLine(orDash(query), max(width, 20)))
	}
	t.flush()
	fmt.Printf("\nSessions that block others or stay idle in a transaction too long show up in `%s`,\n"+
		"which cancels the query or ends the session for you (after checking it is still the same session).\n", fixCmd)
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
	if jsonMode {
		return printJSON(orEmpty(chans))
	}
	if len(chans) == 0 {
		if onServer {
			fmt.Println("No notification channels, so alerts aren't sent anywhere. Add one:\n" +
				"  sudo rowsafe channels add --type slack --name ops --url https://hooks.slack.com/services/...\n" +
				"  (or --type discord, --type ntfy --topic TOPIC [--server https://ntfy.example.com], or --type webhook)")
			return nil
		}
		fmt.Println("No notification channels. Add one: rowsafe channels add --type email --name ops --address you@example.com")
		return nil
	}
	t := newTable("ID", "TYPE", "NAME", "MIN SEVERITY", "DESTINATION", "LAST SENT", "LAST ERROR")
	for _, ch := range chans {
		dest := channelDestination(ch)
		lastErr := "-"
		if ch.LastError != "" && (ch.LastSentAt == nil || (ch.LastErrorAt != nil && ch.LastErrorAt.After(*ch.LastSentAt))) {
			lastErr = firstLine(ch.LastError, 60)
		}
		t.row(ch.ID, ch.Type, ch.Name, ch.MinSeverity, dest, ago(ch.LastSentAt), lastErr)
	}
	t.flush()
	return nil
}

// channelDestination says where a channel sends, without its secrets (the
// control plane masks keys, tokens and webhook paths).
func channelDestination(ch protocol.NotificationChannel) string {
	cfg := ch.Config
	switch ch.Type {
	case protocol.ChannelEmail:
		return strings.Join(cfg.Addresses, ", ")
	case protocol.ChannelPagerDuty, protocol.ChannelOpsgenie:
		return "region " + strings.ToUpper(orText(cfg.Region, protocol.ChannelRegionUS))
	case protocol.ChannelTelegram:
		return orDash(cfg.ChatID)
	}
	return orDash(cfg.URL)
}

func channelsAdd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("channels add", flag.ContinueOnError)
	typ := fs.String("type", "", "email, slack, discord, teams, webhook, pagerduty, opsgenie, telegram or ntfy")
	name := fs.String("name", "", "a name for the channel")
	url := fs.String("url", "", "incoming webhook URL (slack, discord, teams, webhook; https only)")
	minSev := fs.String("min-severity", protocol.SeverityWarning, "send alerts of this severity and above: info, warning or critical")
	var addrs stringList
	fs.Var(&addrs, "address", "email address (repeat for several)")
	var cfg protocol.ChannelConfig
	fs.StringVar(&cfg.RoutingKey, "routing-key", "", "pagerduty: the service's Events API v2 integration key")
	fs.StringVar(&cfg.APIKey, "api-key", "", "opsgenie: an API integration's key")
	fs.StringVar(&cfg.Region, "region", "", "pagerduty, opsgenie: us (default) or eu")
	fs.StringVar(&cfg.BotToken, "bot-token", "", "telegram: the bot's token (from @BotFather)")
	fs.StringVar(&cfg.ChatID, "chat-id", "", "telegram: the chat ID (like -1001234567890) or @channel")
	server := fs.String("server", "", "ntfy: the server (default https://ntfy.sh)")
	fs.StringVar(&cfg.Topic, "topic", "", "ntfy: the topic")
	fs.StringVar(&cfg.Token, "token", "", "ntfy: an access token (tk_...), for a protected topic")
	secretEnv := fs.String("secret-env", "", "read the key or token (pagerduty, opsgenie, telegram, ntfy) from this environment variable, off the command line")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	if *typ == "" || *name == "" {
		return newUsageError("--type and --name are required (rowsafe help channels add)")
	}
	cfg.Addresses, cfg.URL = addrs, *url
	if _, ok := channelFlags[*typ]; ok {
		if err := channelSecret(*typ, *secretEnv, &cfg); err != nil {
			return err
		}
	}
	if err := channelConfig(*typ, *server, onServer, &cfg); err != nil {
		return err
	}
	req := protocol.CreateNotificationChannelRequest{Type: *typ, Name: *name, MinSeverity: *minSev, Config: cfg}
	ch, err := c.CreateNotificationChannel(ctx, req)
	if err != nil {
		return err
	}
	if jsonMode {
		return printJSON(ch)
	}
	fmt.Printf("Added %s channel %q (%s); alerts of severity %s and above go there.\n", ch.Type, ch.Name, ch.ID, ch.MinSeverity)
	if ch.SigningSecret != "" {
		fmt.Printf("\nSigning secret (shown once; verify the %s header with it, see https://rowsafe.sh/docs/reference/webhooks):\n  %s\n",
			"X-Rowsafe-Signature", ch.SigningSecret)
	}
	fmt.Printf("\nSend a test notification: rowsafe channels test %s\n", ch.ID)
	return nil
}

// channelFlags are the flags each channel type takes besides --type, --name
// and --min-severity.
var channelFlags = map[string][]string{
	protocol.ChannelEmail:     {"--address"},
	protocol.ChannelSlack:     {"--url"},
	protocol.ChannelDiscord:   {"--url"},
	protocol.ChannelTeams:     {"--url"},
	protocol.ChannelWebhook:   {"--url"},
	protocol.ChannelPagerDuty: {"--routing-key", "--region"},
	protocol.ChannelOpsgenie:  {"--api-key", "--region"},
	protocol.ChannelTelegram:  {"--bot-token", "--chat-id"},
	protocol.ChannelNtfy:      {"--server", "--topic", "--token"},
}

// channelSecretFlag is the flag of each type's key or token.
var channelSecretFlag = map[string]string{
	protocol.ChannelPagerDuty: "--routing-key",
	protocol.ChannelOpsgenie:  "--api-key",
	protocol.ChannelTelegram:  "--bot-token",
	protocol.ChannelNtfy:      "--token",
}

// channelSecret fills the type's key or token from $secretEnv or, when
// its flag is missing, from stdin (typed without echo on a terminal), so
// it needn't be on the command line. ntfy's token is optional: only from
// the flag or $secretEnv.
func channelSecret(typ, secretEnv string, cfg *protocol.ChannelConfig) error {
	flag, ok := channelSecretFlag[typ]
	if !ok {
		if secretEnv != "" {
			return usageErrorf("--secret-env: %s channels have no key or token", typ)
		}
		return nil
	}
	field := map[string]*string{protocol.ChannelPagerDuty: &cfg.RoutingKey, protocol.ChannelOpsgenie: &cfg.APIKey,
		protocol.ChannelTelegram: &cfg.BotToken, protocol.ChannelNtfy: &cfg.Token}[typ]
	switch {
	case secretEnv != "" && *field != "":
		return usageErrorf("pass %s or --secret-env, not both", flag)
	case secretEnv != "":
		v, err := readSecret(secretEnv, "")
		if err != nil {
			return err
		}
		*field = v
	case *field == "" && typ != protocol.ChannelNtfy:
		what := map[string]string{protocol.ChannelPagerDuty: "The PagerDuty integration key (Events API v2)",
			protocol.ChannelOpsgenie: "The Opsgenie API integration key", protocol.ChannelTelegram: "The Telegram bot token (from @BotFather)"}[typ]
		v, err := readSecret("", what+" (it isn't shown): ")
		if err != nil {
			return err
		}
		if v == "" {
			return usageErrorf("%s channels need %s: pass --secret-env VAR, pipe it on stdin, or %s KEY", typ, flag, flag)
		}
		*field = v
	}
	return nil
}

// channelConfig checks that cfg has what typ needs and nothing another
// type takes, so a mistyped flag isn't silently dropped. ntfy: --server
// and --topic (or --url https://ntfy.sh/TOPIC) become the server and the
// topic; local (a server without an account) wants the topic's whole URL.
func channelConfig(typ, server string, local bool, cfg *protocol.ChannelConfig) error {
	allowed, ok := channelFlags[typ]
	if !ok {
		return usageErrorf("--type: email, slack, discord, teams, webhook, pagerduty, opsgenie, telegram or ntfy (got %q)", typ)
	}
	given := map[string]bool{"--address": len(cfg.Addresses) > 0, "--url": cfg.URL != "", "--routing-key": cfg.RoutingKey != "",
		"--api-key": cfg.APIKey != "", "--region": cfg.Region != "", "--bot-token": cfg.BotToken != "", "--chat-id": cfg.ChatID != "",
		"--server": server != "", "--topic": cfg.Topic != "", "--token": cfg.Token != ""}
	if typ == protocol.ChannelNtfy {
		allowed = append(allowed, "--url")
	}
	for _, f := range slices.Sorted(maps.Keys(given)) {
		if given[f] && !slices.Contains(allowed, f) {
			return usageErrorf("%s channels don't take %s; they take %s", typ, f, strings.Join(channelFlags[typ], ", "))
		}
	}
	need := func(flag, v, example string) error {
		if strings.TrimSpace(v) == "" {
			return usageErrorf("%s channels need %s, e.g. %s", typ, flag, example)
		}
		return nil
	}
	switch typ {
	case protocol.ChannelEmail:
		if len(cfg.Addresses) == 0 {
			return usageErrorf("email channels need --address you@example.com (repeat it for several)")
		}
	case protocol.ChannelSlack, protocol.ChannelDiscord, protocol.ChannelTeams, protocol.ChannelWebhook:
		return need("--url", cfg.URL, "--url https://...")
	case protocol.ChannelPagerDuty, protocol.ChannelOpsgenie:
		key, flag := cfg.RoutingKey, "--routing-key"
		if typ == protocol.ChannelOpsgenie {
			key, flag = cfg.APIKey, "--api-key"
		}
		if err := need(flag, key, flag+" KEY"); err != nil {
			return err
		}
		cfg.Region = strings.ToLower(strings.TrimSpace(cfg.Region))
		if cfg.Region != "" && cfg.Region != protocol.ChannelRegionUS && cfg.Region != protocol.ChannelRegionEU {
			return usageErrorf("--region: us or eu (got %q)", cfg.Region)
		}
	case protocol.ChannelTelegram:
		if err := need("--bot-token", cfg.BotToken, "--bot-token 123456789:ABC... (from @BotFather)"); err != nil {
			return err
		}
		return need("--chat-id", cfg.ChatID, "--chat-id -1001234567890 or --chat-id @yourchannel")
	case protocol.ChannelNtfy:
		return ntfyConfig(server, local, cfg)
	}
	return nil
}

// ntfyConfig fills an ntfy channel's server (config.url) and topic.
func ntfyConfig(server string, local bool, cfg *protocol.ChannelConfig) error {
	if cfg.URL != "" && server != "" {
		return newUsageError("ntfy: pass --server and --topic (or the topic's whole URL with --url), not both")
	}
	if cfg.URL != "" {
		u, err := neturl.Parse(cfg.URL)
		if err != nil || u.Host == "" {
			return usageErrorf("--url: the ntfy topic's address, like https://ntfy.sh/TOPIC (got %q)", cfg.URL)
		}
		topic := strings.Trim(u.Path, "/")
		if topic != "" {
			if cfg.Topic != "" && cfg.Topic != topic {
				return usageErrorf("--url names the topic %q and --topic %q: pass one", topic, cfg.Topic)
			}
			cfg.Topic = topic
		}
		server = u.Scheme + "://" + u.Host
	}
	if server == "" {
		server = "https://ntfy.sh"
	}
	server = strings.TrimRight(server, "/")
	if cfg.Topic == "" || strings.Contains(cfg.Topic, "/") {
		return newUsageError("ntfy channels need --topic NAME (letters, digits, - or _), e.g. --topic my-alerts-7f3k")
	}
	if local {
		// The local control plane stores the topic's whole URL and sends
		// without a token.
		if cfg.Token != "" {
			return newUsageError("--token: a protected ntfy topic needs the dashboard (rowsafe login); on this server use a topic without a token")
		}
		cfg.URL, cfg.Topic = server+"/"+cfg.Topic, ""
		return nil
	}
	cfg.URL = server
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
	if jsonMode {
		if err := printJSON(res); err != nil || res.OK {
			return err
		}
		return exitError(1)
	}
	if !res.OK {
		fmt.Println("Test notification failed:", res.Error)
		return exitError(1)
	}
	fmt.Println("Test notification sent.")
	return nil
}
