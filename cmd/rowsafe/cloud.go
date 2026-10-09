package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/mcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe cloud: Rowsafe Cloud, database servers (PostgreSQL, and MySQL,
// MariaDB or Valkey where the catalog offers them: cloud_engines.go)
// Rowsafe runs in its own cloud accounts, billed by the hour (never more
// than the monthly price).
// A read-write API key (or `rowsafe login`) acts directly, like the
// dashboard: create, resize, change who can connect, clone and delete.
// Money and deletions are confirmed first (--yes in scripts).

func cloudCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return cloudList(ctx, c, args)
	}
	subs := map[string]func(context.Context, *client.Client, []string) error{
		"sizes": cloudSizes, "create": cloudCreate, "list": cloudList, "ls": cloudList, "show": cloudShow,
		"wait": cloudWait, "resize": cloudResize, "allow": cloudAllow, "firewall": cloudFirewall,
		"delete": cloudDelete, "passphrase": cloudPassphrase, "clone": cloudClone, "retry": cloudRetry,
	}
	if run, ok := subs[args[0]]; ok {
		return run(ctx, c, args[1:])
	}
	return fmt.Errorf("unknown command %q. The cloud commands:\n%s", "cloud "+args[0], strings.TrimSpace(helpFor([]string{"cloud"})))
}

// cloudPoll is how often rowsafe cloud wait reads the server again.
var cloudPoll = 5 * time.Second

// cloudErr says plainly when this control plane doesn't offer Rowsafe Cloud.
func cloudErr(err error) error {
	if apiStatus(err) == http.StatusNotFound {
		return errors.New("Rowsafe Cloud isn't offered on this Rowsafe server: protect a database on a server you run instead (rowsafe hosts enroll-token)")
	}
	return apiErr(err)
}

func apiStatus(err error) int {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// ---- finding a server ----

// findServer finds a server Rowsafe created by its name, its ID (cs_...)
// or its database's name. Without ref: the project's database (see
// `rowsafe help names`), else the organization's only server.
func findServer(ctx context.Context, c *client.Client, ref string) (client.CloudServer, error) {
	list, err := c.CloudServerList(ctx)
	if err != nil {
		return client.CloudServer{}, cloudErr(err)
	}
	live := slices.DeleteFunc(slices.Clone(list), func(s client.CloudServer) bool { return s.Status == "deleted" })
	if ref == "" {
		name, _ := projectDatabase()
		switch {
		case name != "":
			ref = name
		case len(live) == 1:
			return live[0], nil
		case len(live) == 0:
			return client.CloudServer{}, errors.New("no Rowsafe Cloud servers yet: create one with `rowsafe cloud create NAME`")
		default:
			names := make([]string, len(live))
			for i, s := range live {
				names[i] = s.Name
			}
			return client.CloudServer{}, fmt.Errorf("which server? This organization has %d: %s. Pass NAME, or run `rowsafe init NAME` in your project", len(live), strings.Join(names, ", "))
		}
	}
	for _, s := range live {
		if s.ID == ref || s.Name == ref {
			return s, nil
		}
	}
	if s := serverOfDatabase(live, ref); s != nil {
		return *s, nil
	}
	return client.CloudServer{}, fmt.Errorf("no server named %q was created by Rowsafe in this organization (rowsafe cloud list shows them)", ref)
}

// serverOfDatabase is the server that runs the database ref (the primary of
// a pair), or nil.
func serverOfDatabase(list []client.CloudServer, ref string) *client.CloudServer {
	for i, s := range list {
		if s.Status == "deleted" || s.DatabaseRef == nil || *s.DatabaseRef != ref {
			continue
		}
		if s.Standby != nil && s.Standby.Role == "standby" {
			continue
		}
		return &list[i]
	}
	return nil
}

// cloudServerFor is the server Rowsafe created for the Rowsafe database
// (server) name, or nil when it runs elsewhere (or Rowsafe Cloud is off).
func cloudServerFor(ctx context.Context, c *client.Client, name string) *client.CloudServer {
	list, err := c.CloudServerList(ctx)
	if err != nil {
		return nil
	}
	if s := serverOfDatabase(list, name); s != nil {
		return s
	}
	if d, err := c.Database(ctx, name); err == nil {
		if s := serverOfDatabase(list, d.Name); s != nil {
			return s
		}
		if s := serverOfDatabase(list, d.ID); s != nil {
			return s
		}
	}
	return nil
}

// serverEndpoint is where apps reach a server Rowsafe created: its name
// (or address until it has one), its engine's port (5432 for PostgreSQL),
// and the sslmode to use.
func serverEndpoint(s client.CloudServer) (host string, port int, sslmode string) {
	port = serverPort(s) // cloud_engines.go
	switch {
	case s.Address != nil && s.Address.Host != "":
		if s.Address.Port != 0 {
			port = s.Address.Port
		}
		return s.Address.Host, port, orText(s.Address.SSLMode, "require")
	case s.IPv4 != nil && *s.IPv4 != "":
		return *s.IPv4, port, "require"
	}
	return "", 0, ""
}

// ---- the catalog ----

func sizePrice(cl client.CloudCatalogCloud, z client.CloudSize) string {
	if cl.Billing == "hourly" && z.HourlyPriceCents > 0 {
		return mcp.HourText(z.HourlyPriceCents, z.Currency) + " an hour, at most " + mcp.PriceText(z.PriceCents, z.Currency) + " a month"
	}
	return mcp.PriceText(z.PriceCents, z.Currency) + " a month"
}

func offeredIn(z client.CloudSize, region string) bool {
	return len(z.Regions) == 0 || slices.Contains(z.Regions, region)
}

func regionText(r client.CloudRegion) string {
	s := r.ID
	if r.Name != "" && r.Name != r.ID {
		s += " (" + r.Name
		if r.Country != "" {
			s += ", " + r.Country
		}
		s += ")"
	}
	return s
}

// cloudPick is where a new server goes.
type cloudPick struct {
	Cloud  client.CloudCatalogCloud
	Region client.CloudRegion
	Size   client.CloudSize
}

func (p cloudPick) describe(standby bool) string {
	z := p.Size
	s := fmt.Sprintf("%s, %s, size %s (%d CPUs, %d GB memory, %d GB disk): %s", p.Cloud.Name, regionText(p.Region), z.ID,
		z.CPUs, z.MemoryGB, z.DiskGB, sizePrice(p.Cloud, z))
	if standby {
		s += ", twice that with the standby server"
	}
	return s
}

// matchCloud reports whether a cloud is the one --cloud names (its ID or
// name, any case).
func matchCloud(cl client.CloudCatalogCloud, name string) bool {
	return name == "" || strings.EqualFold(cl.Provider, name) || strings.EqualFold(cl.Name, name)
}

// pickCloud chooses where a new server goes: the cloud, region and size
// asked for, and for what is left out the cheapest size free right now.
// Without --cloud or --region, clouds billed by the hour come first (a
// server there is created right away once pay as you go is set up).
// hourly: only clouds billed by the hour (a standby, a clone).
func pickCloud(cat client.CloudCatalog, cloudName, region, size string, hourly bool) (cloudPick, error) {
	var clouds []client.CloudCatalogCloud
	for _, cl := range cat.Clouds {
		if matchCloud(cl, cloudName) {
			clouds = append(clouds, cl)
		}
	}
	if len(cat.Clouds) == 0 {
		return cloudPick{}, errors.New("Rowsafe Cloud has no locations open right now; try again later")
	}
	if len(clouds) == 0 {
		var names []string
		for _, cl := range cat.Clouds {
			names = append(names, cl.Provider)
		}
		return cloudPick{}, fmt.Errorf("Rowsafe Cloud has no cloud %q: choose %s", cloudName, strings.Join(names, ", "))
	}
	if region != "" {
		clouds = slices.DeleteFunc(clouds, func(cl client.CloudCatalogCloud) bool {
			return !slices.ContainsFunc(cl.Regions, func(r client.CloudRegion) bool { return r.ID == region })
		})
		if len(clouds) == 0 {
			in := ""
			if cloudName != "" {
				in = " in " + cloudName
			}
			return cloudPick{}, fmt.Errorf("no Rowsafe Cloud region %q%s: `rowsafe cloud sizes` lists them", region, in)
		}
	}
	if hourly {
		before := clouds
		clouds = slices.DeleteFunc(slices.Clone(clouds), func(cl client.CloudCatalogCloud) bool { return cl.Billing != "hourly" })
		if len(clouds) == 0 {
			return cloudPick{}, fmt.Errorf("%s is billed by the month, and a standby or a clone needs a cloud billed by the hour: choose another --cloud or --region", before[0].Name)
		}
	} else if cloudName == "" && region == "" && slices.ContainsFunc(clouds, func(cl client.CloudCatalogCloud) bool { return cl.Billing == "hourly" }) {
		clouds = slices.DeleteFunc(clouds, func(cl client.CloudCatalogCloud) bool { return cl.Billing != "hourly" })
	}
	var best *cloudPick
	var bestCents int64 = math.MaxInt64
	var soldOut, notHere []string
	sizeKnown := false
	for _, cl := range clouds {
		for _, z := range cl.Sizes {
			if size != "" && z.ID != size {
				continue
			}
			sizeKnown = true
			for _, r := range cl.Regions {
				if region != "" && r.ID != region {
					continue
				}
				switch {
				case !offeredIn(z, r.ID):
					notHere = append(notHere, r.ID)
				case slices.Contains(z.UnavailableRegions, r.ID):
					soldOut = append(soldOut, r.ID)
				case z.PriceCents < bestCents:
					best, bestCents = &cloudPick{Cloud: cl, Region: r, Size: z}, z.PriceCents
				}
			}
		}
	}
	switch {
	case best != nil:
		return *best, nil
	case size != "" && !sizeKnown:
		var ids []string
		for _, cl := range clouds {
			for _, z := range cl.Sizes {
				if !slices.Contains(ids, z.ID) {
					ids = append(ids, z.ID)
				}
			}
		}
		return cloudPick{}, fmt.Errorf("no size %q there: choose %s (`rowsafe cloud sizes` shows them)", size, strings.Join(ids, ", "))
	case len(soldOut) > 0:
		return cloudPick{}, fmt.Errorf("none free right now in %s: choose another --region or --size, or try again later (`rowsafe cloud sizes` shows what is sold out)", strings.Join(dedupe(soldOut), ", "))
	case len(notHere) > 0:
		return cloudPick{}, fmt.Errorf("the size %s isn't offered in %s: choose another --size or --region", size, strings.Join(dedupe(notHere), ", "))
	}
	return cloudPick{}, errors.New("no size is free right now there: choose another --region, or try again later")
}

// cloudSizes: rowsafe cloud sizes [--cloud C] [--region R] [--json]
func cloudSizes(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud sizes", flag.ContinueOnError)
	cloudName := fs.String("cloud", "", "only this cloud (hetzner, digitalocean, aws...)")
	region := fs.String("region", "", "only sizes offered in this region")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	cat, err := c.CloudCatalog(ctx)
	if err != nil {
		return cloudErr(err)
	}
	if *asJSON {
		return printJSON(cat)
	}
	shown := 0
	for _, cl := range cat.Clouds {
		if !matchCloud(cl, *cloudName) {
			continue
		}
		if *region != "" && !slices.ContainsFunc(cl.Regions, func(r client.CloudRegion) bool { return r.ID == *region }) {
			continue
		}
		shown++
		billing := "billed by the month, a subscription per server"
		if cl.Billing == "hourly" {
			billing = "billed by the hour, never more than the monthly price"
		}
		if cl.Standby {
			billing += "; can have a standby server"
		}
		fmt.Printf("%s (--cloud %s): %s\n", cl.Name, cl.Provider, billing)
		amdOnly := amd64OnlyEngines(cat) // cloud_engines.go
		var regions []string
		for _, r := range cl.Regions {
			if *region == "" || r.ID == *region {
				regions = append(regions, regionText(r))
			}
		}
		fmt.Printf("  Regions: %s\n\n", strings.Join(regions, ", "))
		t := newTable("  SIZE", "CPUS", "MEMORY", "DISK", "AN HOUR", "AT MOST A MONTH", "NOTE")
		for _, z := range cl.Sizes {
			if *region != "" && !offeredIn(z, *region) {
				continue
			}
			hour := "-"
			if cl.Billing == "hourly" && z.HourlyPriceCents > 0 {
				hour = mcp.HourText(z.HourlyPriceCents, z.Currency)
			}
			var note []string
			if len(z.Regions) > 0 && *region == "" {
				note = append(note, "only in "+strings.Join(z.Regions, ", "))
			}
			if out := slices.DeleteFunc(slices.Clone(z.UnavailableRegions), func(r string) bool { return *region != "" && r != *region }); len(out) > 0 {
				note = append(note, "sold out now in "+strings.Join(out, ", "))
			}
			if tr := mcp.TrafficText(z); tr != "" {
				note = append(note, tr)
			}
			if z.Arch == "arm64" && amdOnly != "" {
				note = append(note, "Arm processor: not for "+amdOnly)
			}
			t.row("  "+z.ID, fmt.Sprint(z.CPUs), fmt.Sprintf("%d GB", z.MemoryGB), fmt.Sprintf("%d GB", z.DiskGB), hour,
				mcp.PriceText(z.PriceCents, z.Currency), orText(strings.Join(note, "; "), "-"))
		}
		t.flush()
		fmt.Println()
	}
	if shown == 0 {
		if len(cat.Clouds) == 0 {
			fmt.Println("Rowsafe Cloud has no locations open right now.")
		} else {
			fmt.Println("Nothing matches: run `rowsafe cloud sizes` without --cloud and --region to see every cloud.")
		}
		return nil
	}
	switch cat.Payg.Status {
	case "active":
		fmt.Println("Pay as you go is active: new servers billed by the hour are created right away.")
	case "past_due":
		fmt.Println("Pay as you go: the last payment failed. An owner updates the payment method in the dashboard (Settings, Billing) before new servers can be created.")
	case "canceling":
		fmt.Println("Pay as you go is canceled. An owner keeps it in the dashboard (Settings, Billing) before new servers can be created.")
	default:
		fmt.Println("Pay as you go isn't set up yet: the first server billed by the hour gives you a link to add a card, once.")
	}
	fmt.Printf("The organization may have %d Rowsafe Cloud servers at a time (%d billed by the hour).\n", cat.MaxServers, cat.MaxHourlyServers)
	printEngines(cat) // cloud_engines.go
	if p, err := pickCloud(cat, *cloudName, *region, "", false); err == nil {
		fmt.Printf("Cheapest free now: %s.\n", p.describe(false))
	}
	fmt.Println("Create one: rowsafe cloud create NAME [--region REGION] [--size SIZE] [--engine ENGINE]")
	return nil
}

// ---- create ----

var serverNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

func checkServerName(name string) error {
	if !serverNameRE.MatchString(name) {
		return fmt.Errorf("%q can't be a server's name: use 2 to 40 lowercase letters, digits and hyphens, starting with a letter (like shop-db)", name)
	}
	return nil
}

// allowedFor turns --allow into the list a new server gets: this computer's
// address when none is given.
func allowedFor(ctx context.Context, c *client.Client, allow []string) ([]string, error) {
	if len(allow) == 0 {
		mine, err := myAddresses(ctx, c.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("%w; or --allow none to let nobody connect until `rowsafe cloud allow`", err)
		}
		return mine, nil
	}
	return expandAddresses(ctx, c.BaseURL, allow)
}

// confirmMoney asks before something that costs money; scripts pass --yes.
func confirmMoney(yes bool, what string) error {
	if yes {
		return nil
	}
	if !stdinIsTerminal() {
		return fmt.Errorf("%s costs money: pass --yes to confirm", what)
	}
	if !confirm(strings.ToUpper(what[:1]) + what[1:] + "?") {
		return errors.New("cancelled; nothing was created")
	}
	return nil
}

// cloudCreate: rowsafe cloud create NAME [--cloud C] [--region R] [--size S]
// [--engine postgresql|mysql|mariadb|valkey|clickhouse] [--engine-version V] [--postgres 17]
// [--extensions vector,postgis,timescaledb] [--allow me|IP|CIDR]... [--standby] [--wait] [--yes] [--json]
func cloudCreate(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud create", flag.ContinueOnError)
	cloudName := fs.String("cloud", "", "the cloud (hetzner, digitalocean, aws...; default: the cheapest)")
	region := fs.String("region", "", "the region, e.g. fsn1 (it decides the cloud; default: where the cheapest size is free)")
	size := fs.String("size", "", "the size, e.g. small (default: the cheapest free now)")
	pg := fs.String("postgres", "", "PostgreSQL major version: 15, 16, 17 or 18 (default 17); the same as --engine postgresql --engine-version")
	engineName := fs.String("engine", "", "the database: "+engineChoices()+" (`rowsafe cloud sizes` lists what is offered)")
	engineVersion := fs.String("engine-version", "", "the engine's version (default: the one Rowsafe recommends; `rowsafe cloud sizes` lists them)")
	var allow, exts csvList
	fs.Var(&allow, "allow", "who can connect: me (this computer), an IP address or a network; repeat or comma-separate (default: me; none: nobody yet)")
	fs.Var(&exts, "extensions", fmt.Sprintf("PostgreSQL %d to %d: extensions installed and turned on from the start: vector (pgvector), postgis (PostGIS), timescaledb (TimescaleDB, Apache-2.0 edition); comma-separated",
		protocol.PGExtensionsMinMajor, protocol.PGExtensionsMaxMajor))
	standby := fs.Bool("standby", false, "also a standby server of the same size, ready to take over (doubles the price)")
	wait := fs.Bool("wait", false, "follow it until it's ready")
	yes := fs.Bool("yes", false, "don't ask (it costs money: --yes is the confirmation)")
	asJSON := fs.Bool("json", false, "print the server as JSON (messages go to stderr)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rowsafe cloud create NAME [--region REGION] [--size SIZE] [--allow me|IP] [--wait]")
	}
	name := pos[0]
	if err := checkServerName(name); err != nil {
		return err
	}
	cat, err := c.CloudCatalog(ctx)
	if err != nil {
		return cloudErr(err)
	}
	engine, version, err := chooseEngine(cat, *engineName, *engineVersion, *pg, *standby) // cloud_engines.go
	if err != nil {
		return err
	}
	extensions, err := chooseExtensions(engine, version, exts) // cloud_engines.go
	if err != nil {
		return err
	}
	pick, err := pickCloud(catalogFor(cat, engine, *size), *cloudName, *region, *size, *standby)
	if err != nil {
		return err
	}
	if err := armRefusal(engine, pick.Size); err != nil {
		return err
	}
	if *standby && !pick.Cloud.Standby {
		return fmt.Errorf("servers in %s can't have a standby: choose another --cloud or --region", pick.Cloud.Name)
	}
	allowed, err := allowedFor(ctx, c, allow)
	if err != nil {
		return err
	}
	out := msgOut(*asJSON)
	fmt.Fprintf(out, "New server %s: %s %s on %s.\n", name, engine.Name, version, pick.describe(*standby))
	if len(extensions) > 0 {
		fmt.Fprintf(out, "Extensions: %s (in the postgres database and every new one).\n", extensionTitles(extensions))
	}
	fmt.Fprintf(out, "Who can connect: %s.\n", sourcesText(allowed))
	if pick.Cloud.Billing == "hourly" && cat.Payg.Status != "active" && cat.Payg.Status != "past_due" && cat.Payg.Status != "canceling" {
		fmt.Fprintln(out, "Pay as you go isn't set up yet: you get a link to add a card, once; the server is created as soon as that's done.")
	}
	if err := confirmMoney(*yes, "create "+name); err != nil {
		return err
	}
	res, err := c.CreateCloudServer(ctx, client.CreateCloudServerRequest{Where: "rowsafe", Provider: pick.Cloud.Provider,
		Region: pick.Region.ID, Size: pick.Size.ID, Name: name, Engine: engine.Engine, EngineVersion: version,
		AllowedIPs: allowed, Standby: *standby, Extensions: extensions})
	if err != nil {
		return apiErr(err)
	}
	return afterCreate(ctx, c, res, pick.Cloud.Billing == "hourly", *wait, *asJSON)
}

// msgOut is where messages go: stderr when stdout carries JSON.
func msgOut(asJSON bool) io.Writer {
	if asJSON {
		return os.Stderr
	}
	return os.Stdout
}

// afterCreate reports a new server or clone: the checkout link when it waits
// for payment, else its progress (with --wait, until it's ready).
func afterCreate(ctx context.Context, c *client.Client, res client.CloudServerCreated, hourly, wait, asJSON bool) error {
	out := msgOut(asJSON)
	s := res.Server
	if res.CheckoutURL != "" {
		if hourly {
			fmt.Fprintf(out, "\n%s waits for payment: add a card once for pay as you go (an owner of the organization), and it is created right after:\n\n  %s\n\n", s.Name, res.CheckoutURL)
			fmt.Fprintln(out, "Nothing is billed before. After that, new servers billed by the hour are created right away.")
		} else {
			fmt.Fprintf(out, "\n%s is paid by the month: pay for it here (an owner of the organization), and it is created right after:\n\n  %s\n\n", s.Name, res.CheckoutURL)
		}
		if !asJSON && stdinIsTerminal() && canOpenBrowser() && openBrowser(res.CheckoutURL) == nil {
			fmt.Fprintln(out, "Opened it in your browser.")
		}
	}
	if wait {
		var err error
		if s, err = waitServer(ctx, c, s.ID, 45*time.Minute, os.Stderr); err != nil {
			return err
		}
	}
	if asJSON {
		res.Server = s
		return printJSON(res)
	}
	switch s.Status {
	case "ready":
		fmt.Println()
		printServer(s)
		printNext(s)
	case "payment":
		fmt.Printf("Follow it with `rowsafe cloud wait %s`.\n", s.Name)
	default:
		fmt.Printf("Creating %s: about 5 to 10 minutes. Follow it with `rowsafe cloud wait %s`.\n", s.Name, s.Name)
	}
	return nil
}

func printNext(s client.CloudServer) {
	ref := s.Name
	if s.DatabaseRef != nil {
		ref = *s.DatabaseRef
	}
	fmt.Println("\nNext:")
	fmt.Printf("  rowsafe env --on %s       a database and login for your app, written to .env as DATABASE_URL\n", ref)
	fmt.Printf("  rowsafe connect %s        open psql\n", ref)
	if len(s.AllowedIPs) == 0 {
		fmt.Printf("  rowsafe cloud allow %s    let this computer (or your app's address) connect\n", s.Name)
	}
}

// ---- wait ----

// waitServer follows a server until it's ready, reporting each new step to
// progress. Failed, deleted and the timeout are errors.
func waitServer(ctx context.Context, c *client.Client, id string, timeout time.Duration, progress io.Writer) (client.CloudServer, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	last := ""
	var s client.CloudServer
	for {
		cur, err := c.CloudServer(ctx, id)
		switch {
		case err == nil:
			s = cur
		case ctx.Err() != nil:
			return s, fmt.Errorf("%s isn't ready after %s; it keeps going: `rowsafe cloud wait %s` follows it again", orText(s.Name, id), timeout, orText(s.Name, id))
		case apiStatus(err) >= 400 && apiStatus(err) < 500:
			return s, apiErr(err)
		default:
			fmt.Fprintln(progress, "(still waiting: "+err.Error()+")")
		}
		if err == nil {
			if line := s.Status + "|" + s.Step; line != last {
				last = line
				msg := orText(s.Step, s.Status)
				if s.Status == "payment" && s.Billing != nil && s.Billing.CheckoutURL != nil {
					msg = "waiting for payment at " + *s.Billing.CheckoutURL
				}
				fmt.Fprintf(progress, "%s  %s: %s\n", time.Now().Format("15:04:05"), s.Name, msg)
			}
			switch s.Status {
			case "ready":
				return s, nil
			case "failed":
				return s, fmt.Errorf("%s couldn't be set up: %s. Try again with `rowsafe cloud retry %s`, or delete it with `rowsafe cloud delete %s`",
					s.Name, orText(deref(s.Problem), "no reason given"), s.Name, s.Name)
			case "deleting", "deleted":
				return s, fmt.Errorf("%s is being deleted", s.Name)
			}
		}
		if err := sleepCtx(ctx, cloudPoll); err != nil {
			return s, fmt.Errorf("%s isn't ready after %s; it keeps going: `rowsafe cloud wait %s` follows it again", orText(s.Name, id), timeout, orText(s.Name, id))
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// cloudWait: rowsafe cloud wait [NAME] [--timeout 30m] [--json]
func cloudWait(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud wait", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 30*time.Minute, "give up after this long")
	asJSON := fs.Bool("json", false, "print the server as JSON once it's ready")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if s, err = waitServer(ctx, c, s.ID, *timeout, os.Stderr); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(s)
	}
	printServer(s)
	printNext(s)
	return nil
}

func optionalName(fs *flag.FlagSet, args []string) (string, error) {
	pos, err := positionals(fs, args)
	if err != nil {
		return "", err
	}
	if len(pos) > 1 {
		return "", fmt.Errorf("expected at most one server name, got %q", strings.Join(pos, " "))
	}
	if len(pos) == 1 {
		return pos[0], nil
	}
	return "", nil
}

// ---- list, show ----

func serverPrice(s client.CloudServer) string {
	b := s.Billing
	if b == nil {
		return "-"
	}
	if b.Mode == "hourly" && b.HourlyPriceCents > 0 {
		return mcp.HourText(b.HourlyPriceCents, b.Currency) + "/hour"
	}
	if b.PriceCents > 0 {
		return mcp.PriceText(b.PriceCents, b.Currency) + "/month"
	}
	return "-"
}

func serverStatus(s client.CloudServer) string {
	st := s.Status
	if s.Status == "payment" {
		st = "waiting for payment"
	}
	if s.Step != "" && !strings.EqualFold(s.Step, s.Status) && !strings.EqualFold(s.Step, "ready") {
		st += " (" + s.Step + ")"
	}
	return st
}

func serverSize(s client.CloudServer) string {
	size := s.Size
	if s.PlanSize != nil && *s.PlanSize != "" {
		size = *s.PlanSize
	}
	return size
}

// cloudList: rowsafe cloud list [--json]
func cloudList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	list, err := c.CloudServerList(ctx)
	if err != nil {
		return cloudErr(err)
	}
	list = slices.DeleteFunc(list, func(s client.CloudServer) bool { return s.Status == "deleted" })
	if *asJSON {
		if list == nil {
			list = []client.CloudServer{}
		}
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No servers yet. See what they cost with `rowsafe cloud sizes`, then `rowsafe cloud create NAME`.")
		return nil
	}
	t := newTable("NAME", "STATUS", "WHERE", "SIZE", "PRICE", "CONNECT TO", "WHO CAN CONNECT")
	for _, s := range list {
		where := s.Provider + " " + s.Region
		if s.Billing != nil && s.Billing.Cloud != "" {
			where = s.Billing.Cloud + " " + s.Region
		}
		if s.Where == "account" {
			where += " (your account)"
		}
		host, _, _ := serverEndpoint(s)
		t.row(s.Name, serverStatus(s), where, serverSize(s), serverPrice(s), orText(host, "-"), sourcesText(s.AllowedIPs))
	}
	t.flush()
	return nil
}

// cloudShow: rowsafe cloud show [NAME] [--json]
func cloudShow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if full, err := c.CloudServer(ctx, s.ID); err == nil {
		s = full
	}
	if *asJSON {
		return printJSON(s)
	}
	printServer(s)
	if s.Status == "ready" {
		printNext(s)
	}
	return nil
}

func printServer(s client.CloudServer) {
	row := func(k, v string) { fmt.Printf("  %-19s %s\n", k+":", v) }
	fmt.Printf("%s (%s)\n", s.Name, s.ID)
	row("Status", serverStatus(s))
	if p := deref(s.Problem); p != "" {
		row("Problem", p)
	}
	cloud := s.Provider
	if s.Billing != nil && s.Billing.Cloud != "" {
		cloud = s.Billing.Cloud
	}
	where := cloud + ", " + s.Region
	if s.RegionName != "" && s.RegionName != s.Region {
		where += " (" + s.RegionName + ")"
	}
	if s.Where == "account" {
		where += ", in your own cloud account"
	}
	row("Where", where)
	size := serverSize(s)
	if s.Billing != nil && s.Billing.SizeName != "" && s.Billing.SizeName != size {
		size += " (" + s.Billing.SizeName + ")"
	}
	if z := s.SizeInfo; z != nil {
		size += fmt.Sprintf(": %d CPUs, %d GB memory, %d GB disk", z.CPUs, z.MemoryMB/1024, z.DiskGB)
	}
	if p := deref(s.PendingSize); p != "" {
		size += ", moving to " + p
	}
	row("Size", size)
	if b := s.Billing; b != nil {
		price := mcp.PriceText(b.PriceCents, b.Currency) + " a month"
		if b.Mode == "hourly" && b.HourlyPriceCents > 0 {
			price = mcp.HourText(b.HourlyPriceCents, b.Currency) + " an hour, at most " + mcp.PriceText(b.PriceCents, b.Currency) + " a month"
		}
		if b.Status != "" && b.Status != "active" {
			price += " (billing: " + b.Status + ")"
		}
		row("Price", price)
		if b.CheckoutURL != nil {
			row("Pay at", *b.CheckoutURL)
		}
	}
	if s.EngineVersion != "" {
		row("Database", protocol.EngineDisplayName(s.Engine)+" "+s.EngineVersion)
	}
	if len(s.Extensions) > 0 {
		row("Extensions", extensionTitles(s.Extensions))
	}
	if s.DatabaseRef != nil {
		row("Database in Rowsafe", *s.DatabaseRef)
	}
	if host, port, ssl := serverEndpoint(s); host != "" {
		if protocol.NormalizeEngine(s.Engine) == protocol.EnginePostgreSQL {
			row("Connect to", fmt.Sprintf("%s port %d, sslmode=%s", host, port, ssl))
		} else {
			row("Connect to", fmt.Sprintf("%s port %d, always with TLS (%s)", host, port, engineURLExample(s, host, port)))
			if e, ok := protocol.CloudEngineFor(s.Engine); ok && e.Engine == protocol.EngineClickHouse && len(e.Ports) > 1 {
				row("HTTPS interface", "https://"+net.JoinHostPort(host, strconv.Itoa(e.Ports[1])))
			}
			if e, ok := protocol.CloudEngineFor(s.Engine); ok && e.Engine == protocol.EngineQdrant && len(e.Ports) > 1 {
				row("gRPC", net.JoinHostPort(host, strconv.Itoa(e.Ports[1]))+" (TLS)")
				row("API key", "make one in the dashboard (Databases & users): it is shown once, to you only")
			}
		}
		if s.Address != nil && s.Address.ReadHost != "" && s.Address.ReadHost != host {
			row("Read-only queries", s.Address.ReadHost)
		}
	}
	who := sourcesText(s.AllowedIPs)
	if s.FirewallPending {
		who += " (being applied on the server)"
	}
	if p := deref(s.FirewallProblem); p != "" {
		who += " (problem: " + p + ")"
	}
	row("Who can connect", who)
	if sb := s.Standby; sb != nil {
		v := sb.Role
		if sb.PartnerName != "" {
			v += ", with " + sb.PartnerName
		}
		if sb.State != "" {
			v += " (" + sb.State + ")"
		}
		row("Standby", v)
	}
	if cl := s.Clone; cl != nil {
		v := cl.SourceName
		switch {
		case cl.Mark != nil:
			v += " at the Mark " + *cl.Mark
		case cl.At != nil:
			v += " as it was at " + describeTime(*cl.At)
		}
		row("Clone of", v)
	}
	if s.DeleteAt != nil {
		row("Deleted by itself", describeTime(*s.DeleteAt))
	}
	if s.DatabaseRef != nil && s.Clone == nil {
		if s.PassphraseSavedAt != nil {
			row("Backup passphrase", "saved "+ago(s.PassphraseSavedAt))
		} else {
			row("Backup passphrase", "not saved yet: rowsafe cloud passphrase "+s.Name+" --file FILE")
		}
	}
	row("Created", describeTime(s.CreatedAt)+prefix(" by ", s.CreatedBy))
}

func prefix(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

// ---- resize ----

// cloudResize: rowsafe cloud resize [NAME] SIZE [--yes] [--wait]
func cloudResize(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud resize", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask (--yes is the confirmation)")
	wait := fs.Bool("wait", false, "follow it until the server is ready again")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var ref, size string
	switch len(pos) {
	case 1:
		size = pos[0]
	case 2:
		ref, size = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe cloud resize [NAME] SIZE [--yes]")
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if serverSize(s) == size {
		return fmt.Errorf("%s already has the size %s", s.Name, size)
	}
	what := fmt.Sprintf("Change %s from %s to %s", s.Name, serverSize(s), size)
	if s.Where == "rowsafe" {
		if cat, err := c.CloudCatalog(ctx); err == nil {
			for _, cl := range cat.Clouds {
				if cl.Provider != s.Provider {
					continue
				}
				i := slices.IndexFunc(cl.Sizes, func(z client.CloudSize) bool { return z.ID == size })
				if i < 0 {
					var ids []string
					for _, z := range cl.Sizes {
						ids = append(ids, z.ID)
					}
					return fmt.Errorf("%s has no size %q: choose %s", cl.Name, size, strings.Join(ids, ", "))
				}
				z := cl.Sizes[i]
				if s.SizeInfo != nil && z.DiskGB < s.SizeInfo.DiskGB {
					return fmt.Errorf("a server's disk can't shrink: choose a size with at least %d GB of disk", s.SizeInfo.DiskGB)
				}
				what += fmt.Sprintf(" (%d CPUs, %d GB memory, %d GB disk: %s)", z.CPUs, z.MemoryGB, z.DiskGB, sizePrice(cl, z))
				if s.SizeInfo != nil && z.DiskGB > s.SizeInfo.DiskGB {
					what += ". The bigger disk stays: disks never shrink"
				}
			}
		}
	}
	fmt.Println(what + ".")
	if s.Standby != nil {
		fmt.Println("Both servers of the pair change, one at a time, with a switchover in between (writes pause for a few seconds); each is billed at the new size. Rowsafe saves a Mark first.")
	} else {
		fmt.Println("The database is offline for a few minutes while the server restarts. Rowsafe saves a Mark first.")
	}
	if !*yes {
		if !stdinIsTerminal() {
			return errors.New("changing the size restarts the server: pass --yes to confirm")
		}
		if !confirm("Change the size now?") {
			return errors.New("cancelled; nothing changed")
		}
	}
	s, err = c.ResizeCloudServer(ctx, s.ID, size)
	if err != nil {
		return apiErr(err)
	}
	if !*wait {
		fmt.Printf("Changing the size of %s. Follow it with `rowsafe cloud wait %s`.\n", s.Name, s.Name)
		return nil
	}
	if s, err = waitServer(ctx, c, s.ID, 45*time.Minute, os.Stderr); err != nil {
		return err
	}
	fmt.Printf("%s is ready with the size %s.\n", s.Name, serverSize(s))
	return nil
}

// ---- who can connect ----

// cloudAllow: rowsafe cloud allow [NAME] [me|IP|CIDR]...
func cloudAllow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud allow", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask (opening it to everyone)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	ref := ""
	if len(pos) > 0 && !looksLikeSource(pos[0]) {
		ref, pos = pos[0], pos[1:]
	}
	if len(pos) == 0 {
		pos = []string{"me"}
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	add, err := expandAddresses(ctx, c.BaseURL, pos)
	if err != nil {
		return err
	}
	return setFirewall(ctx, c, s, dedupe(append(slices.Clone(s.AllowedIPs), add...)), *yes)
}

// cloudFirewall: rowsafe cloud firewall [NAME] [--set A,B | --add A | --remove A | --clear] [--yes] [--json]
func cloudFirewall(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud firewall", flag.ContinueOnError)
	var set, add, remove csvList
	fs.Var(&set, "set", "the whole list of who can connect (me, IP addresses, networks; comma-separated)")
	fs.Var(&add, "add", "add addresses or networks (me: this computer)")
	fs.Var(&remove, "remove", "remove addresses or networks")
	clear := fs.Bool("clear", false, "nobody can connect")
	yes := fs.Bool("yes", false, "don't ask")
	asJSON := fs.Bool("json", false, "print who can connect as JSON")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if len(set) == 0 && len(add) == 0 && len(remove) == 0 && !*clear {
		if *asJSON {
			return printJSON(struct {
				AllowedIPs []string `json:"allowed_ips"`
				Pending    bool     `json:"pending"`
			}{nonNilList(s.AllowedIPs), s.FirewallPending})
		}
		fmt.Printf("Who can connect to %s: %s.\n", s.Name, sourcesText(s.AllowedIPs))
		if s.FirewallPending {
			fmt.Println("The server's own firewall is still applying it.")
		}
		fmt.Printf("Change it with rowsafe cloud allow %s [me|IP], or rowsafe cloud firewall %s --set/--add/--remove.\n", s.Name, s.Name)
		return nil
	}
	if *clear && (len(set) > 0 || len(add) > 0) {
		return errors.New("--clear and --set/--add don't go together")
	}
	list := slices.Clone(s.AllowedIPs)
	switch {
	case *clear:
		list = nil
	case len(set) > 0:
		if list, err = expandAddresses(ctx, c.BaseURL, set); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		more, err := expandAddresses(ctx, c.BaseURL, add)
		if err != nil {
			return err
		}
		list = dedupe(append(list, more...))
	}
	if len(remove) > 0 {
		gone, err := expandAddresses(ctx, c.BaseURL, remove)
		if err != nil {
			return err
		}
		for _, g := range gone {
			if !slices.Contains(list, g) {
				return fmt.Errorf("%s isn't in the list of who can connect to %s (%s)", shortSource(g), s.Name, sourcesText(list))
			}
		}
		list = slices.DeleteFunc(list, func(v string) bool { return slices.Contains(gone, v) })
	}
	return setFirewall(ctx, c, s, list, *yes)
}

func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// setFirewall replaces who can connect, after a question when addresses
// lose access or the server opens to everyone.
func setFirewall(ctx context.Context, c *client.Client, s client.CloudServer, list []string, yes bool) error {
	var lost []string
	for _, v := range s.AllowedIPs {
		if !slices.Contains(list, v) {
			lost = append(lost, v)
		}
	}
	if len(lost) == 0 && len(list) == len(s.AllowedIPs) {
		fmt.Printf("Nothing to change: who can connect to %s is %s.\n", s.Name, sourcesText(list))
		return nil
	}
	var warn []string
	if len(lost) > 0 {
		warn = append(warn, fmt.Sprintf("Apps and people connecting from %s won't be able to connect to %s anymore.", sourcesText(lost), s.Name))
	}
	for _, v := range list {
		if (v == "0.0.0.0/0" || v == "::/0") && !slices.Contains(s.AllowedIPs, v) {
			warn = append(warn, "Anyone on the internet can then try to connect (they still need a user and its password).")
			break
		}
	}
	if len(warn) > 0 && !yes {
		fmt.Println(strings.Join(warn, " "))
		if !stdinIsTerminal() {
			return errors.New("pass --yes to confirm")
		}
		if !confirm("Change who can connect?") {
			return errors.New("cancelled; nothing changed")
		}
	}
	out, err := c.SetCloudFirewall(ctx, s.ID, list, s.SSHIPs)
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("Who can connect to %s now: %s.\n", out.Name, sourcesText(out.AllowedIPs))
	if out.FirewallPending {
		fmt.Println("The server's own firewall applies it within a minute.")
	}
	return nil
}

// ---- delete ----

// cloudDelete: rowsafe cloud delete [NAME] [--with-standby] [--yes] [--wait]
func cloudDelete(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud delete", flag.ContinueOnError)
	withStandby := fs.Bool("with-standby", false, "the server has a standby server: delete both")
	yes := fs.Bool("yes", false, "don't ask you to type the name (--yes is the confirmation)")
	wait := fs.Bool("wait", false, "wait until it's gone")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	if ref == "" && *yes {
		return errors.New("name the server to delete: rowsafe cloud delete NAME --yes")
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if s.Status == "deleting" {
		fmt.Printf("%s is already being deleted.\n", s.Name)
		return nil
	}
	if s.DatabaseRef != nil && s.PassphraseSavedAt == nil && s.Clone == nil {
		return fmt.Errorf("save %s's backup passphrase first: without it, its backups can't be restored once the server is gone.\n"+
			"Run `rowsafe cloud passphrase %s --file %s-backup-passphrase.txt` (it is encrypted for this terminal only, Rowsafe can't read it), keep the file somewhere safe, then delete again", s.Name, s.Name, s.Name)
	}
	partner := ""
	if sb := s.Standby; sb != nil {
		partner = orText(sb.PartnerName, sb.PartnerID)
		if sb.Role == "primary" && !*withStandby {
			return fmt.Errorf("%s has a standby server, %s, which is deleted with it: pass --with-standby to delete both", s.Name, partner)
		}
	}
	what := fmt.Sprintf("This deletes the server %s", s.Name)
	switch {
	case s.Standby != nil && s.Standby.Role == "standby":
		what = fmt.Sprintf("This deletes %s, the standby server of %s; %s keeps running without a standby", s.Name, partner, partner)
	case s.DatabaseRef != nil:
		what += " and the database on it, " + *s.DatabaseRef
		if partner != "" {
			what += ", and its standby server " + partner
		}
	}
	fmt.Println(what + ". It can't be undone.")
	if s.Billing != nil && s.Billing.Mode == "hourly" {
		fmt.Println("Billing by the hour stops once it's deleted.")
	}
	if !*yes {
		if !stdinIsTerminal() {
			return errors.New("deleting a server can't be undone: pass --yes to confirm")
		}
		fmt.Printf("Type the server's name (%s) to delete it: ", s.Name)
		if strings.TrimSpace(readLine()) != s.Name {
			return errors.New("cancelled; nothing was deleted")
		}
	}
	out, err := c.DeleteCloudServer(ctx, s.ID, s.Name, s.PassphraseSavedAt != nil, *withStandby)
	if err != nil {
		return apiErr(err)
	}
	if !*wait || out.Status == "deleted" {
		fmt.Printf("Deleting %s. `rowsafe cloud list` shows it until it's gone.\n", out.Name)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	for out.Status != "deleted" {
		if err := sleepCtx(ctx, cloudPoll); err != nil {
			return fmt.Errorf("%s is still being deleted; `rowsafe cloud list` shows it until it's gone", out.Name)
		}
		cur, err := c.CloudServer(ctx, out.ID)
		if apiStatus(err) == http.StatusNotFound {
			break
		}
		if err == nil {
			out = cur
			if out.Status == "failed" {
				return fmt.Errorf("deleting %s failed: %s", out.Name, orText(deref(out.Problem), "no reason given"))
			}
		}
	}
	fmt.Printf("Deleted %s.\n", out.Name)
	return nil
}

// ---- backup passphrase ----

// cloudPassphrase: rowsafe cloud passphrase [NAME] [--file PATH]
func cloudPassphrase(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud passphrase", flag.ContinueOnError)
	file := fs.String("file", "", "write it to this new file (readable only by you) instead of showing it")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if s.DatabaseRef == nil {
		return fmt.Errorf("%s has no database yet, so it has no backups or passphrase", s.Name)
	}
	if *file != "" {
		if _, err := os.Stat(*file); err == nil {
			return fmt.Errorf("%s already exists: choose another --file", *file)
		}
	}
	key, err := newSealKey()
	if err != nil {
		return err
	}
	ref = *s.DatabaseRef
	taskID, err := c.RequestBackupPassphrase(ctx, ref, protocol.EncodeSealKey(key.PublicKey()))
	if err != nil {
		return apiErr(err)
	}
	fmt.Fprintln(os.Stderr, "Asking the server for it, encrypted for this terminal only...")
	t, err := c.WaitTask(ctx, taskID, nil)
	if err != nil {
		return err
	}
	if t.Status != protocol.StatusSucceeded {
		return errors.New(orText(t.Error, "the task "+t.Status))
	}
	sealed, err := c.BackupPassphraseSecret(ctx, ref, taskID)
	if err != nil {
		return apiErr(err)
	}
	plain, err := protocol.Open(key, []byte(taskID), &sealed)
	if err != nil {
		return err
	}
	defer clear(plain)
	var sec protocol.BackupPassphraseSecret
	if err := json.Unmarshal(plain, &sec); err != nil {
		return err
	}
	if *file != "" {
		body := fmt.Sprintf("Rowsafe backup passphrase for %s (database %s), saved %s.\nWithout it the backups can't be restored. Keep it somewhere safe, like a password manager.\n\npassphrase: %s\n",
			s.Name, ref, time.Now().Format("2006-01-02 15:04"), sec.Passphrase)
		if sec.SecondCopy != "" {
			body += "second copy's passphrase: " + sec.SecondCopy + "\n"
		}
		f, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(body); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("Saved %s's backup passphrase to %s (readable only by you). Keep a copy somewhere safe, like a password manager.\n", s.Name, *file)
	} else {
		fmt.Printf("%s's backup passphrase (Rowsafe can't read it; keep it somewhere safe, like a password manager):\n\n  %s\n\n", s.Name, sec.Passphrase)
		if sec.SecondCopy != "" {
			fmt.Printf("The second copy's passphrase:\n\n  %s\n\n", sec.SecondCopy)
		}
		if !stdinIsTerminal() || !confirm("Did you save it?") {
			fmt.Fprintf(os.Stderr, "Not recorded as saved: run it again with --file, or answer yes in a terminal.\n")
			return nil
		}
	}
	if _, err := c.CloudPassphraseSaved(ctx, s.ID); err != nil {
		return fmt.Errorf("recording that it was saved: %w", apiErr(err))
	}
	return nil
}

// ---- clone ----

// cloudClone: rowsafe cloud clone [SOURCE] NAME [--at TIME | --mark LABEL] [--delete-after 24h]
// [--region R] [--size S] [--allow me|IP]... [--wait] [--yes] [--json]
func cloudClone(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud clone", flag.ContinueOnError)
	at, mark := rewindTargetFlags(fs)
	deleteAfter := fs.String("delete-after", "", "Rowsafe deletes the clone this long after it's ready: 4h, 2d... at most 30d (default: kept until you delete it)")
	cloudName := fs.String("cloud", "", "the cloud (default: the source's, else the cheapest)")
	region := fs.String("region", "", "the region (default: the source's, else where the cheapest size is free)")
	size := fs.String("size", "", "the size (default: the source's, else the cheapest free now)")
	var allow csvList
	fs.Var(&allow, "allow", "who can connect: me (this computer), an IP address or a network (default: me; none: nobody yet)")
	wait := fs.Bool("wait", false, "follow it until it's ready")
	yes := fs.Bool("yes", false, "don't ask (it costs money: --yes is the confirmation)")
	asJSON := fs.Bool("json", false, "print the server as JSON (messages go to stderr)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var source, name string
	switch len(pos) {
	case 1:
		name = pos[0]
	case 2:
		source, name = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe cloud clone [SOURCE] NAME [--at TIME | --mark LABEL] [--delete-after 24h]")
	}
	if err := checkServerName(name); err != nil {
		return err
	}
	if source, err = resolveDatabase(ctx, c, source); err != nil {
		return err
	}
	var when *time.Time
	markName, whenText := "", "as it is now"
	if *at != "" || *mark != "" {
		var desc string
		if when, markName, desc, err = rewindTarget(*at, *mark); err != nil {
			return err
		}
		whenText = "as it was at " + desc
		if markName != "" {
			whenText = "at " + desc
		}
	}
	hours := 0
	if v := strings.TrimSpace(*deleteAfter); v != "" && v != "0" && v != "never" {
		d, err := parseSince(v)
		if err != nil {
			return fmt.Errorf("can't read --delete-after %q: use e.g. 4h, 2d (at most 30d)", v)
		}
		if hours = int(math.Ceil(d.Hours())); hours < 1 || hours > 720 {
			return errors.New("--delete-after must be between 1 hour and 30 days")
		}
	}
	cat, err := c.CloudCatalog(ctx)
	if err != nil {
		return cloudErr(err)
	}
	// Next to the source by default, at its size, when it runs in Rowsafe
	// Cloud by the hour.
	pick, err := pickCloud(cat, *cloudName, *region, *size, true)
	if src := cloudServerFor(ctx, c, source); src != nil && src.Where == "rowsafe" && *cloudName == "" && *region == "" {
		srcSize := *size
		if srcSize == "" {
			srcSize = serverSize(*src)
		}
		if p, err2 := pickCloud(cat, src.Provider, src.Region, srcSize, true); err2 == nil {
			pick, err = p, nil
		} else if p, err2 := pickCloud(cat, src.Provider, src.Region, *size, true); err2 == nil {
			pick, err = p, nil
		}
	}
	if err != nil {
		return err
	}
	allowed, err := allowedFor(ctx, c, allow)
	if err != nil {
		return err
	}
	out := msgOut(*asJSON)
	fmt.Fprintf(out, "Clone %s %s onto a new server %s: %s.\n", source, whenText, name, pick.describe(false))
	if hours > 0 {
		fmt.Fprintf(out, "Rowsafe deletes it %d hours after it's ready.\n", hours)
	} else {
		fmt.Fprintln(out, "It's kept (and billed by the hour) until you delete it: --delete-after 24h deletes it by itself.")
	}
	fmt.Fprintf(out, "Who can connect: %s.\n", sourcesText(allowed))
	if err := confirmMoney(*yes, "create the clone "+name); err != nil {
		return err
	}
	res, err := c.CloneToNewServer(ctx, source, client.CreateCloneRequest{Where: "rowsafe", Provider: pick.Cloud.Provider, Region: pick.Region.ID,
		Size: pick.Size.ID, Name: name, At: when, Mark: markName, DeleteAfterHours: hours, AllowedIPs: allowed})
	if err != nil {
		return apiErr(err)
	}
	return afterCreate(ctx, c, res, true, *wait, *asJSON)
}

// ---- retry ----

// cloudRetry: rowsafe cloud retry [NAME]
func cloudRetry(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud retry", flag.ContinueOnError)
	wait := fs.Bool("wait", false, "follow it until it's ready")
	ref, err := optionalName(fs, args)
	if err != nil {
		return err
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	if s.Status != "failed" {
		return fmt.Errorf("%s is %s: only a server that failed to set up can be created again", s.Name, serverStatus(s))
	}
	if s, err = c.RetryCloudServer(ctx, s.ID); err != nil {
		return apiErr(err)
	}
	if *wait {
		if s, err = waitServer(ctx, c, s.ID, 45*time.Minute, os.Stderr); err != nil {
			return err
		}
		printServer(s)
		printNext(s)
		return nil
	}
	fmt.Printf("Creating %s again. Follow it with `rowsafe cloud wait %s`.\n", s.Name, s.Name)
	return nil
}
