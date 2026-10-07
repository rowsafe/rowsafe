package mcp

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rowsafe Cloud, read-only: the catalog (clouds, regions, sizes and their
// prices) and the servers Rowsafe created. Asking for a server, a firewall
// change, a new size, a clone or a deletion is request_change (the "cloud"
// group): a person approves it in the dashboard, where the price is shown.

// ---- outputs ----

// CloudCatalogOutput is cloud_catalog's result.
type CloudCatalogOutput struct {
	Clouds []CatalogCloud `json:"clouds"`
	// PayAsYouGo is the org's pay-as-you-go subscription (clouds billed by
	// the hour): none, active, canceling, past_due or ended.
	PayAsYouGo       string `json:"pay_as_you_go" jsonschema:"the org's pay-as-you-go subscription for clouds billed by the hour: none (the first server goes through a checkout), active (servers are created right away), canceling, past_due or ended"`
	MaxServers       int    `json:"max_servers" jsonschema:"Rowsafe Cloud servers the organization may have at a time"`
	MaxHourlyServers int    `json:"max_hourly_servers" jsonschema:"of them, billed by the hour"`
	// Cheapest is the cheapest size that is free somewhere right now.
	Cheapest *CatalogPick `json:"cheapest,omitempty"`
	Guidance string       `json:"guidance"`
}

// CatalogCloud is one cloud in the catalog.
type CatalogCloud struct {
	Provider string               `json:"provider"`
	Name     string               `json:"name"`
	Billing  string               `json:"billing" jsonschema:"hourly (billed by the hour, never more than the monthly price) or monthly (a subscription per server)"`
	Standby  bool                 `json:"standby" jsonschema:"servers here can have a standby server (doubles the price)"`
	Regions  []client.CloudRegion `json:"regions"`
	Sizes    []CatalogSize        `json:"sizes"`
}

// CatalogSize is one size of a cloud, with its price there.
type CatalogSize struct {
	ID           string   `json:"id" jsonschema:"what create_cloud_server's size takes"`
	Name         string   `json:"name"`
	CPUs         int      `json:"cpus"`
	MemoryGB     int      `json:"memory_gb"`
	DiskGB       int      `json:"disk_gb"`
	PerMonth     string   `json:"per_month" jsonschema:"the price of a month; for hourly clouds the most a month costs"`
	PerHour      string   `json:"per_hour,omitempty" jsonschema:"hourly clouds: the price of an hour"`
	MonthlyCents int64    `json:"monthly_cents"`
	Currency     string   `json:"currency"`
	Regions      []string `json:"regions,omitempty" jsonschema:"region IDs it is offered in (empty: all of the cloud's)"`
	SoldOutIn    []string `json:"sold_out_in,omitempty" jsonschema:"region IDs where none is free right now"`
	Traffic      string   `json:"traffic,omitempty" jsonschema:"outbound traffic included per month and the price above it"`
}

// CatalogPick is one size in one region.
type CatalogPick struct {
	Cloud    string `json:"cloud"`
	Region   string `json:"region"`
	Size     string `json:"size"`
	PerMonth string `json:"per_month"`
	PerHour  string `json:"per_hour,omitempty"`
}

// CloudServerView is a server Rowsafe created, for an assistant.
type CloudServerView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Where      string   `json:"where" jsonschema:"rowsafe (Rowsafe Cloud) or account (the organization's own cloud account)"`
	Cloud      string   `json:"cloud"`
	Region     string   `json:"region"`
	RegionName string   `json:"region_name,omitempty"`
	Size       string   `json:"size"`
	Status     string   `json:"status" jsonschema:"payment (waiting for payment), creating, installing, ready, resizing, deleting, deleted or failed"`
	Step       string   `json:"step,omitempty" jsonschema:"where it is, in plain words"`
	Problem    string   `json:"problem,omitempty"`
	Price      string   `json:"price,omitempty"`
	PostgreSQL string   `json:"postgresql,omitempty" jsonschema:"the PostgreSQL major version"`
	Database   string   `json:"database,omitempty" jsonschema:"its database in Rowsafe (name), once ready: what database takes in the other tools"`
	AllowedIPs []string `json:"allowed_ips" jsonschema:"who can connect to PostgreSQL (cloud_firewall changes it)"`
	// Connection: how apps connect (everything but the user and password).
	Host        string     `json:"host,omitempty" jsonschema:"the name apps connect to (it follows the primary)"`
	ReadHost    string     `json:"read_host,omitempty" jsonschema:"the name for read-only queries (the standby, else the primary)"`
	Port        int        `json:"port,omitempty"`
	SSLMode     string     `json:"sslmode,omitempty" jsonschema:"require, or verify-full once a public certificate is installed"`
	CheckoutURL string     `json:"checkout_url,omitempty" jsonschema:"waiting for payment: where an owner pays"`
	Standby     string     `json:"standby,omitempty"`
	CloneOf     string     `json:"clone_of,omitempty"`
	DeleteAt    *time.Time `json:"delete_at,omitempty" jsonschema:"when Rowsafe deletes it (clones)"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CloudServersOutput is list_cloud_servers' result.
type CloudServersOutput struct {
	Servers []CloudServerView `json:"servers"`
}

// CloudServerOutput is get_cloud_server's result.
type CloudServerOutput struct {
	Server   CloudServerView `json:"server"`
	Guidance string          `json:"guidance"`
}

type cloudServerInput struct {
	Server      string `json:"server" jsonschema:"the server's name or ID (cs_...): list_cloud_servers shows them, get_approval shows the ID of one an approval created"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"while it is being created, installed or resized, wait up to this many seconds for it to be ready (0 returns at once); call again to keep waiting"`
}

// ---- registration ----

func (t *tools) addRowsafeCloudReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "cloud_catalog",
		Description: "Shows what a new Rowsafe Cloud server can be: each cloud with its regions and sizes (CPUs, memory, disk), the price of an hour and the most a month costs " +
			"(or the monthly price), the traffic included, where a size is sold out right now, whether servers there can have a standby, whether the organization's pay as you go is active, " +
			"and how many servers it may have. Use it before create_cloud_server or clone_to_new_server (request_change) to pick the region and the cheapest size that fits. Read-only.",
		Annotations: readOnly("Rowsafe Cloud catalog"),
	}, t.cloudCatalog)

	sdk.AddTool(s, &sdk.Tool{
		Name: "list_cloud_servers",
		Description: "Lists the servers Rowsafe created for the organization (Rowsafe Cloud, and servers in its own cloud accounts): status and progress, region, size and price, " +
			"the name apps connect to, who can connect and the database once ready. Read-only.",
		Annotations: readOnly("Rowsafe Cloud servers"),
	}, t.listCloudServers)

	sdk.AddTool(s, &sdk.Tool{
		Name: "get_cloud_server",
		Description: "Shows one server Rowsafe created: status and progress step (or what went wrong), region, size and price, how apps connect (host name like x7kq2mfa3pzd.cloud.rowsafe.sh, read-only host, port, sslmode), " +
			"who can connect, its database once ready, and what to do next. With wait_seconds it waits while the server is being set up. Read-only.",
		Annotations: readOnly("Rowsafe Cloud server"),
		InputSchema: withWait[cloudServerInput](nil),
	}, t.getCloudServer)
}

// ---- cloud_catalog ----

func (t *tools) cloudCatalog(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, CloudCatalogOutput, error) {
	cat, err := t.c.CloudCatalog(ctx)
	if isStatus(err, 404) {
		return nil, CloudCatalogOutput{}, fmt.Errorf("Rowsafe Cloud isn't offered on this Rowsafe server: the user can protect a database on a server they run, or create one in their own cloud account from the dashboard")
	}
	if err != nil {
		return nil, CloudCatalogOutput{}, apiError(err)
	}
	out := CloudCatalogOutput{Clouds: []CatalogCloud{}, PayAsYouGo: cmpOr(cat.Payg.Status, "none"), MaxServers: cat.MaxServers, MaxHourlyServers: cat.MaxHourlyServers}
	var b textBuilder
	var best *CatalogPick
	var bestCents int64 = math.MaxInt64
	for _, c := range cat.Clouds {
		cc := CatalogCloud{Provider: c.Provider, Name: c.Name, Billing: c.Billing, Standby: c.Standby, Regions: c.Regions, Sizes: []CatalogSize{}}
		billing := "a subscription per server, paid before it is created"
		if c.Billing == "hourly" {
			billing = "billed by the hour, never more than the monthly price"
		}
		standby := ""
		if c.Standby {
			standby = "; a standby server can be added (it doubles the price)"
		}
		b.line("%s (%s%s):", c.Name, billing, standby)
		regions := make([]string, 0, len(c.Regions))
		for _, r := range c.Regions {
			regions = append(regions, r.ID+" "+cmpOr(r.Name, r.ID))
		}
		b.line("  regions: %s", strings.Join(regions, "; "))
		for _, z := range c.Sizes {
			sz := CatalogSize{ID: z.ID, Name: z.Name, CPUs: z.CPUs, MemoryGB: z.MemoryGB, DiskGB: z.DiskGB, MonthlyCents: z.PriceCents,
				Currency: z.Currency, PerMonth: priceText(z.PriceCents, z.Currency), Regions: z.Regions, SoldOutIn: z.UnavailableRegions, Traffic: trafficText(z)}
			price := sz.PerMonth + " a month"
			if c.Billing == "hourly" && z.HourlyPriceCents > 0 {
				sz.PerHour = hourText(z.HourlyPriceCents, z.Currency)
				price = sz.PerHour + " an hour, at most " + sz.PerMonth + " a month"
			}
			line := fmt.Sprintf("  size %s (%s): %d CPUs, %d GB memory, %d GB disk, %s", z.ID, z.Name, z.CPUs, z.MemoryGB, z.DiskGB, price)
			if sz.Traffic != "" {
				line += "; " + sz.Traffic
			}
			if len(z.Regions) > 0 {
				line += "; only in " + strings.Join(z.Regions, ", ")
			}
			if len(z.UnavailableRegions) > 0 {
				line += "; sold out now in " + strings.Join(z.UnavailableRegions, ", ")
			}
			b.line("%s", line)
			cc.Sizes = append(cc.Sizes, sz)
			// The cheapest size free somewhere right now.
			if z.PriceCents > 0 && z.PriceCents < bestCents {
				for _, r := range c.Regions {
					if (len(z.Regions) == 0 || slices.Contains(z.Regions, r.ID)) && !slices.Contains(z.UnavailableRegions, r.ID) {
						best, bestCents = &CatalogPick{Cloud: c.Name, Region: r.ID, Size: z.ID, PerMonth: sz.PerMonth, PerHour: sz.PerHour}, z.PriceCents
						break
					}
				}
			}
		}
		out.Clouds = append(out.Clouds, cc)
	}
	if len(cat.Clouds) == 0 {
		b.line("Rowsafe Cloud has no locations open right now.")
	}
	out.Cheapest = best
	switch out.PayAsYouGo {
	case "active":
		b.line("Pay as you go is active: servers billed by the hour are created as soon as a person approves.")
	case "past_due":
		b.line("Pay as you go: the last payment failed; an owner updates the payment method in Settings → Billing before new hourly servers can be created.")
	case "canceling":
		b.line("Pay as you go is canceled: an owner keeps it in Settings → Billing before new hourly servers can be created.")
	default:
		b.line("Pay as you go isn't active yet: the first server billed by the hour goes through a checkout right after a person approves it (an owner pays), and is created once paid.")
	}
	b.line("The organization may have %d Rowsafe Cloud servers at a time (%d billed by the hour).", cat.MaxServers, cat.MaxHourlyServers)
	if best != nil {
		price := best.PerMonth + " a month"
		if best.PerHour != "" {
			price = best.PerHour + " an hour, at most " + best.PerMonth + " a month"
		}
		b.line("Cheapest free now: %s size %s in %s (%s).", best.Cloud, best.Size, best.Region, price)
	}
	out.Guidance = "Pick the cheapest size that fits the app (a small app's database fits the smallest size), in a region near the app. " +
		"Then ask for it with request_change create_cloud_server (name, region, size, allowed_ips; the reason says what it's for). Nothing is created or billed until a person approves it."
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

// ---- list_cloud_servers, get_cloud_server ----

func (t *tools) listCloudServers(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, CloudServersOutput, error) {
	list, err := t.c.CloudServerList(ctx)
	if err != nil {
		return nil, CloudServersOutput{}, apiError(err)
	}
	out := CloudServersOutput{Servers: []CloudServerView{}}
	var b textBuilder
	for _, c := range list {
		if c.Status == "deleted" {
			continue
		}
		v := cloudServerView(c)
		out.Servers = append(out.Servers, v)
		b.line("%s", cloudServerLine(v))
	}
	if len(out.Servers) == 0 {
		b.line("Rowsafe hasn't created any servers for this organization. cloud_catalog shows what a Rowsafe Cloud server can be; request_change create_cloud_server asks a person for one.")
	}
	return text(b), out, nil
}

func (t *tools) getCloudServer(ctx context.Context, _ *sdk.CallToolRequest, in cloudServerInput) (*sdk.CallToolResult, CloudServerOutput, error) {
	c, err := t.findCloudServer(ctx, in.Server)
	if err != nil {
		return nil, CloudServerOutput{}, err
	}
	if in.WaitSeconds > 0 && settingUp(c.Status) {
		deadline := time.Now().Add(min(time.Duration(in.WaitSeconds)*time.Second, t.opts.MaxWait, maxWaitLimit))
		for settingUp(c.Status) && time.Until(deadline) > 0 {
			select {
			case <-ctx.Done():
				return nil, CloudServerOutput{}, fmt.Errorf("stopped waiting (call get_cloud_server again): %w", ctx.Err())
			case <-time.After(min(cloudPoll, time.Until(deadline))):
			}
			if c, err = t.c.CloudServer(ctx, c.ID); err != nil {
				return nil, CloudServerOutput{}, apiError(err)
			}
		}
	}
	v := cloudServerView(c)
	out := CloudServerOutput{Server: v, Guidance: cloudServerGuidance(v, t.opts.AllowWrites)}
	var b textBuilder
	b.line("%s", cloudServerLine(v))
	if v.Host != "" {
		b.line("Apps connect to %s port %d with sslmode=%s (read-only queries: %s). Who can connect: %s.", v.Host, v.Port, v.SSLMode, cmpOr(v.ReadHost, v.Host), allowedText(v.AllowedIPs))
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

// cloudPoll is how often get_cloud_server re-reads a server while waiting.
var cloudPoll = 5 * time.Second

func settingUp(status string) bool {
	switch status {
	case "creating", "installing", "resizing":
		return true
	}
	return false
}

// findCloudServer finds a server by ID or name.
func (t *tools) findCloudServer(ctx context.Context, ref string) (client.CloudServer, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "cs_") {
		c, err := t.c.CloudServer(ctx, ref)
		if err == nil {
			return c, nil
		}
		if !isStatus(err, 404) {
			return c, apiError(err)
		}
	}
	list, err := t.c.CloudServerList(ctx)
	if err != nil {
		return client.CloudServer{}, apiError(err)
	}
	for _, c := range list {
		if c.Status != "deleted" && (c.ID == ref || c.Name == ref) {
			return c, nil
		}
	}
	return client.CloudServer{}, fmt.Errorf("no server named %q was created by Rowsafe in this organization (list_cloud_servers shows them)", ref)
}

// serverHolding finds the server Rowsafe created that runs a database.
func serverHolding(list []client.CloudServer, d protocol.Database) *client.CloudServer {
	for i, c := range list {
		if c.Status == "deleted" || c.DatabaseRef == nil {
			continue
		}
		if *c.DatabaseRef == d.Name || *c.DatabaseRef == d.ID {
			// A pair names the database on both: the primary has it.
			if c.Standby != nil && c.Standby.Role == "standby" {
				continue
			}
			return &list[i]
		}
	}
	return nil
}

func cloudServerView(c client.CloudServer) CloudServerView {
	v := CloudServerView{ID: c.ID, Name: c.Name, Where: c.Where, Cloud: c.Provider, Region: c.Region, RegionName: c.RegionName, Size: c.Size,
		Status: c.Status, Step: c.Step, PostgreSQL: c.EngineVersion, AllowedIPs: nonNilStrings(c.AllowedIPs), DeleteAt: c.DeleteAt, CreatedAt: c.CreatedAt}
	if c.Problem != nil {
		v.Problem = *c.Problem
	}
	if c.DatabaseRef != nil {
		v.Database = *c.DatabaseRef
	}
	if c.PlanSize != nil && *c.PlanSize != "" {
		v.Size = *c.PlanSize
	}
	if bl := c.Billing; bl != nil {
		v.Cloud = cmpOr(bl.Cloud, v.Cloud)
		if bl.SizeName != "" {
			v.Size += " (" + bl.SizeName + ")"
		}
		switch {
		case bl.Mode == "hourly" && bl.HourlyPriceCents > 0:
			v.Price = hourText(bl.HourlyPriceCents, bl.Currency) + " an hour, at most " + priceText(bl.PriceCents, bl.Currency) + " a month"
		case bl.PriceCents > 0:
			v.Price = priceText(bl.PriceCents, bl.Currency) + " a month"
		}
		if bl.CheckoutURL != nil {
			v.CheckoutURL = *bl.CheckoutURL
		}
	}
	if a := c.Address; a != nil && a.Host != "" {
		v.Host, v.ReadHost, v.Port, v.SSLMode = a.Host, a.ReadHost, 5432, cmpOr(a.SSLMode, "require")
	} else if c.IPv4 != nil && *c.IPv4 != "" {
		v.Host, v.Port, v.SSLMode = *c.IPv4, 5432, "require"
	}
	if s := c.Standby; s != nil {
		v.Standby = s.Role
		if s.PartnerName != "" {
			v.Standby += ", with " + s.PartnerName
		}
		if s.State != "" {
			v.Standby += " (" + s.State + ")"
		}
	}
	if cl := c.Clone; cl != nil {
		v.CloneOf = cl.SourceName
	}
	return v
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func cloudServerLine(v CloudServerView) string {
	where := "Rowsafe Cloud"
	if v.Where == "account" {
		where = "your cloud account"
	}
	line := fmt.Sprintf("%s (%s): %s", v.Name, v.ID, v.Status)
	if v.Step != "" && v.Step != "Ready" && !strings.EqualFold(v.Step, v.Status) {
		line += " (" + v.Step + ")"
	}
	line += fmt.Sprintf(", %s, %s %s, size %s", where, v.Cloud, cmpOr(v.RegionName, v.Region), v.Size)
	if v.Price != "" {
		line += ", " + v.Price
	}
	if v.PostgreSQL != "" {
		line += ", PostgreSQL " + v.PostgreSQL
	}
	if v.Database != "" {
		line += ", database " + v.Database
	}
	if v.Host != "" {
		line += ", host " + v.Host
	}
	if v.Standby != "" {
		line += ", " + v.Standby
	}
	if v.CloneOf != "" {
		line += ", a clone of " + v.CloneOf
	}
	if v.DeleteAt != nil {
		line += ", deleted at " + v.DeleteAt.UTC().Format(time.RFC3339)
	}
	if v.Problem != "" {
		line += ". Problem: " + v.Problem
	}
	return line
}

func allowedText(ips []string) string {
	if len(ips) == 0 {
		return "nobody yet"
	}
	return strings.Join(ips, ", ")
}

func cloudServerGuidance(v CloudServerView, canAsk bool) string {
	ask := func(what string) string {
		if canAsk {
			return what
		}
		return "the user can do it in the Rowsafe dashboard (you can't ask for changes with this connection)"
	}
	switch v.Status {
	case "payment":
		g := "It waits for payment: nothing is created or billed before. An owner of the organization pays at the checkout"
		if v.CheckoutURL != "" {
			g += " (" + v.CheckoutURL + ")"
		}
		return g + "; the server is created once it's paid. Tell the user, then follow it with get_cloud_server."
	case "creating", "installing":
		return "It's being set up (" + cmpOr(v.Step, v.Status) + "); that takes about 5 to 10 minutes in all. Call get_cloud_server again with wait_seconds until it's ready."
	case "resizing":
		return "Its size is changing; the database is back once it's ready. Call get_cloud_server again with wait_seconds."
	case "failed":
		return "Setting it up failed: " + cmpOr(v.Problem, "no reason given") + ". Tell the user; the dashboard has Retry on the server's page. Don't ask for another server unless they want one."
	case "deleting", "deleted":
		return "It's being deleted."
	case "ready":
		var next []string
		if len(v.AllowedIPs) == 0 {
			next = append(next, "Nobody can connect yet: "+ask("ask for request_change cloud_firewall with the addresses the app (or this machine) connects from"))
		}
		if v.Database != "" {
			next = append(next, "For the app's own database and login, "+ask("call create_app_database with database "+v.Database)+
				"; put the connection string in the app's environment (e.g. DATABASE_URL in .env), never in code or git")
		}
		return "Ready. " + strings.Join(next, ". ") + "."
	}
	return "Status " + v.Status + "."
}

// ---- money ----

// priceText is a price in cents: "$10", "$10.50", or "12.00 EUR".
func priceText(cents int64, currency string) string {
	if currency == "" || currency == "USD" {
		if cents%100 == 0 {
			return fmt.Sprintf("$%d", cents/100)
		}
		return fmt.Sprintf("$%d.%02d", cents/100, cents%100)
	}
	return fmt.Sprintf("%d.%02d %s", cents/100, cents%100, currency)
}

// hourText is an hourly price in cents (1.4 is $0.014): "$0.014".
func hourText(cents float64, currency string) string {
	s := strconv.FormatFloat(cents/100, 'f', 4, 64)
	s = strings.TrimRight(s, "0")
	if i := strings.IndexByte(s, '.'); i >= 0 && len(s)-i-1 < 2 {
		s += strings.Repeat("0", 2-(len(s)-i-1))
	}
	if currency == "" || currency == "USD" {
		return "$" + s
	}
	return s + " " + currency
}

// trafficText says what traffic a size includes.
func trafficText(z client.CloudSize) string {
	bw := z.Bandwidth
	if bw == nil || bw.IncludedGB == nil || *bw.IncludedGB < 0 {
		return ""
	}
	inc := fmt.Sprintf("%d GB", *bw.IncludedGB)
	if *bw.IncludedGB >= 1024 && *bw.IncludedGB%1024 == 0 {
		inc = fmt.Sprintf("%d TB", *bw.IncludedGB/1024)
	}
	s := inc + " of traffic out included a month"
	if bw.ExtraCentsPerGB != nil {
		s += ", then " + hourText(*bw.ExtraCentsPerGB, z.Currency) + " per GB"
	}
	return s
}
