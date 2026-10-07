package client

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Rowsafe Cloud as the control plane shows it: the catalog of clouds,
// regions and sizes with their prices (GET /v1/cloud/rowsafe/catalog), and
// the servers Rowsafe created for the org (GET /v1/cloud/servers[/{id}]).
//
// Creating, resizing, changing who can connect, cloning and deleting
// (cloud_change.go) are for people: the dashboard, or the CLI with a
// read-write API key. AI assistants ask with approval requests a person
// approves (protocol ApprovalActions, group "cloud"); the control plane
// refuses these calls on /mcp.

// CloudCatalog is Rowsafe Cloud's catalog.
type CloudCatalog struct {
	Clouds []CloudCatalogCloud `json:"clouds"`
	// MaxServers: servers the org may have at a time (waiting for payment
	// included); MaxHourlyServers: of them, billed by the hour.
	MaxServers       int `json:"max_servers"`
	MaxHourlyServers int `json:"max_hourly_servers"`
	// Payg is the org's pay-as-you-go subscription, which clouds billed by
	// the hour use: Status none (never subscribed), active, canceling,
	// past_due or ended.
	Payg struct {
		Status    string     `json:"status"`
		PeriodEnd *time.Time `json:"period_end"`
	} `json:"payg"`
}

// CloudCatalogCloud is one cloud: its regions, and its sizes with their
// prices there.
type CloudCatalogCloud struct {
	Provider string `json:"provider"` // "hetzner"
	Name     string `json:"name"`     // "Hetzner"
	// Billing: "hourly" (pay as you go, never more than the monthly price)
	// or "monthly" (a subscription per server).
	Billing string        `json:"billing"`
	Regions []CloudRegion `json:"regions"`
	Sizes   []CloudSize   `json:"sizes"`
	// Standby: servers here can have a standby server.
	Standby bool `json:"standby"`
}

// CloudRegion is a region of a cloud.
type CloudRegion struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country,omitempty"`
}

// CloudSize is a size in one cloud, with its price there.
type CloudSize struct {
	ID       string `json:"id"`   // "small"
	Name     string `json:"name"` // "Small"
	CPUs     int    `json:"cpus"`
	MemoryGB int    `json:"memory_gb"`
	DiskGB   int    `json:"disk_gb"`
	// PriceCents is the price of a month (for hourly clouds, the most a
	// month costs).
	PriceCents int64  `json:"price_cents"`
	Currency   string `json:"currency"`
	// HourlyPriceCents (hourly clouds): the price of an hour, in cents
	// (4.8 is $0.048).
	HourlyPriceCents float64 `json:"hourly_price_cents,omitempty"`
	// Regions it is offered in, when not all of the cloud's.
	Regions []string `json:"regions,omitempty"`
	// UnavailableRegions: offered there, but none free right now.
	UnavailableRegions []string `json:"unavailable_regions,omitempty"`
	// Bandwidth: outbound traffic included per billing cycle and the price
	// of each GB above it; nil, or IncludedGB nil or negative: unlimited.
	Bandwidth *struct {
		IncludedGB      *int64   `json:"included_gb"`
		ExtraCentsPerGB *float64 `json:"extra_cents_per_gb"`
	} `json:"bandwidth,omitempty"`
}

// CloudCatalog reads Rowsafe Cloud's catalog (404 when this control plane
// doesn't offer Rowsafe Cloud).
func (c *Client) CloudCatalog(ctx context.Context) (out CloudCatalog, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/cloud/rowsafe/catalog", nil, &out)
}

// CloudServer is a server Rowsafe created (or is creating), as the API
// shows it.
type CloudServer struct {
	ID         string `json:"id"`    // cs_...
	Where      string `json:"where"` // "rowsafe" (Rowsafe Cloud) or "account" (the org's own cloud account)
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	Region     string `json:"region"`
	RegionName string `json:"region_name"`
	Size       string `json:"size"`
	SizeInfo   *struct {
		CPUs     int `json:"cpus"`
		MemoryMB int `json:"memory_mb"`
		DiskGB   int `json:"disk_gb"`
	} `json:"size_info"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version"`
	// Status: payment (waiting for payment), creating, installing, ready,
	// resizing, deleting, deleted or failed; Step says where it is in plain
	// words, Problem what went wrong.
	Status      string   `json:"status"`
	Step        string   `json:"step"`
	Problem     *string  `json:"problem"`
	IPv4        *string  `json:"ipv4"`
	IPv6        *string  `json:"ipv6"`
	DatabaseRef *string  `json:"database_ref"` // the database's name in Rowsafe, once enrolled
	AllowedIPs  []string `json:"allowed_ips"`
	// SSHIPs may reach SSH (servers in the org's own cloud account only).
	SSHIPs []string `json:"ssh_ips"`
	// PassphraseSavedAt: when someone saved the backup passphrase (a
	// server with a database can be deleted only after that).
	PassphraseSavedAt *time.Time `json:"passphrase_saved_at"`
	PendingSize       *string    `json:"pending_size"`
	PlanSize          *string    `json:"plan_size"` // Rowsafe Cloud: the size ID bought
	CreatedAt         time.Time  `json:"created_at"`
	CreatedBy         string     `json:"created_by"`
	DeleteAt          *time.Time `json:"delete_at"`
	// FirewallPending: the server's own firewall still has to apply the
	// allow list.
	FirewallPending bool    `json:"firewall_pending"`
	FirewallProblem *string `json:"firewall_problem"`
	// DeleteAfterHours: a clone is deleted this long after it's ready.
	DeleteAfterHours *int `json:"delete_after_hours"`
	Billing          *struct {
		Status           string  `json:"status"` // payment, active, canceling, past_due, ended
		Mode             string  `json:"mode"`   // hourly or monthly
		HourlyPriceCents float64 `json:"hourly_price_cents,omitempty"`
		SizeName         string  `json:"size_name"`
		Cloud            string  `json:"cloud"`
		PriceCents       int64   `json:"price_cents"`
		Currency         string  `json:"currency"`
		CheckoutURL      *string `json:"checkout_url"`
		CanResize        bool    `json:"can_resize"`
		// PaidUntil: the end of the period paid for.
		PaidUntil *time.Time `json:"paid_until"`
	} `json:"billing"`
	// Address: the names apps connect to (Rowsafe Cloud).
	Address *struct {
		Host        string  `json:"host"`
		ReadHost    string  `json:"read_host"`
		Published   bool    `json:"published"`
		Certificate string  `json:"certificate"` // verified, pending or unavailable
		SSLMode     string  `json:"sslmode"`     // verify-full once verified, else require
		Problem     *string `json:"problem"`
	} `json:"address"`
	Standby *struct {
		Role        string `json:"role"` // primary or standby
		PartnerID   string `json:"partner_id"`
		PartnerName string `json:"partner_name,omitempty"`
		State       string `json:"state,omitempty"`
	} `json:"standby"`
	Clone *struct {
		SourceName string     `json:"source_name"`
		At         *time.Time `json:"at"`
		Mark       *string    `json:"mark"`
		Now        bool       `json:"now"`
	} `json:"clone"`
}

// CloudServerList lists the servers Rowsafe created for the org, with all
// they show.
func (c *Client) CloudServerList(ctx context.Context) ([]CloudServer, error) {
	var out struct {
		Servers []CloudServer `json:"servers"`
	}
	return out.Servers, c.do(ctx, http.MethodGet, "/v1/cloud/servers", nil, &out)
}

// CloudServer reads one server (id is cs_...).
func (c *Client) CloudServer(ctx context.Context, id string) (out CloudServer, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/cloud/servers/"+url.PathEscape(id), nil, &out)
}
