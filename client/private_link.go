package client

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Private connections from a customer's AWS network to a Rowsafe Cloud
// server (AWS PrivateLink), as the control plane shows them
// (GET /v1/cloud/servers/{id}/private-link). Read-only here: turning one on
// or off is for people in the dashboard.

// CloudServerRef is a server Rowsafe created, as GET /v1/cloud/servers lists it.
type CloudServerRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Where    string `json:"where"` // "account" or "rowsafe"
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Status   string `json:"status"`
}

// CloudServers lists the servers Rowsafe created for the org.
func (c *Client) CloudServers(ctx context.Context) ([]CloudServerRef, error) {
	var out struct {
		Servers []CloudServerRef `json:"servers"`
	}
	return out.Servers, c.do(ctx, http.MethodGet, "/v1/cloud/servers", nil, &out)
}

// PrivateConnectionView is a server's private connection.
type PrivateConnectionView struct {
	Offered     bool    `json:"offered"`
	Unavailable string  `json:"unavailable,omitempty"`
	PriceCents  int64   `json:"price_cents"`
	Currency    string  `json:"currency"`
	HourlyCents float64 `json:"hourly_price_cents"`
	Cloud       string  `json:"cloud,omitempty"`
	Region      string  `json:"region,omitempty"`
	RegionName  string  `json:"region_name,omitempty"`
	Link        *struct {
		Status      string   `json:"status"` // creating, ready, deleting, failed
		Step        string   `json:"step"`
		Problem     *string  `json:"problem"`
		Accounts    []string `json:"accounts"`
		ServiceName *string  `json:"service_name"`
		Zones       []string `json:"zones"`
		Connections []struct {
			ID        string    `json:"id"`
			Account   string    `json:"account"`
			State     string    `json:"state"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"connections"`
	} `json:"link"`
	Endpoints []struct {
		AccountName string `json:"account_name"`
		EndpointID  string `json:"endpoint_id"`
		NetworkID   string `json:"network_id"`
		DNSName     string `json:"dns_name"`
		State       string `json:"state"`
		Status      string `json:"status"`
	} `json:"endpoints"`
	Connection *struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		SSLMode string `json:"sslmode"`
		URL     string `json:"url"`
		TLS     string `json:"tls"`
	} `json:"connection"`
	OnlyPrivate bool `json:"only_private"`
}

// PrivateConnection reads a server's private connection (server is the
// Rowsafe Cloud server's ID).
func (c *Client) PrivateConnection(ctx context.Context, serverID string) (out PrivateConnectionView, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/cloud/servers/"+url.PathEscape(serverID)+"/private-link", nil, &out)
}
