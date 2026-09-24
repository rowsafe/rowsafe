package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// FleetHealth returns every database's health score, worst first.
func (c *Client) FleetHealth(ctx context.Context) (out protocol.HealthOverview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/health", nil, &out)
}

// Health returns one database's health score and findings.
func (c *Client) Health(ctx context.Context, ref string) (out protocol.DatabaseHealth, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/health", nil, &out)
}

// DiskForecast estimates when a database's disk fills up.
func (c *Client) DiskForecast(ctx context.Context, ref string) (out protocol.DiskForecast, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/disk-forecast", nil, &out)
}

// Insights returns a database's table and index insights.
func (c *Client) Insights(ctx context.Context, ref string) (out protocol.InsightsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/insights", nil, &out)
}

// Availability returns a database's uptime and incidents.
func (c *Client) Availability(ctx context.Context, ref string) (out protocol.Availability, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/availability", nil, &out)
}

// QueryTrendsQuery selects a time range of statement activity. Zero
// fields use the server's defaults (the last 24 hours, by total time).
type QueryTrendsQuery struct {
	From, To time.Time
	Since    time.Duration // instead of From: this long before To
	Sort     string        // total_time | calls | mean_time | rows
	Limit    int
}

func (q QueryTrendsQuery) encode() url.Values {
	v := url.Values{}
	if !q.From.IsZero() {
		v.Set("from", fmt.Sprint(q.From.Unix()))
	}
	if !q.To.IsZero() {
		v.Set("to", fmt.Sprint(q.To.Unix()))
	}
	if q.Since > 0 && q.From.IsZero() {
		v.Set("since", q.Since.String())
	}
	if q.Sort != "" {
		v.Set("sort", q.Sort)
	}
	if q.Limit > 0 {
		v.Set("limit", fmt.Sprint(q.Limit))
	}
	return v
}

// QueryTrends returns the top statements of a time range (and the
// cumulative pg_stat_statements snapshot).
func (c *Client) QueryTrends(ctx context.Context, ref string, q QueryTrendsQuery) (out protocol.QueriesResponse, err error) {
	path := "/v1/databases/" + esc(ref) + "/queries"
	if v := q.encode(); len(v) > 0 {
		path += "?" + v.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// QueryDetail returns one statement's time series.
func (c *Client) QueryDetail(ctx context.Context, ref, queryID string, q QueryTrendsQuery) (out protocol.QueryDetail, err error) {
	path := "/v1/databases/" + esc(ref) + "/queries/" + esc(queryID)
	q.Sort, q.Limit = "", 0
	if v := q.encode(); len(v) > 0 {
		path += "?" + v.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// OrgSettings returns the organization's settings (the weekly report).
func (c *Client) OrgSettings(ctx context.Context) (out protocol.OrgSettings, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/org/settings", nil, &out)
}

// UpdateOrgSettings changes settings; nil fields are kept.
func (c *Client) UpdateOrgSettings(ctx context.Context, req protocol.UpdateOrgSettingsRequest) (out protocol.OrgSettings, err error) {
	return out, c.do(ctx, http.MethodPut, "/v1/org/settings", req, &out)
}

// WeeklyReport renders the weekly report as it would be sent now.
func (c *Client) WeeklyReport(ctx context.Context) (out protocol.WeeklyReportPreview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/org/weekly-report", nil, &out)
}

// SendTestWeeklyReport emails the weekly report to its recipients now.
func (c *Client) SendTestWeeklyReport(ctx context.Context) (out protocol.ChannelTestResult, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/org/weekly-report/test", nil, &out)
}
