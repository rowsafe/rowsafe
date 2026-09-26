package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rowsafe/rowsafe/protocol"
)

// LogsQuery filters a database's log entries. Zero fields mean everything.
type LogsQuery struct {
	Kind   string // a kind, or protocol.LogFilter* (errors, locks, maintenance)
	Search string
	Group  string
	Before string // entry ID: older entries
	After  string // entry ID: newer entries (live tail)
	Limit  int
}

func (q LogsQuery) values() string {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("kind", q.Kind)
	set("q", q.Search)
	set("group", q.Group)
	set("before", q.Before)
	set("after", q.After)
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// Logs returns a database's PostgreSQL log entries, newest first.
func (c *Client) Logs(ctx context.Context, ref string, q LogsQuery) (out protocol.LogsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/logs"+q.values(), nil, &out)
}

// LogGroups returns a database's repeated log messages of the last 24
// hours, most frequent first.
func (c *Client) LogGroups(ctx context.Context, ref string, q LogsQuery) (out protocol.LogGroupsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/logs/groups"+q.values(), nil, &out)
}

// LogsOverview returns a database's log settings, source and counts.
func (c *Client) LogsOverview(ctx context.Context, ref string) (out protocol.LogsOverview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/logs/overview", nil, &out)
}
