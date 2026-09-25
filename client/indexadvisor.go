package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Index recommendations (Pulse): indexes proven on a copy of the database.

func indexRecsPath(ref string) string { return "/v1/databases/" + esc(ref) + "/index-recommendations" }

// IndexRecommendations is the advisor's state and its recommendations.
func (c *Client) IndexRecommendations(ctx context.Context, ref string) (out protocol.IndexAdvisorView, err error) {
	return out, c.do(ctx, http.MethodGet, indexRecsPath(ref), nil, &out)
}

// RunIndexAdvisor looks for index recommendations now.
func (c *Client) RunIndexAdvisor(ctx context.Context, ref string) (out protocol.TaskView, err error) {
	return out, c.do(ctx, http.MethodPost, indexRecsPath(ref)+"/run", struct{}{}, &out)
}

// SetIndexAdvisorSchedule sets when the advisor runs: auto, off or a cron.
func (c *Client) SetIndexAdvisorSchedule(ctx context.Context, ref, schedule string) (out protocol.IndexAdvisorView, err error) {
	return out, c.do(ctx, http.MethodPut, indexRecsPath(ref)+"/settings", protocol.IndexAdvisorSettingsRequest{Schedule: schedule}, &out)
}

// DismissIndexRecommendation hides a recommendation ("not now").
func (c *Client) DismissIndexRecommendation(ctx context.Context, ref, id, reason string) (out protocol.IndexRecommendationView, err error) {
	return out, c.do(ctx, http.MethodPost, indexRecsPath(ref)+"/"+esc(id)+"/dismiss", protocol.DismissIndexRecommendationRequest{Reason: reason}, &out)
}
