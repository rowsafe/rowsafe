package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Recommendations returns every database's open recommendations (schema,
// queries, capacity, indexes), the most important first.
func (c *Client) Recommendations(ctx context.Context) (out protocol.RecommendationsOverview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/recommendations", nil, &out)
}

// DatabaseRecommendations returns one database's recommendations: the open
// ones, highest impact first, and the dismissed ones.
func (c *Client) DatabaseRecommendations(ctx context.Context, ref string) (out protocol.RecommendationsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/recommendations", nil, &out)
}

// DismissRecommendation sets a recommendation aside with a reason
// (protocol.Dismiss*).
func (c *Client) DismissRecommendation(ctx context.Context, ref, id string, req protocol.DismissRecommendationRequest) (out protocol.RecommendationDismissal, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/recommendations/"+esc(id)+"/dismiss", req, &out)
}

// RestoreRecommendation brings a dismissed recommendation back.
func (c *Client) RestoreRecommendation(ctx context.Context, ref, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/databases/"+esc(ref)+"/recommendations/"+esc(id)+"/dismiss", nil, nil)
}
