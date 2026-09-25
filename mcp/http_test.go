package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeAPI answers /v1/org and /v1/whoami for a few known credentials.
func fakeAPI(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var who protocol.WhoAmI
		switch tok {
		case "rsk_good":
			who = protocol.WhoAmI{Org: protocol.Org{ID: "org_1"}, Actor: "key"}
		case "rso_read":
			who = protocol.WhoAmI{Org: protocol.Org{ID: "org_1"}, OAuth: &protocol.OAuthConnection{Scopes: []string{protocol.ScopeRead}}}
		case "rso_marks":
			who = protocol.WhoAmI{Org: protocol.Org{ID: "org_1"}, OAuth: &protocol.OAuthConnection{Scopes: []string{protocol.ScopeRead, protocol.ScopeMarks}}}
		case "rso_nooauth": // accepted by the API but not an OAuth grant
			who = protocol.WhoAmI{Org: protocol.Org{ID: "org_1"}}
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(protocol.Error{Error: "invalid credentials"})
			return
		}
		switch r.URL.Path {
		case "/v1/org":
			_ = json.NewEncoder(w).Encode(who.Org)
		case "/v1/whoami":
			_ = json.NewEncoder(w).Encode(who)
		default:
			http.NotFound(w, r)
		}
	})
}

const prm = "https://api.example.test/.well-known/oauth-protected-resource/mcp"

func listTools(t *testing.T, h http.Handler, token string) (int, http.Header, []string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, rec.Header(), nil
	}
	var resp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if resp.Error != nil {
		t.Fatalf("tools/list: %s", resp.Error.Message)
	}
	var names []string
	for _, tl := range resp.Result.Tools {
		names = append(names, tl.Name)
	}
	return rec.Code, rec.Header(), names
}

func TestHTTPOAuthScopesDecideTools(t *testing.T) {
	h := NewHTTPHandler(fakeAPI(t), HTTPOptions{ResourceMetadataURL: prm, MaxWait: time.Second})

	_, _, read := listTools(t, h, "rso_read")
	if len(read) == 0 || slices.Contains(read, "create_restore_point") || slices.Contains(read, "run_backup") {
		t.Errorf("rowsafe:read tools = %v, want read-only tools only", read)
	}
	if !slices.Contains(read, "safety_check") || !slices.Contains(read, "fleet_health") {
		t.Errorf("rowsafe:read tools = %v, missing read tools", read)
	}
	_, _, marks := listTools(t, h, "rso_marks")
	if !slices.Contains(marks, "create_restore_point") {
		t.Errorf("rowsafe:marks tools = %v, want create_restore_point", marks)
	}
	for _, w := range []string{"run_backup", "run_drill", "apply_adoption", "plan_adoption", "update_schedule", "verify_database"} {
		if slices.Contains(marks, w) {
			t.Errorf("OAuth token got write tool %s", w)
		}
	}
	// API keys keep their behavior: every write tool is listed.
	_, _, key := listTools(t, h, "rsk_good")
	if !slices.Contains(key, "run_backup") || !slices.Contains(key, "create_restore_point") {
		t.Errorf("API key tools = %v, want write tools", key)
	}
}

func TestHTTPOAuthChallenges(t *testing.T) {
	h := NewHTTPHandler(fakeAPI(t), HTTPOptions{ResourceMetadataURL: prm, MaxWait: time.Second})
	for _, tc := range []struct {
		token        string
		invalidToken bool
	}{
		{"", false},
		{"rso_expired", true},
		{"rsk_bad", true},
		{"rso_nooauth", true}, // an access token must be an OAuth grant
		{"something-else", true},
	} {
		code, hdr, _ := listTools(t, h, tc.token)
		if code != http.StatusUnauthorized {
			t.Errorf("token %q: HTTP %d, want 401", tc.token, code)
			continue
		}
		ch := hdr.Get("WWW-Authenticate")
		if !strings.HasPrefix(ch, "Bearer ") || !strings.Contains(ch, `resource_metadata="`+prm+`"`) ||
			!strings.Contains(ch, `scope="rowsafe:read rowsafe:marks"`) {
			t.Errorf("token %q: WWW-Authenticate = %q", tc.token, ch)
		}
		if got := strings.Contains(ch, `error="invalid_token"`); got != tc.invalidToken {
			t.Errorf("token %q: invalid_token in %q = %v, want %v", tc.token, ch, got, tc.invalidToken)
		}
	}
}

func TestHTTPWithoutOAuthRefusesAccessTokens(t *testing.T) {
	h := NewHTTPHandler(fakeAPI(t), HTTPOptions{MaxWait: time.Second})
	code, hdr, _ := listTools(t, h, "rso_marks")
	if code != http.StatusUnauthorized {
		t.Fatalf("HTTP %d, want 401", code)
	}
	if ch := hdr.Get("WWW-Authenticate"); strings.Contains(ch, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q: OAuth is off", ch)
	}
	if code, _, _ := listTools(t, h, "rsk_good"); code != http.StatusOK {
		t.Errorf("API key: HTTP %d", code)
	}
}
