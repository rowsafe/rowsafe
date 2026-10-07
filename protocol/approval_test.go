package protocol

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestApprovalActions(t *testing.T) {
	seen := map[string]bool{}
	param := regexp.MustCompile(`\{([a-z_]+)\}`)
	for _, a := range ApprovalActions {
		if a.Name == "" || seen[a.Name] {
			t.Errorf("action %q: empty or duplicate name", a.Name)
		}
		seen[a.Name] = true
		if a.Title == "" || a.Description == "" || a.Group == "" {
			t.Errorf("%s: title, description and group are required", a.Name)
		}
		if !slices.Contains([]string{RiskNormal, RiskDisruptive, RiskDestructive}, a.Risk) {
			t.Errorf("%s: risk %q", a.Name, a.Risk)
		}
		if !slices.Contains([]string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}, a.Method) {
			t.Errorf("%s: method %q", a.Name, a.Method)
		}
		if !strings.HasPrefix(a.Path, "/v1/") || strings.HasPrefix(a.Path, "/v1/approvals") || strings.HasPrefix(a.Path, "/v1/internal/") {
			t.Errorf("%s: path %q", a.Name, a.Path)
		}
		if a.Task != "" && !strings.HasSuffix(a.Path, "/tasks") {
			t.Errorf("%s: a task action posts to /tasks", a.Name)
		}
		for _, m := range param.FindAllStringSubmatch(a.Path, -1) {
			if m[1] == "ref" && !strings.HasPrefix(a.Path, "/v1/databases/{ref}") {
				t.Errorf("%s: {ref} is the database", a.Name)
			}
		}
		if f, ok := FindApprovalAction(a.Name); !ok || f.Path != a.Path {
			t.Errorf("FindApprovalAction(%s)", a.Name)
		}
	}
}

// jsonFields are a struct's JSON field names.
func jsonFields(v any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}

// Fixed fields must be fields of the body, so the control plane's strict
// decoding of params + Fixed accepts them.
func TestApprovalFixedFieldsInBody(t *testing.T) {
	for _, a := range ApprovalActions {
		if a.Body == nil || a.Task != "" {
			continue
		}
		fields := jsonFields(a.Body)
		for k := range a.Fixed {
			if !fields[k] {
				t.Errorf("%s: fixed %q isn't a field of %T", a.Name, k, a.Body)
			}
		}
	}
}

// The Rowsafe Cloud actions: what costs money says so, servers are named
// in params.server, create_cloud_server needs no database.
func TestCloudApprovalActions(t *testing.T) {
	money := map[string]bool{"create_cloud_server": true, "resize_cloud_server": true, "clone_to_new_server": true}
	var cloud []string
	for _, a := range ApprovalActions {
		if a.CostsMoney != money[a.Name] {
			t.Errorf("%s: costs_money %v", a.Name, a.CostsMoney)
		}
		if strings.Contains(a.Path, "{server}") && a.Group != "cloud" {
			t.Errorf("%s: {server} outside the cloud group", a.Name)
		}
		if a.Group == "cloud" {
			cloud = append(cloud, a.Name)
		}
	}
	want := []string{"create_cloud_server", "cloud_firewall", "resize_cloud_server", "clone_to_new_server", "delete_cloud_server"}
	if !slices.Equal(cloud, want) {
		t.Errorf("cloud actions %v, want %v", cloud, want)
	}
	c, _ := FindApprovalAction("create_cloud_server")
	if strings.Contains(c.Path, "{ref}") || c.Fixed["where"] != "rowsafe" || c.Fixed["engine"] != EnginePostgreSQL {
		t.Errorf("create_cloud_server %+v", c)
	}
	d, _ := FindApprovalAction("delete_cloud_server")
	if d.Risk != RiskDestructive || jsonFields(d.Body)["confirm_name"] || jsonFields(d.Body)["passphrase_saved"] {
		t.Errorf("delete_cloud_server: the confirmations are the person's, never the assistant's: %+v", d)
	}
	app, _ := FindApprovalAction("create_app_database")
	if app.Fixed["action"] != DBAdminCreateDatabase || app.Fixed["create_owner"] != true || jsonFields(app.Body)["public_key"] {
		t.Errorf("create_app_database %+v", app)
	}
}

func TestApprovalNeedsBrowserKey(t *testing.T) {
	for _, c := range []struct {
		a    Approval
		want bool
	}{
		{Approval{Action: "create_app_database", Params: json.RawMessage(`{"database":"shop"}`)}, true},
		{Approval{Action: "create_app_database"}, true},
		{Approval{Action: "create_app_database", Params: json.RawMessage(`{"database":"shop","password_verifier":"SCRAM-SHA-256$4096:x"}`)}, false},
		{Approval{Action: "manage_databases_users", Params: json.RawMessage(`{"action":"create_database"}`)}, false},
		{Approval{Action: "create_app_database", Params: json.RawMessage(`[`)}, false},
	} {
		if got := ApprovalNeedsBrowserKey(c.a); got != c.want {
			t.Errorf("%s %s: %v", c.a.Action, c.a.Params, got)
		}
	}
}
