package protocol

import (
	"net/http"
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
