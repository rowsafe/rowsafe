package protocol

import "testing"

// A server key is always compared by a person, whatever the level.
func TestAutonomyPersonActions(t *testing.T) {
	for _, name := range AutonomyPersonActions {
		if _, ok := FindApprovalAction(name); !ok {
			t.Errorf("%s isn't an approval action", name)
		}
		if AutonomyMayCover(AutonomyFull, name) {
			t.Errorf("full covers %s", name)
		}
	}
	if !AutonomyMayCover(AutonomyFull, "restart") || AutonomyMayCover(AutonomyBudget, "restart") || !AutonomyMayCover(AutonomyBudget, "create_app_database") ||
		AutonomyMayCover(AutonomyAsk, "create_cloud_server") {
		t.Error("coverage")
	}
}
