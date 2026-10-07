package protocol

import "testing"

// A server key is always compared by a person, whatever the level.
func TestAutonomyPersonActions(t *testing.T) {
	for _, name := range AutonomyPersonActions {
		if _, ok := FindApprovalAction(name); !ok {
			t.Errorf("%s isn't an approval action", name)
		}
		for _, level := range []string{AutonomyAct, AutonomyFull, AutonomyBudget, AutonomyAsk} {
			if AutonomyMayCover(level, name) {
				t.Errorf("%s covers %s", level, name)
			}
		}
	}
	if !AutonomyMayCover(AutonomyAct, "restart") || !AutonomyMayCover(AutonomyFull, "restart") || AutonomyMayCover(AutonomyBudget, "restart") ||
		!AutonomyMayCover(AutonomyBudget, "create_app_database") || AutonomyMayCover(AutonomyAsk, "create_cloud_server") ||
		AutonomyMayCover(AutonomyAct, "no_such_action") {
		t.Error("coverage")
	}
}

// The earlier full level reads as act, the default.
func TestNormalizeAutonomyLevel(t *testing.T) {
	if NormalizeAutonomyLevel(AutonomyFull) != AutonomyAct || NormalizeAutonomyLevel(AutonomyAsk) != AutonomyAsk ||
		AutonomyDefault != AutonomyAct || AutonomyLevels[0] != AutonomyDefault {
		t.Error("levels")
	}
}
