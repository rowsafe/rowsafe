package protocol

import (
	"slices"
	"testing"
)

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
		!AutonomyMayCover(AutonomyBudget, "create_app_database") || !AutonomyMayCover(AutonomyAsk, "create_cloud_server") ||
		AutonomyMayCover(AutonomyAct, "no_such_action") || AutonomyMayCover("", "restart") {
		t.Error("coverage")
	}
}

// The earlier full and the removed ask levels read as act, the default.
func TestNormalizeAutonomyLevel(t *testing.T) {
	if NormalizeAutonomyLevel(AutonomyFull) != AutonomyAct || NormalizeAutonomyLevel(AutonomyAsk) != AutonomyAct ||
		NormalizeAutonomyLevel(AutonomyBudget) != AutonomyBudget ||
		AutonomyDefault != AutonomyAct || AutonomyLevels[0] != AutonomyDefault || slices.Contains(AutonomyLevels, AutonomyAsk) {
		t.Error("levels")
	}
}
