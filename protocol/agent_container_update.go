package protocol

import "time"

// ---- Docker sidecars: "Update now" through the container control service ----
//
// A docker-sidecar agent can't replace its own container. When the
// operator allowed it (ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE=1 on
// rowsafe-docker-control), the agent reports DockerControlReport.AgentUpdate
// and the control plane may queue TaskAgentContainerUpdate after a person
// confirmed it. The agent hands the release's signed images document
// (release/agentimages) to the control service, which verifies it with the
// release key built into it, pulls the image by digest and recreates only
// the agent's container, rolling back if the new one doesn't come up.
//
// The old agent is stopped in the middle of the task: the new one finishes
// it (it finds the task in its state volume) and reports the outcome, and
// both report it in HeartbeatRequest.Update with UpdateReport.Container set.

// TaskAgentContainerUpdate replaces a docker-sidecar agent's container with
// the image of a newer release. Host-level (no database).
const TaskAgentContainerUpdate = "agent_container_update"

// AgentContainerUpdateParams carry the release's images document verbatim.
type AgentContainerUpdateParams struct {
	Version string `json:"version"`
	// Images is the exact signed JSON (release/agentimages), Signature its
	// base64 Ed25519 signature.
	Images    string `json:"images"`
	Signature string `json:"signature"`
}

// AgentContainerUpdateResult is the task's result.
type AgentContainerUpdateResult struct {
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	// Image is what the container runs now: ghcr.io/rowsafe/agent@sha256:...
	Image      string `json:"image,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Summary    string `json:"summary"`
}

// AgentContainerUpdateTimeout bounds the task (pulling a few hundred MB, the
// switch, and five minutes for the new agent to come up).
const AgentContainerUpdateTimeout = 45 * time.Minute
