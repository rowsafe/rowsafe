package protocol

// ---- Docker: container control (opt-in) ----
//
// In docker-sidecar mode the agent can't stop or start PostgreSQL's
// container by itself. When the operator adds the rowsafe-docker-control
// service to the compose project (it holds the Docker socket and acts on
// exactly one container), the agent reports it here, and RestartPorts /
// RestartActions in the heartbeat as for a native host:
//
//	RestartActions ["restart"]                  the control service answers
//	RestartActions ["restart", "stop", "start"] and the data volume is
//	                                            writable in the agent
//	                                            container (rewind in place)

// DockerControlReport is what a docker-sidecar agent reports about the
// container control service (HeartbeatRequest.DockerControl). Nil from
// native agents and from older docker agents.
type DockerControlReport struct {
	// Found: the control service's socket is mounted in the agent container.
	Found bool `json:"found"`
	// Container is the controlled container's name (e.g. myapp-postgres-1),
	// Project and Service its compose labels, State Docker's state.
	Container string `json:"container,omitempty"`
	Project   string `json:"project,omitempty"`
	Service   string `json:"service,omitempty"`
	State     string `json:"state,omitempty"`
	// DataDir is PostgreSQL's data directory; DataWritable whether the agent
	// container may write it (the data volume mounted without :ro), which
	// rewinding in place needs.
	DataDir      string `json:"data_dir,omitempty"`
	DataWritable bool   `json:"data_writable"`
	// Error says in plain words why the control service can't be used
	// (e.g. it can't find the PostgreSQL service).
	Error string `json:"error,omitempty"`
}
