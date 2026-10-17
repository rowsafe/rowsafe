package protocol

import (
	"fmt"
	"regexp"
	"slices"
)

// Usage counts (rowsafe telemetry): off unless the person turns them on
// with `rowsafe telemetry on`, never prompted. Then, after each command, the
// CLI sends one TelemetryEvent to POST /v1/telemetry on the control plane it
// uses and nothing else: no arguments, flag values, names, connection
// strings, hostnames, error messages, or anything tied to an account. The
// control plane accepts exactly these fields (Validate) and drops the rest.

// TelemetryPath is where the CLI sends usage counts.
const TelemetryPath = "/v1/telemetry"

// TelemetryEvent is one command run. Every field is listed in the docs
// (reference/cli, "Usage counts"); adding one means updating them.
type TelemetryEvent struct {
	// InstallID is random (32 hex characters), made by `rowsafe telemetry
	// on` and forgotten by `rowsafe telemetry off`; not tied to an account.
	InstallID string `json:"install_id"`
	// Command is the command and subcommand names from the CLI's own
	// reference ("cloud create", "pulse"), or "other".
	Command  string `json:"command"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	ExitCode int    `json:"exit_code"`
	// Duration is one of TelemetryDurations.
	Duration string `json:"duration"`
	// Terminal: run from a terminal (false: a script, CI or an AI agent).
	Terminal bool `json:"terminal"`
	// Agent is the AI agent that ran the command (TelemetryAgents), "" for
	// none found.
	Agent    string `json:"agent"`
	LoggedIn bool   `json:"logged_in"`
}

// TelemetryOther is the command of anything not in the CLI's reference.
const TelemetryOther = "other"

// TelemetryDurations are the duration buckets, shortest first.
var TelemetryDurations = []string{"0-1s", "1-10s", "10-60s", "1-10m", "10m+"}

// TelemetryAgents are the AI agents the CLI recognizes.
var TelemetryAgents = []string{"claude-code", "codex", "cursor", "gemini"}

var (
	telemetryIDRe      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	telemetryCommandRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}( [a-z][a-z0-9-]{0,30}){0,2}$`)
	telemetryVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,40}$`)
	telemetryPlatRe    = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// Validate checks every field against what the CLI can send.
func (e TelemetryEvent) Validate() error {
	switch {
	case !telemetryIDRe.MatchString(e.InstallID):
		return fmt.Errorf("install_id: 32 hex characters")
	case !telemetryCommandRe.MatchString(e.Command):
		return fmt.Errorf("command: up to three lowercase words")
	case !telemetryVersionRe.MatchString(e.Version):
		return fmt.Errorf("version: not a version")
	case !telemetryPlatRe.MatchString(e.OS) || !telemetryPlatRe.MatchString(e.Arch):
		return fmt.Errorf("os, arch: not a platform")
	case e.ExitCode < 0 || e.ExitCode > 255:
		return fmt.Errorf("exit_code: 0 to 255")
	case !slices.Contains(TelemetryDurations, e.Duration):
		return fmt.Errorf("duration: one of %v", TelemetryDurations)
	case e.Agent != "" && !slices.Contains(TelemetryAgents, e.Agent):
		return fmt.Errorf("agent: one of %v or empty", TelemetryAgents)
	}
	return nil
}

// TelemetryDuration buckets a run's length in seconds.
func TelemetryDuration(seconds float64) string {
	switch {
	case seconds < 1:
		return TelemetryDurations[0]
	case seconds < 10:
		return TelemetryDurations[1]
	case seconds < 60:
		return TelemetryDurations[2]
	case seconds < 600:
		return TelemetryDurations[3]
	}
	return TelemetryDurations[4]
}
