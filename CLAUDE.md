# Rowsafe agent, CLI and installer (public repo)

Rowsafe (https://rowsafe.sh) gives databases that people run on their own servers the safety net
of a managed database: continuous backups to their own bucket, encrypted on their server; restore
to any second (Rewind, Marks); a weekly automatic restore test (Proof); monitoring with one-click
fixes (Pulse); and a safety net for AI coding agents (Guard). This repository is the part that runs
on the customer's machines, open source under Apache-2.0. The control plane and dashboard are
proprietary (api.rowsafe.sh, app.rowsafe.sh).

## Layout

- `cmd/rowsafe-agent`, `internal/agent`: the agent. Pull model (outbound HTTPS only), runs as the
  `postgres` user, one task at a time plus a side lane (restore points, maintenance, compare).
  Tasks: inspect, adopt, check, backup, drill (Proof), restore_point (Mark), restart, maintenance
  (Apply fix actions), rewind_* and more. Non-PostgreSQL engines plug in through
  `internal/agent/engine.go` (`RegisterEngine`, packages under `internal/engine/`).
- `internal/pgbackrest`, `internal/pginspect`: PostgreSQL backup (pgBackRest) and inspection.
- `collect/`: monitoring collectors (metrics, insights, statements, locks, replication).
- `protocol/`: API types shared with the control plane. `protocol/engine.go` has the per-engine
  feature flags.
- `cmd/rowsafe`, `client/`: the CLI (`rowsafe login`, `adopt`, `apply`, `verify`, `status`, `mark`,
  `proof`, `pulse`, `fix`, `rewind`, `restart`, `cloud`, `env`, `connect`, ...). `rowsafe help all`
  lists everything. `rowsafe cloud` acts directly on Rowsafe Cloud with a read-write key (money and
  deletions confirmed, `--yes` in scripts); `env`/`connect` never let a password pass through Rowsafe.
- `mcp/`: the MCP server (`rowsafe mcp`, also served remotely by the control plane). Read-only
  unless `--allow-restore-points` / `--allow-writes` (remote: OAuth scopes `rowsafe:marks` /
  `rowsafe:act`). Changes to production are filed as change requests (`request_change`, and the
  direct `create_cloud_server`, `cloud_firewall`, `apply_fix`; catalog in `protocol/approval.go`).
  The organization's agent setting (`protocol/autonomy.go`) decides what happens: at the default
  (`act`) the control plane runs them right away as the person who connected the agent, with that
  person's rights (owner or admin now; a member's agent asks); `budget` runs only the Rowsafe Cloud
  actions in `AutonomyBudgetActions` within a monthly budget; `ask` makes every change wait for an
  owner or admin to approve in the dashboard. A connection or key made before agents could act
  as their person (`OAuthConnection.ActsAsYou`, `APIKey.ActsAsCreator` false), or a key made by a
  key, asks first. No tool can approve or change the setting.
- `scripts/install.sh`: the installer served at `curl -fsSL https://rowsafe.sh | sudo sh -s rse_...`
  (guided storage setup, finds PostgreSQL, plan → yes → apply, optional restart).
  `scripts/rowsafe-pg-restart`: the only root component (a sandboxed systemd path/service pair that
  restarts/stops/starts only the PostgreSQL units root listed in `/etc/rowsafe/restart-allowed`).
- `integrations/claude-code`, `integrations/codex`, `integrations/github-action`: plugins and the
  GitHub Action (published separately as github.com/rowsafe/action).
- `deploy/`: systemd unit, Docker sidecar images (`ghcr.io/rowsafe/agent:pg<major>`, `:clickhouse<YY.M>`, `:redis<X.Y>`
  and `:valkey<X.Y>` floating, `:<ver>-pg<major>`, `:<ver>-clickhouse<YY.M>`... exact), compose examples.

## Commands

- `make build`, `go vet ./... && go test ./...`, `make lint` (vet, gofmt, shellcheck),
  `make check-installer`, `make test-installer` (Debian 12/13, Ubuntu 22.04/24.04 containers),
  `make test-rewind` (real rewind on a systemd container), `make dist` (reproducible builds).
- Integration tests use a local PostgreSQL when available (`/tmp:5432`) and skip otherwise.

## Rules

- Plain language in everything users read; no jargon in the main flow.
- Never build SQL from strings: resolve names through the catalogs and quote with PostgreSQL's
  `format('%I')`.
- Root never writes into directories the agent user owns (symlink/TOCTOU safety).
- Secrets never leave the server, never appear on command lines or in logs.
- Releases: tag `v*` → GitHub release with SLSA provenance, SBOM, cosign-signed images and an
  Ed25519-signed manifest the agent verifies before self-updating.
