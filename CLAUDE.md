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
  The CLI covers what the dashboard does with an API key (`security`, `security-updates`, `reboot`,
  `alerts rules set`, `logs`, `log-destinations`, `cloud maintenance`, ...): new changes use
  `confirm.go` (`--yes`; refused without a terminal) and offer `--json`.
  The CLI also builds for Windows (amd64, arm64; `make dist`, CI job "CLI on Windows"): Unix-only
  code its packages need has a `_windows.go` counterpart (`collect/disk_windows.go`), and
  `internal/agent`, the agent, stays Linux/macOS-only: the CLI's fixes run `internal/maintenance`
  (Pulse fixes and settings changes, plain SQL; the agent's maintenance and settings tasks run it
  too) and `rowsafe explain` reads indexes with `internal/indexadvisor`. MySQL/MariaDB without an
  account and running a migration on a copy (`local/*_windows.go`) still need macOS or Linux.
  A server without an account is reachable from another computer over plain SSH:
  `rowsafe add NAME ssh://USER@HOST` (cmd/rowsafe/ssh_saved.go) saves only the address; commands
  that go to a control plane then reach the agent's socket through `client.NewSSH` (each HTTP
  connection is `ssh HOST sudo -n rowsafe-agent control-bridge`, internal/localcp/bridge.go),
  and pulse/fix/... run on the server with its rowsafe (`ssh -t`). `make test-no-account-ssh`.
  `rowsafe init` offers a Rowsafe section in AGENTS.md / CLAUDE.md (`agentsmd.go`; append-only).
  Rules for scripts and AI agents (`rowsafe help agents`, checked over every command by
  `TestAgentRules`): every command takes `--json` (stdout only JSON, `jsonout.go`); exit codes
  0/1/2 usage/3 not healthy; no question without a terminal; errors say the next step
  (`errors.go`: `explain`, `newUsageError`).
- `integrations/npm`: the `rowsafe` npm package (`npx rowsafe`): no install script; on first run it
  downloads the release binary, checks it against the `SHA256SUMS` the release workflow puts in
  the package, and caches it. Published by release.yml's `npm` job through npm trusted publishing (OIDC, no token) when the repository variable `NPM_PUBLISH` is `true`.
  `make test-npm` (fake release on 127.0.0.1).
- `mcp/`: the MCP server (`rowsafe mcp`, also served remotely by the control plane). Read-only
  unless `--allow-restore-points` / `--allow-writes` (remote: OAuth scopes `rowsafe:marks` /
  `rowsafe:act`). Changes to production go through `request_change` (and the direct
  `create_cloud_server`, `cloud_firewall`, `apply_fix`; catalog in `protocol/approval.go`).
  The control plane runs them right away as the person who connected the agent, with exactly that
  person's rights (owner or admin now), or refuses (403) with a reason the agent tells its user
  (a member, a key without a creator, a server key to compare, no backup yet, over the budget,
  ...). Nothing waits for approval (founder, 2026-10-10); the agent confirms disruptive,
  destructive and paid changes with its user first. `protocol/autonomy.go`: `act` (default) or
  `budget` (any agent may run `AutonomyBudgetActions` as the owner who chose it, within a monthly
  budget); `ask` is gone (read as act). A connection or key made before agents could act as their
  person (`OAuthConnection.ActsAsYou`, `APIKey.ActsAsCreator` false), or a key made by a key, is
  refused until its person lets it act. No tool can change the setting.
  `get_agent_action` / `list_agent_actions` show what agents did (the old names `get_approval` /
  `list_approvals` still work, unlisted: `toolAliases`). `server.json` is the MCP Registry entry
  (`sh.rowsafe/rowsafe`): release.yml's `mcp-registry` job publishes it at each tag's version
  (`scripts/publish-mcp-registry.sh`, secret `MCP_REGISTRY_PRIVATE_KEY`, the DNS key of rowsafe.sh).
- `scripts/install.sh`: the installer served at `curl -fsSL https://rowsafe.sh | sudo sh -s rse_...`
  (guided storage setup, finds PostgreSQL, plan → yes → apply, optional restart).
  `scripts/rowsafe-pg-restart`: the only root component (a sandboxed systemd path/service pair that
  restarts/stops/starts only the PostgreSQL units root listed in `/etc/rowsafe/restart-allowed`).
- `integrations/claude-code`, `integrations/codex`, `integrations/github-action`: plugins and the
  GitHub Action (published separately as github.com/rowsafe/action).
- `deploy/`: systemd unit, Docker sidecar images (`ghcr.io/rowsafe/agent:pg<major>`, `:clickhouse<YY.M>`, `:redis<X.Y>`,
  `:valkey<X.Y>`, `:qdrant<X.Y>`, `:opensearch<major>` and `:meilisearch1` floating, `:<ver>-pg<major>`,
  `:<ver>-clickhouse<YY.M>`... exact), compose examples.

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
