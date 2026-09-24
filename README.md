# Rowsafe

**Sleep at night.** Rowsafe backs up the databases you already run, lets you restore to any second, and proves every week that your backups actually restore. This repository is the open-source part of [Rowsafe](https://rowsafe.sh): the agent that runs on your servers, the `rowsafe` CLI, the installer and the MCP server for AI agents.

Everything that touches your data is here, under Apache-2.0, so you can read exactly what runs on your machines.

**Documentation:** [rowsafe.sh/docs](https://rowsafe.sh/docs) · **Status:** PostgreSQL 13–18 on Linux servers and in Docker. MySQL, MariaDB, MongoDB and Redis are planned.

## Get started

```sh
rowsafe login                                          # opens the dashboard to approve this machine
curl -fsSL https://rowsafe.sh | sudo sh -s rse_…       # on the database server
rowsafe adopt app                                      # read-only plan first
rowsafe apply app
```

Then, before a risky change:

```sh
rowsafe status            # is everything protected?
rowsafe mark before-drop  # a named point you can restore to
```

Full guide: [Quickstart](https://rowsafe.sh/docs/quickstart).

## What's in this repository

| Path | What it is |
|---|---|
| `cmd/rowsafe-agent`, `internal/agent` | The agent. Makes outbound HTTPS requests only and runs a fixed set of tasks: inspect, adopt, check, backup, drill, restore point. |
| `cmd/rowsafe`, `client` | The CLI. |
| `mcp`, `integrations/claude-code` | `rowsafe mcp`, an MCP server for AI assistants, and a Claude Code plugin that creates a restore point before migrations. |
| `collect` | Database and host metrics the agent reports. |
| `protocol` | The API types shared by the agent, the CLI and the Rowsafe service. |
| `internal/pgbackrest`, `internal/pginspect` | PostgreSQL backup and inspection. |
| `scripts/install.sh` | The installer served at `https://rowsafe.sh`. |
| `release`, `cmd/rowsafe-release` | Release signing and verification. |

## Safety by design

- **Never restarts your database.** Changes that need a restart wait for you.
- **Plan before apply.** You see every change before anything happens.
- **Isolated restore drills** that can't touch production or its backups.
- **Signed, verifiable releases** with automatic rollback of a bad update. See [verifying releases](docs/verifying-releases.md).
- **Your secrets stay on your server,** and backups are encrypted before upload.

## Build from source

```sh
make build   # bin/rowsafe, bin/rowsafe-agent, bin/rowsafe-release
make test
make lint
```

Release builds are reproducible (`make dist`). Locally built agents run but never auto-update.

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Documentation lives in [rowsafe/docs](https://github.com/rowsafe/docs). Report vulnerabilities privately through [GitHub security advisories](https://github.com/rowsafe/rowsafe/security/advisories/new) ([SECURITY.md](SECURITY.md)).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Adraa Labs.
