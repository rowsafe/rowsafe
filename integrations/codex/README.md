# Rowsafe Guard for OpenAI Codex

The database safety net for AI agents, in Codex: before a migration or destructive SQL, Codex checks that the database can be recovered, sets a named Rowsafe restore point (a Mark) and tells you its name. If something breaks, you Rewind to that Mark from the Rowsafe dashboard. Codex never restores or restarts anything on its own.

This directory is a Codex plugin with three parts:

- **MCP server** `https://api.rowsafe.sh/mcp` (`.mcp.json`): sign in with Rowsafe once; you choose the organization and what Codex may do. Always: `safety_check`, `list_restore_points` and read-only tools such as `fleet_health`, `database_health`, `list_alerts`, `live_activity`, Rowsafe Cloud's `cloud_catalog` and `get_cloud_server`, and `describe_change`. If you allow Marks: `create_restore_point`. If you allow it to act: backups, restore tests, checks, migration previews, safe copies, `request_change` for a change to production or a new Rowsafe Cloud server, the direct `create_cloud_server`, `cloud_firewall` and `apply_fix`, and `create_app_database` for the app's own database and login. Codex makes these changes with your rights (see [Safety model](#safety-model)).
- **Skill** `rowsafe-safety` (`skills/`): the workflow. Check, set a Mark, tell you its name, proceed; if something goes wrong, stop and hand recovery to you.
- **Skill** `rowsafe-new-database` (`skills/`): when the app needs a database, Codex picks the cheapest fitting Rowsafe Cloud size, tells you the price and gets your OK, creates the server (with a checkout link if pay as you go isn't on yet), waits until it's ready, gets the app's own database and login (made in the dashboard, where your browser makes its password, or `create_app_database` from a local `rowsafe mcp`), and puts the connection string in `.env`. The password never passes through Rowsafe.
- **Hook** `rowsafe guard` (`hooks/hooks.json`): a `PreToolUse` hook on shell commands. With the `rowsafe` CLI installed, it sets a Mark right before commands like `prisma migrate deploy`, `rails db:migrate`, `alembic upgrade`, `psql -c "DROP TABLE ..."`, `mysql -e "TRUNCATE ..."`, `mongosh --eval "db.orders.drop()"`, `clickhouse-client -q "ALTER TABLE ... DELETE ..."` or `sqlite3 app.db "DROP TABLE ..."`, whether or not the model remembered to. Without the CLI it does nothing.

It works with PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey, SQLite, Qdrant, OpenSearch and Meilisearch, in the Codex CLI and the IDE extension, which share `~/.codex/config.toml`. In Codex cloud, see [below](#codex-cloud).

## Requirements

- A Rowsafe account with the database connected.
- The project's database named once, so the skill and the hook know which one to check: `.rowsafe.json` at the project root (`{"database": "app"}`, or `rowsafe init app` with the CLI), or `ROWSAFE_DATABASE`. Without it, Codex asks you which database.
- For the hook only: the `rowsafe` CLI on your `PATH`, logged in (`rowsafe login`; see the [Quickstart](https://rowsafe.sh/docs/quickstart#install-the-cli-and-log-in)).

## Install

### The plugin (recommended)

```sh
codex plugin marketplace add rowsafe/rowsafe
codex plugin add rowsafe@rowsafe
```

Once the marketplace is added, you can also install and manage it from `/plugins` inside Codex.

Then **sign in with Rowsafe**: Codex opens the sign-in page; if it doesn't, run `codex mcp login rowsafe`. You approve Codex in the Rowsafe dashboard and choose what it may do. Check:

```sh
codex mcp list        # rowsafe  https://api.rowsafe.sh/mcp  ...  enabled
```

If you use the CLI, **trust the hook once**: Codex skips plugin hooks until you review them. Start Codex, run `/hooks`, and trust `rowsafe guard`. Codex asks again if the hook definition changes in an update.

### MCP server only

Hosted, with Sign in with Rowsafe:

```sh
codex mcp add rowsafe --url https://api.rowsafe.sh/mcp
codex mcp login rowsafe
```

With an API key instead, for CI:

```sh
export ROWSAFE_API_KEY=rsk_...
codex mcp add rowsafe --url https://api.rowsafe.sh/mcp --bearer-token-env-var ROWSAFE_API_KEY
```

With an API key, the hosted endpoint lists every tool, write tools included; what a tool can do depends on the key, and Codex acts as the person who created it. Give Codex its own key (`rowsafe api-keys create codex`), or a `--read-only` key if it should only check. You can also narrow the tools with `enabled_tools` (see `config.toml.example`).

Or run the server on your machine with the CLI's login (read-only tools plus `create_restore_point`; `--allow-writes` for the rest):

```sh
codex mcp add rowsafe -- rowsafe mcp --allow-restore-points
```

Add the workflow with the [AGENTS.md snippet](#agentsmd-snippet) or the skill: copy `skills/rowsafe-safety` into your repository's `.agents/skills/` (or `~/.agents/skills/` for every project).

For the hook without the plugin, put [`hooks/hooks.json`](hooks/hooks.json) in `~/.codex/hooks.json` or in a trusted project's `.codex/hooks.json`, and trust it with `/hooks`.

### AGENTS.md snippet

With or without the plugin, you can put the workflow in your project's `AGENTS.md`. Copy [`AGENTS.snippet.md`](AGENTS.snippet.md) and replace `app` with your database's name.

## What it does

Before a destructive or risky database operation, Codex:

1. finds the database (`ROWSAFE_DATABASE`, or `.rowsafe.json` in the project);
2. calls `safety_check`: can this database be restored right now? If not, it tells you why and waits for your OK;
3. calls `create_restore_point` with a descriptive name (`before-drop-legacy-orders`), waits until the Mark is confirmed in your backup bucket, and tells you its name;
4. runs the command.

If the command still goes wrong, Codex stops, doesn't try to repair the data, and tells you the Mark. You decide whether to Rewind, in the dashboard at [app.rowsafe.sh](https://app.rowsafe.sh) (see [Restore a database](https://rowsafe.sh/docs/guides/restore)).

The hook is the backstop for when the model skips the workflow. For a shell command that looks destructive, `rowsafe guard` sets the Mark `agent-<UTC time>` on the project's database, waits up to 90 seconds for it to be confirmed, lets the command run, and passes the Mark's name to you and to Codex. It ignores status, dry-run and help commands and commands that only mention a tool (`git commit -m "..."`, `grep`, `echo`). Test a command:

```sh
rowsafe guard --check 'npx prisma migrate deploy'   # destructive: prisma migrate deploy (exit 0)
rowsafe guard --check 'npx prisma migrate status'   # not destructive (exit 1)
```

What it matches is listed in the [Guard guide](https://rowsafe.sh/docs/guides/ai-agents#what-it-matches).

## Safety model

- **Codex doesn't restore, rewind, restart or fix anything unless you ask.** The skill tells Codex to make only changes you asked for or agreed to, and to say what will happen and what it costs before a destructive, disruptive or paid one. Recovery is your decision.
- **Read-only unless you say otherwise.** At sign-in you choose: read-only tools only, Marks (`create_restore_point`), or acting too. A Mark only records a named point in the backup stream; it changes no data.
- **Codex acts as you.** If you allowed Codex to act (or with `rowsafe mcp --allow-writes`), Codex makes changes with `request_change` (a Pulse fix, settings, a restart, a rewind, an upgrade, a Rowsafe Cloud server, and the rest of what the dashboard does) and the direct `create_cloud_server`, `cloud_firewall` and `apply_fix`, with exactly the rights of the person who connected it (who approved Codex at sign-in, or created its API key, or signed in with `rowsafe login` for a local `rowsafe mcp`), like a CLI token, right away. What that person can't do in the dashboard, Codex can't either: Rowsafe refuses it with the reason, and Codex tells you (a member's change, an API key that doesn't record who created it, a first payment only an owner makes). Nothing waits for approval. An owner can set a monthly budget for agents (Settings → AI agents); Codex can't change that setting.
- **Safety nets stay on.** Rowsafe saves a Mark before risky changes; a change that deletes or replaces data needs a backup first; backups of a database Codex removes are kept until an owner deletes them; adding a standby or moving or forking a database is done in the dashboard (a person compares the server's key), and so is an app database whose password is made in your browser. Every action is in the audit log as done by you through Codex, and in the owners' digest email of what AI agents did.
- **Everything goes through the Rowsafe API** with your sign-in or key, and shows up in the audit log. Nothing runs SQL or reads backup contents.
- **The hook warns, it doesn't block**, when something fails (no database configured, not logged in, Rowsafe unreachable, the Mark not confirmed): the command runs and Codex is told to mention it. To block instead, set `"require_protection": true` in `.rowsafe.json` or `ROWSAFE_REQUIRE_PROTECTION=1`: the hook then checks protection first and blocks the command when the database isn't protected or the Mark can't be confirmed.
- **It's a safety net, not a sandbox.** A destructive statement hidden in application code or an unusual wrapper won't match the hook. The skill and the MCP tools cover what the hook can't see.

Codex specifics:

- Codex connects to the MCP server and runs the hook outside its sandbox, so they reach Rowsafe even when the sandbox has no network access. Commands Codex runs in the sandbox usually can't, which is why the skill asks you to set a Mark yourself if the tools are unavailable.
- Codex passes only a few environment variables (`HOME`, `PATH`, `USER`, ...) to local MCP servers. For `rowsafe mcp` with `ROWSAFE_API_KEY` or `ROWSAFE_URL` instead of `rowsafe login`, forward them with `env_vars` (see `config.toml.example`).

## Example prompts

- "Is the app database safe to migrate right now?"
- "Set a restore point, then run the pending Prisma migrations."
- "Drop the `legacy_orders` table. Mark it first."
- "Which restore points does the app database have?"
- "Why is the app database not protected?"
- "Backfill `users.plan` from `subscriptions`; set a Mark before you start."

## Codex cloud

Codex cloud tasks read `AGENTS.md`, but agent internet access is off by default there and secrets are removed before the agent runs, so the hook isn't available and the MCP tools may not be. Use the AGENTS.md snippet, and set Marks yourself (`rowsafe mark app before-...`) before applying a cloud task's migrations to a real database.

## Files

| File | What it is |
| --- | --- |
| `.codex-plugin/plugin.json` | Plugin manifest (name, listing text, paths) |
| `assets/icon.png` | Logo and composer icon |
| `.mcp.json` | The MCP server the plugin connects to (hosted, Sign in with Rowsafe) |
| `skills/rowsafe-safety/SKILL.md` | The safety workflow skill |
| `skills/rowsafe-new-database/SKILL.md` | The "need a database?" skill (Rowsafe Cloud) |
| `hooks/hooks.json` | `PreToolUse` hook on shell commands: `rowsafe guard` (skipped without the CLI) |
| `AGENTS.snippet.md` | The workflow as an `AGENTS.md` section |
| `config.toml.example` | Manual MCP setup, hosted or local |

The plugin uses the `.codex-plugin/plugin.json` layout rather than a root `plugin.json` (Agent Plugins format) on purpose: the `.mcp.json` of this layout accepts Codex settings such as `tool_timeout_sec`.

More: [Guard: a safety net for AI agents](https://rowsafe.sh/docs/guides/ai-agents) · [MCP server reference](https://rowsafe.sh/docs/reference/mcp)
