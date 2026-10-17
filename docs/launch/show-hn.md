# Launch drafts: no account

Drafts only. Nothing here has been posted. The founder edits and posts.

**Before posting:**

- v0.10.19 (the installer's `--no-account`, `rowsafe add`, poolers) is released, and
  `curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account` works on a fresh server.
- Every command below works on that release, and rowsafe.sh/docs/guides/no-account-server is live.
- Restores without an account: confirm pgBackRest restores the backups by hand with the
  passphrase from the server, or cut "What if you go away?".
- The demo was recorded with v0.10.18: re-record it (`docs/demo/record.sh`) if pulse's output changed.

## Show HN

**Title** (80 characters max):

- Show HN: Rowsafe – backups, restore tests and health checks for your own Postgres
- Show HN: Rowsafe – a health check for Postgres that also applies the fixes (pulse only)

**URL:** https://github.com/rowsafe/rowsafe

**First comment:**

> Hi HN. I built Rowsafe because the databases we run on our own servers had none of the safety net a managed database gives you: backups someone had actually restored, someone noticing a table autovacuum gave up on, someone to clean it up.
>
> On the database server, with no account:
>
>     curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account
>
> That sets up continuous backups of PostgreSQL to your own S3 bucket (pgBackRest, encrypted on the server with a passphrase only you hold), a restore test every week that restores the latest backup next to production and checks it, and a health score. `sudo rowsafe status shop` says whether it's protected, `sudo rowsafe mark shop before-migration` saves a named restore point, `sudo rowsafe backups shop` lists backups. Restoring through Rowsafe (a copy as of any second, bringing back deleted rows, rewinding in place) needs an account for now. `sudo rowsafe login` connects the server to an account later and keeps its backups and Marks.
>
> For a database you can't install anything on (RDS, Cloud SQL, Supabase, Neon), from your laptop:
>
>     curl -fsSL https://rowsafe.sh/cli | sh
>     rowsafe add shop postgres://user@host/db
>     rowsafe pulse shop
>
> It reads PostgreSQL's statistics views (read-only, short timeouts) and gives a 0–100 score with findings in plain words: tables autovacuum isn't keeping up with, bloat, duplicate and unused indexes, sessions left idle in a transaction, locks, connections, replication slots, transaction ID wraparound, settings. `rowsafe fix` applies a fix after you confirm: VACUUM a table, end one session, drop a duplicate index, change settings with ALTER SYSTEM and a reload. It checks again right before it changes anything. `rowsafe mcp shop` gives the same checks to Claude Code, Codex or Cursor, read-only unless you pass `--allow-writes`. It works through PgBouncer and other poolers, except the fixes that run inside the database. Nothing is sent to us; anonymous usage counts exist but are off unless you turn them on.
>
> The account adds the dashboard: restores in one click, alerts, history, more than one server, and MySQL, MariaDB, MongoDB, ClickHouse, Redis/Valkey and SQLite. Free for one server, paid plans for more.
>
> The agent, CLI, installer and MCP server are Apache-2.0: everything that runs on your machines. The dashboard and control plane are not open source.
>
> Limits: no-account mode is PostgreSQL only, and the installer needs a Linux server. Over a connection, pulse can't see the server's memory or disk, so settings advice needs `--memory` and `--cpus`. It's new, so I'd most like to hear about findings that are wrong or missing.

## Questions HN will ask

**Why not pgBackRest, WAL-G or Barman?**
For PostgreSQL, Rowsafe runs pgBackRest. What it adds around it: setup in one command, encryption on by default, a restore test every week so you know the backups restore, restore to any second and bring back deleted rows from a dashboard or the CLI, and alerts when backups fall behind. If you already run pgBackRest and test your restores, you may not need us for backups; `rowsafe pulse` still works on that database.

**Why not pg_dump in a cron job?**
A dump is a snapshot: you lose everything since the last one, and restoring a big one takes hours. Most dump scripts are never restored until the day they're needed. Rowsafe keeps the write-ahead log, so you can restore to any second, and it restores a backup every week to prove it works.

**Why not PgHero, pganalyze or pgwatch?**
PgHero shows many of the same insights in a web page you host. pganalyze and pgwatch are monitoring: they collect statistics over time. `rowsafe pulse` is a one-off CLI with nothing to install on the server, and it applies the fix after you confirm. History and alerts need the agent.

**What does Rowsafe see?**
Without an account: nothing about your databases. The agent fetches the signed release manifest from releases.rowsafe.sh to update itself (`ROWSAFE_AUTO_UPDATE=false` turns that off); the CLI sends anonymous usage counts only if you run `rowsafe telemetry on`. With the agent: metadata such as database and table names, sizes, row counts, settings, metrics and the text of slow queries (you can turn query text off). Never rows: backups are encrypted on your server before upload, with a passphrase that never leaves it, and restores and comparisons run on your server and report only counts. The agent makes outbound HTTPS calls only and runs a fixed list of tasks, never arbitrary commands or SQL. What a compromised Rowsafe could and couldn't do: https://rowsafe.sh/docs/security

**Where do backups go?**
To your own S3-compatible bucket (AWS, R2, B2, MinIO, …), or to Rowsafe Storage if you prefer. Either way they are encrypted on your server first.

**What if you go away?**
The backups are pgBackRest's own format in your bucket, encrypted with your passphrase. You can restore them with pgBackRest and that passphrase, without us. Restoring a lost server is a pgBackRest restore by hand today.

**Will it change my production database on its own?**
No. Every change runs only when a person confirms it, or when an AI agent they connected asks with that person's rights. Fixes come from a fixed list and are checked again right before they run.

**How do you make money?**
The dashboard: free for one server and three databases, $39/month for 5 servers, $149/month for 25. Every plan has every feature. We also run PostgreSQL servers for people who don't want to (Rowsafe Cloud), billed by the hour.

**Why would I let an AI agent near my database?**
You don't have to. The MCP server is read-only by default. If you do let one change things, Rowsafe saves a restore point before migrations and destructive SQL, and the agent acts with exactly your rights.

## X (@rowsafe)

> Backups, a weekly restore test and a health score for the PostgreSQL on your own server. No account:
>
> curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account
>
> No server access? `rowsafe pulse postgres://…` scores any Postgres, managed ones too, and fixes what it finds after you confirm.
>
> Open source: github.com/rowsafe/rowsafe

Attach `docs/demo/rowsafe-demo.mp4` (sharper than the GIF on X).

## r/PostgreSQL

**Title:** I made a CLI that scores a PostgreSQL database's health and applies the fixes (open source, no account)

> `rowsafe pulse postgres://user@host/db` reads the statistics views (read-only, short timeouts) and gives a 0–100 score with findings in plain words: autovacuum falling behind, bloat, duplicate and unused indexes, idle-in-transaction sessions, locks, connections, replication slots, wraparound and settings. `rowsafe fix` applies one after you confirm (VACUUM, end a session, drop a duplicate index, ALTER SYSTEM + reload) and checks again right before it runs.
>
> Nothing is sent to us (usage counts are opt-in). Apache-2.0: https://github.com/rowsafe/rowsafe
>
> On your own server, `curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account` also sets up continuous backups to your own bucket and a weekly restore test, still with no account. Restoring through Rowsafe needs an account for now.
>
> Limits: PostgreSQL 13–18; through PgBouncer the fixes that run inside the database need the direct connection; on Windows, fixes don't apply yet. I'd like to know which findings are wrong or missing.
