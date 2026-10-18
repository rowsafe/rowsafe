// Command rowsafe is the Rowsafe CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

var version = "dev"

// usage is the full command reference (rowsafe help all). rowsafe help
// COMMAND prints the lines of it that start with that command.
const usage = `rowsafe - databases that let you sleep at night

All commands (NAME is optional where shown in brackets; see "rowsafe help names"):

Start here: save a database once, then use it by name ("rowsafe help local")
  rowsafe add NAME [CONN] [--from-env VAR] [--no-check] [--yes] [--json]
                                             save a database on this computer once (checks it connects, read-only);
                                             the connection string stays in your config folder, readable only by you.
                                             CONN is postgres://USER:PASSWORD@HOST/DB; without it: piped in, or this
                                             project's DATABASE_URL (asks first). On the database's own server
                                             (sudo), also offers to turn on backups, Marks, Proof and restores
  rowsafe add NAME ssh://USER@HOST[:PORT] [--database DB] [--no-check] [--yes] [--json]
                                             a server set up with Rowsafe (no account), from this computer over your own
                                             SSH (keys, ~/.ssh/config; sudo when USER isn't root). Only the address is
                                             saved here. Then status, mark, backups, restore, rewind, proof, alerts,
                                             channels and mcp take NAME and run on that server's agent; pulse, fix and
                                             the other direct ones run there with its rowsafe. Also --ssh USER@HOST
  rowsafe use NAME [--json]                  make NAME this project's database (.rowsafe.json; never the password)
  rowsafe databases [--json]                 databases saved on this computer (also rowsafe ls when not logged in)
  rowsafe forget NAME [--yes]                delete a saved database's connection string
  rowsafe pulse [NAME|CONN] | fix | insights | top | activity | settings | tune | schema | explain | mcp
                                             NAME: a saved database, or this project's; CONN: a connection string
                                             used once; DATABASE_URL when you aren't logged in
  rowsafe schema [NAME|CONN] [TABLE...] [--table T] [--schema S] [--limit N] [--json]
                                             tables, columns, keys, indexes (used or not), views and enums,
                                             compact for an AI agent's context (the largest 100 tables unless named)
  rowsafe explain [NAME|CONN] "SELECT ..." | -f FILE [--analyze [--timeout 30s]] [--json]
                                             why a query is slow, in plain words, and the index that would likely
                                             help; --analyze runs a SELECT read-only (rolled back)

Getting started
  rowsafe login [--url URL]                  log in with your browser (default URL https://api.rowsafe.sh)
  rowsafe login --key rsk_... [--url URL]    log in with an existing API key (CI, scripts)
  sudo rowsafe login [--yes]                 on a database server: also connects it to the dashboard, with its
                                             backups, Proofs and Marks (no reinstall)
  rowsafe logout [--keep-key]                forget the login and revoke the key "rowsafe login" created
  rowsafe whoami [--json]                    control plane, organization, plan, API key in use and who it acts as
  rowsafe hosts add [USER@]SERVER [-p PORT] [-i KEY] [-- INSTALLER OPTIONS]
                                             install the agent on a Linux server over SSH from this computer
                                             (no SERVER: on this Linux server). The installer sets up everything
                                             there and asks before turning on backups
  rowsafe hosts enroll-token [--ttl 1h]      the install command for a database server. The installer sets up
                                             everything there and asks before turning on backups
  rowsafe init [NAME] [--yes] [--no-agents]  write .rowsafe.json here, so commands in this project use NAME;
                                             offers a short section in AGENTS.md / CLAUDE.md for AI agents
  rowsafe restart [NAME] [--yes]             restart the database, e.g. when setup needs it; asks first. Only on
                                             servers where the installer allowed it
  rowsafe restart [NAME] --at TIME|window [--yes]
                                             restart it later: "03:00", "2026-10-20 03:00", "in 2h" (up to 30
                                             days ahead) or the server's maintenance window (Rowsafe Cloud)
  rowsafe restart [NAME] --cancel            cancel the scheduled restart
  rowsafe version                            the CLI's version

Rowsafe Cloud: PostgreSQL servers Rowsafe runs for you, billed by the hour (never more than the monthly price)
  rowsafe cloud sizes [--cloud CLOUD] [--region REGION] [--json]
                                             clouds, regions and sizes: CPUs, memory, disk, the price of an hour,
                                             the most a month costs, what is sold out right now, and the
                                             databases a new server can run
  rowsafe cloud create NAME [--cloud hetzner] [--region fsn1] [--size small] [--postgres 17]
        [--engine postgresql|mysql|mariadb|valkey|clickhouse] [--engine-version V]
        [--extensions vector,postgis,timescaledb] [--allow me|IP|CIDR]... [--standby] [--wait] [--yes] [--json]
                                             a new server with PostgreSQL (or the --engine offered), backups, Proof and Pulse on;
                                             --extensions: pgvector, PostGIS, TimescaleDB (PostgreSQL 15-18) on from the start. Defaults:
                                             the cheapest size free now; only this computer may connect. The first
                                             server billed by the hour gives you a link to add a card, once
  rowsafe cloud list [--json]                the servers Rowsafe created: status, size, price, who can connect
  rowsafe cloud show [NAME] [--json]         one server: status, size, price, where apps connect, who can
  rowsafe cloud wait [NAME] [--timeout 30m]  follow a server being created or resized until it's ready
  rowsafe cloud resize [NAME] SIZE [--yes] [--wait]
                                             another size (a Mark first; offline a few minutes while the server
                                             restarts, a pair switches over instead). Disks never shrink
  rowsafe cloud allow [NAME] [me|IP|CIDR]... let more addresses connect (default: this computer)
  rowsafe cloud firewall [NAME] [--set A,B | --add A | --remove A | --clear] [--yes] [--json]
                                             who can connect: show it, or change it (asks before cutting anyone off)
  rowsafe cloud passphrase [NAME] [--file PATH]
                                             the backup passphrase, encrypted for this terminal only. Save it: a
                                             server with a database can't be deleted before
  rowsafe cloud clone [SOURCE] NAME [--at TIME | --mark LABEL] [--delete-after 24h] [--region R] [--size S]
        [--allow me|IP]... [--wait] [--yes] [--json]
                                             a copy of a database as it was then (default: now) on a new server
                                             billed by the hour, next to the source at its size by default
  rowsafe cloud retry [NAME] [--wait]        create a server that failed to set up again
  rowsafe cloud delete-after [NAME] 24h|never
                                             when Rowsafe deletes a clone (from now; never keeps it)
  rowsafe cloud maintenance [NAME] [--json]  the weekly maintenance window: when, what it applies next, critical fixes
  rowsafe cloud maintenance set [NAME] [--day sun] [--hour 3] [--timezone ZONE] [--on | --off] [--json]
                                             move the window, or turn it off (critical fixes still go in once due)
  rowsafe cloud maintenance postpone [NAME]  skip the next window, once
  rowsafe cloud maintenance apply-now [NAME] [--yes] [--json]
                                             apply what the next window would, now (a Mark first; asks you to type
                                             the server's name)
  rowsafe cloud delete [NAME] [--with-standby] [--wait] [--yes]
                                             delete the server and the database on it (asks you to type the name)
  rowsafe env [DATABASE] [--on NAME] [--file .env] [--name DATABASE_URL] [--user USER] [--extension EXT]...
        [--reset-password] [--print] [--force]
                                             the app's database and login, with a password made for this computer
                                             only: writes DATABASE_URL to .env (and .env to .gitignore). DATABASE
                                             defaults to this directory's name. Never prints the password unless --print
  rowsafe connect [DATABASE|SERVER] [--on NAME] [--user USER] [--access read_only|read_write|owner] [-- PSQL ARGS]
                                             open psql: as a temporary user removed when you quit, or as USER (psql
                                             asks for its password). Offers to let this computer connect first

Manual setup, from your workstation (the installer does this for you)
  rowsafe adopt NAME [--host HOST] [--port 5432] [--socket-dir DIR] [--retention-full 2]
                                             register an existing PostgreSQL; prints a read-only plan.
                                             --host may be omitted when the organization has one host;
                                             other engines: --engine ENGINE ("rowsafe help adopt" lists them),
                                             SQLite: --engine sqlite --path /srv/app/db/production.sqlite3
  rowsafe plan [NAME]                        re-run the read-only plan
  rowsafe apply [NAME] [--force] [--yes]     apply the plan (never restarts PostgreSQL)
  rowsafe verify [NAME]                      check now that WAL reaches your storage; backups start once it passes

Rewind: continuous backups, restore to any second
  rowsafe ls                                 databases
  rowsafe show [NAME]                        one database in detail
  rowsafe status [NAME] [--json]             with NAME: is it recoverable right now? without: every problem, with
                                             what to do. Exit 0 if protected / all healthy, 3 if not
  rowsafe backup [NAME] [--type full|diff|incr] [--second-copy] [--no-wait]
                                             take a backup now (--second-copy: a full one to the second copy)
  rowsafe backups [NAME] [--second-copy]     backups (in the second copy)
  rowsafe mark [NAME] [LABEL] [--no-wait] [--json]
                                             a named restore point (a Mark), e.g. before a migration.
                                             LABEL defaults to manual-<UTC time>. --json prints the Mark
                                             (status, restore_from_backup) for scripts and CI
  rowsafe marks [NAME]                       restore points
  rowsafe storage [NAME] [--json]            what the backups take in each storage, the cost a month, the second
                                             copy, and ways to spend less
  rowsafe secondcopy [NAME] [--json]         the second backup copy: where it is, how far it is, its backups
  rowsafe secondcopy add [NAME] --endpoint HOST --bucket BUCKET [--region R] [--yes] [--no-wait]
                                             on the server, with sudo: keep a second copy of the backups and the
                                             change log in another bucket, ideally at another provider. The key
                                             ($ROWSAFE_REPO2_S3_KEY, $ROWSAFE_REPO2_S3_KEY_SECRET, or asked) and a
                                             new passphrase stay in /etc/rowsafe/agent.env. Tests the bucket first
  rowsafe secondcopy remove [--yes]          on the server, with sudo: stop the second copy (its bucket is kept)
  rowsafe set [NAME] [--retention-full N] [--full-schedule CRON] [--diff-schedule CRON] [--proof-schedule CRON]
                                             change retention and schedules (5-field cron, UTC; --diff-schedule "" disables diffs)
  rowsafe remove NAME [--keep-archiving] [--yes]
                                             stop managing a database; never changes the server
  rowsafe restore [NAME] --to TIME|MARK [--hours 24] [--second-copy] [--no-wait]
                                             restore a copy as it was then, next to production (never
                                             touches it): rowsafe rewind copy, with the time or Mark in one flag.
                                             --second-copy restores from the second copy (the first bucket is gone)
  rowsafe restore NAME --from-bucket [--as NAME] [--to TIME] [--port N | --new-cluster] [--folder F] [--yes]
                                             on a server on its own, installed with the old server's bucket and
                                             passphrase: restore a lost (or moving) database here and protect it
  rowsafe restores [NAME] [--json]           the copy, the recovery window and recent restores (rowsafe rewind)
  rowsafe rewind [NAME] [--json]             the recovery window, the copy and data kept aside by a rewind
  rowsafe rewind find [NAME] [--table T] [--since 24h | --from TIME [--to TIME]] [--kind delete,update,truncate,drop]
                                             when were rows deleted or changed, or a table emptied or dropped?
                                             Lists the biggest changes with exact times, to rewind to just before
  rowsafe rewind copy [NAME] (--at TIME | --mark LABEL) [--hours 24] [--second-copy] [--no-wait]
                                             restore a copy as it was then, next to production (never
                                             touches it). TIME: "2026-09-24 14:04" or "14:04" (your time
                                             zone), "10m ago", or RFC 3339
  rowsafe rewind compare [NAME] [TABLE...] [--db DB] [--json]
                                             rows missing in production, changed, or added since, by
                                             primary key (no TABLE: every table)
  rowsafe rewind rows [NAME] TABLE... [--include-changed] [--db DB] [--yes]
                                             bring the missing rows back from the copy (a Mark first; asks
                                             you to type the name). TABLE is schema.table or DB:schema.table
  rowsafe rewind extend [NAME] [--hours 24]  keep the copy longer
  rowsafe rewind drop [NAME] [--yes]         delete the copy
  rowsafe rewind database [NAME] --to TIME|MARK [--yes]
                                             rewind the whole live database (stops PostgreSQL; the current
                                             data is kept aside for undo; asks you to type the name). Only on
                                             servers where the installer allowed restarting PostgreSQL
  rowsafe rewind undo [NAME] [--yes]         undo the rewind: put the data from before it back
  rowsafe rewind cleanup [NAME] [--yes]      delete the data kept aside by a rewind (frees disk)
  rowsafe files [NAME] [--json]              the folders backed up with the database (uploads, media)
  rowsafe files add [NAME] PATH [--exclude cache,*.tmp]
                                             back up a folder of the database server with the database
  rowsafe files remove [NAME] PATH [--yes]   stop backing up a folder
  rowsafe files backup [NAME] [--no-wait]    snapshot the folders now
  rowsafe files restore [NAME] (--at TIME | --mark LABEL) [--folder PATH] [--path REL]...
                        [--column DB:schema.table.column] [--whole-folder] [--overwrite] [--preview] [--yes]
                                             bring files back as they were: by default only the missing
                                             ones; --column restores the files a column refers to
  rowsafe files undo [NAME] [--yes]          undo a --whole-folder restore
  rowsafe files proof [NAME]                 restore a few files and compare them with the live ones, now
  rowsafe files [SUBCOMMAND] --server SERVER ...
                                             the same for a server's own folders (any folder or Docker volume
                                             as /var/lib/docker/volumes/VOLUME/_data, with or without a
                                             database on it); a restore asks for the server's hostname

Move in: bring a database from DigitalOcean, RDS, Supabase, Neon... onto your server
  rowsafe migrate [NAME] [--json]            migrations (into NAME, or all)
  rowsafe migrate start [NAME] [--into DB] [--method live|dump] [--source-env VAR] [--id ID] [--host ADDR] [--user NAME] [--yes]
                                             check the source and start copying into the server of NAME. The
                                             connection string is typed (not shown), piped, or read from $VAR,
                                             and sealed here to the server's key: Rowsafe never sees it
  rowsafe migrate status ID [--json]         progress: tables copied, how far behind, the check's findings
  rowsafe migrate fix ID [--yes]             mark source tables without a primary key REPLICA IDENTITY FULL
  rowsafe migrate switch ID [--writes-stopped] [--user NAME] [--host ADDR] [--yes]
                                             switch over: the old database goes read-only (unless you stopped
                                             writes yourself), the last changes arrive, then the new
                                             connection string is shown once
  rowsafe migrate password ID                a new password for the apps' login, shown once
  rowsafe migrate writable ID                make the old database writable again (rollback)
  rowsafe migrate cancel ID [--drop-copy] [--yes]
                                             stop and remove the sync from the old database
  rowsafe migrate finish ID [--yes]          forget the old database's connection string
  Advanced (restore by hand or to another server): https://rowsafe.sh/docs/guides/restore

Updates and upgrades: PostgreSQL kept current, with a Mark first
  rowsafe update [NAME] [--yes] [--no-wait]  install the newest minor release (e.g. 16.9 -> 16.10) and restart
                                             PostgreSQL; asks you to type the name. Only on servers where the
                                             installer allowed updates (--allow-updates)
  rowsafe update [NAME] --auto on|off [--timezone ZONE]
                                             install minor releases by itself, Sundays at 03:00 (your time zone)
  rowsafe upgrade [NAME] [--json]            versions, newer majors, the latest rehearsal, an upgrade to undo
  rowsafe upgrade [NAME] [--to 18] [--rehearse-only] [--mode safe|fast] [--yes]
                                             check, rehearse on a restored copy (production isn't touched),
                                             then upgrade. Safe keeps the old version for an instant undo;
                                             fast hard-links the data (undo restores from the backup)
  rowsafe upgrade undo [NAME] [--yes]        go back to the version the upgrade kept (7 days)
  rowsafe upgrade cleanup [NAME] [--yes]     remove the kept version (frees disk; no undo afterwards)
  rowsafe security-updates [NAME] [--yes] [--no-wait] [--json]
                                             install the server's security updates (a Mark first; services keep
                                             running, the database isn't restarted). Only where root allowed it
  rowsafe reboot [NAME] [--yes] [--no-wait] [--json]
                                             reboot the database's server (a Mark first; a minute or two offline;
                                             asks you to type the server's name). Only where root allowed it

Standby: a second server that stays in sync, is readable, and takes over
  rowsafe standby [NAME] [--json]            the standby, how far behind it is, fenced old primaries, automatic
                                             failover, connection strings that follow the primary
  rowsafe standby add [NAME] --host SERVER [--port 5432] [--fingerprint F] [--no-stream] [--no-wait]
                                             restore the latest backup on an empty cluster of SERVER and follow
                                             the primary (streaming when it can reach it, else the bucket)
  rowsafe standby promote [NAME] [--primary-down] [--force] [--yes]
                                             make the standby the primary: the old one is stopped for good first
                                             (asks you to type the name)
  rowsafe standby rebuild [NAME] [--host SERVER] [--yes]
                                             turn the fenced old primary into the new standby
  rowsafe standby unfence [NAME] [--yes]     start the fenced primary again when the standby wasn't promoted
  rowsafe standby failover [NAME] --on|--off [--after 3m] [--max-data-loss 1m] [--yes]
                                             automatic failover (off by default)
  rowsafe standby remove [NAME] [--yes]      remove the standby; its cluster gets its own data back
  rowsafe standby forget [NAME] [--host SERVER] [--yes]
                                             stop watching a fenced old primary (it stays stopped; asks you to
                                             type its name)
  On servers on their own (both set up with the same bucket and passphrase), one command on each server:
  sudo rowsafe standby link NAME --address IP
                                             on the primary: let the standby at IP stream (optional; without
                                             it the standby follows through the bucket)
  sudo rowsafe standby create NAME [--primary IP[:PORT]] [--port N] [--folder F] [--yes]
                                             on the standby's server: its empty cluster restores the backups
                                             and follows the primary; on a fenced old primary, rebuilds it
  sudo rowsafe standby fence NAME [--yes]    on the primary: stop it for good for a switchover (the bucket
                                             says where its last change is)
  sudo rowsafe standby promote NAME [--primary-down] [--yes]
                                             on the standby's server: promote it (after the fence, nothing is
                                             lost; --primary-down when the primary is down)
  sudo rowsafe standby unfence|unlink|remove|forget NAME [--yes]
                                             start a fenced primary again (if the standby wasn't promoted),
                                             stop the streaming, remove the standby, let a fenced copy go
  rowsafe move [NAME] --to SERVER [--port N] [--at TIME] [--keep-days 7] [--fingerprint F]
                                             move the database to another server: a standby there, then a
                                             planned switchover (nothing lost); the old server is kept stopped
                                             as a way back. Without --to: the move in progress
  rowsafe move switch|schedule|cancel|back|finish [NAME]
                                             switch over now, (re)schedule it (--at TIME, --clear), cancel,
                                             switch back to the old server, remove the old server

Fork: a new, independent database from any moment, on another server or a new port
  rowsafe fork [SOURCE] --to SERVER [--name NAME] [--at TIME | --mark MARK] [--mask]
               [--port PORT | --into-port PORT] [--fingerprint F] [--no-wait] [--json]
                                             restore SOURCE as it was (default: now) as a new database with its own
                                             backups; --mask replaces personal data before anyone can connect
  rowsafe forks [SOURCE] [--json]            the forks made from SOURCE, and what it was forked from

Proof: the weekly restore test
  rowsafe proof [NAME] [--second-copy] [--no-wait]
                                             restore the latest backup (in the second copy) to a scratch copy and
                                             check it, now
  rowsafe proof NAME --from-bucket [--folder F]
                                             on another server on its own with the same bucket and passphrase:
                                             test NAME's backups there (nothing changes on either server)
  rowsafe proofs [NAME]                      restore test results

Pulse: health, monitoring and alerts
  rowsafe pulse [NAME] [--json]              health score (0-100) and findings in plain language; without NAME,
                                             every database. Exit 3 if one scores below 70
  rowsafe fix [NAME] [FINDING [FIX] | NUMBER] [--yes]
                                             what Rowsafe can fix from pulse (clean up tables, end a stuck
                                             session, remove an unused index...) and do it; asks first
  rowsafe insights [NAME] [--limit 10] [--json]
                                             largest tables, unused and duplicate indexes, estimated bloat,
                                             dead rows and vacuum, transaction ID age
  rowsafe top [NAME] [--since 24h] [--sort total_time|calls|mean_time|rows] [--query ID] [--json]
                                             statements that took the most time in a range, and which got slower
  rowsafe recommendations [NAME] [--group schema|queries|capacity|indexes] [--dismissed] [--json]
                                             what would make it better (missing indexes, ids running out,
                                             N+1 queries, memory...), why and what it costs; without NAME,
                                             each database's top one. Apply the ones Rowsafe can do with rowsafe fix
  rowsafe recommendations [NAME] --dismiss ID [--reason not_relevant|intended|later|wrong] [--note TEXT]
  rowsafe recommendations [NAME] --restore ID
                                             set a recommendation aside, or bring it back
  rowsafe recommendations find [NAME] [--no-wait]
                                             test index ideas on a copy of the database now (runs every night
                                             by itself); proven ones appear under Indexes
  rowsafe recommendations schedule [NAME] auto|off|CRON
                                             when to test index ideas (auto: every night at the quietest hour)
  rowsafe activity [NAME]                    queries running, or idle in a transaction, for over a minute
  rowsafe alerts [--all | --resolved]        firing alerts (with --all, resolved ones too)
  rowsafe alerts ack ID                      acknowledge a firing alert: no more reminders
  rowsafe alerts rules [--json]              built-in alert rules with this org's settings
  rowsafe alerts rules set RULE [--on | --off] [--threshold N] [--for 5m] [--severity warning|critical] [--json]
                                             change a rule for this organization (what you don't pass stays)
  rowsafe alerts rules reset RULE [--json]   back to the defaults
  rowsafe channels list
  rowsafe channels add --type email --name NAME --address A [--address B] [--min-severity warning]
  rowsafe channels add --type slack|discord|teams|webhook --name NAME --url URL [--min-severity warning]
  rowsafe channels add --type pagerduty --name NAME --routing-key KEY [--region us|eu]
  rowsafe channels add --type opsgenie --name NAME --api-key KEY [--region us|eu]
  rowsafe channels add --type telegram --name NAME --bot-token TOKEN --chat-id ID
  rowsafe channels add --type ntfy --name NAME --topic TOPIC [--server https://ntfy.sh] [--token tk_...]
                                             where alerts are sent (webhooks print a signing secret once).
                                             Leave out --routing-key, --api-key or --bot-token to type it
                                             (not shown) or pipe it, or pass --secret-env VAR. On a server
                                             without the dashboard: slack, discord, ntfy (no --token), webhook
  rowsafe channels remove ID
  rowsafe channels test ID                   send a test notification now
  rowsafe report [--preview [--html]] [--on | --off] [--to A,B] [--send-test]
                                             "Your weekly Pulse", the weekly email: settings, preview, test
  rowsafe security [NAME] [--json]           security grade, checklist and findings: who can reach the database,
                                             how they log in, TLS, and what Rowsafe can do about it
  rowsafe security check [NAME] [--no-wait] [--json]
                                             check again now (and from the internet, when that is on)
  rowsafe security set [NAME] --outside-check on|off [--json]
                                             let Rowsafe check the database's port from the internet, or not
  rowsafe security fix [NAME] [ACTION] [--allow me|IP|CIDR]... [--require-tls] [--role USER]
        [--password-env VAR] [--yes] [--no-wait] [--json]
                                             without ACTION: the actions and whether each can run now. E.g.
                                             restrict_access --allow 10.0.0.0/16, enable_tls, firewall, set_password
                                             --role app (the password is made here; Rowsafe never sees it)
  rowsafe logs [NAME] [--kind errors|locks|maintenance|KIND] [--search TEXT] [--limit 50] [--groups] [--follow] [--json]
                                             the database's log entries (redacted on the server), newest last;
                                             --groups: repeated messages of the last 24 hours
  rowsafe logs set [NAME] [--send on|off] [--full-text on|off] [--json]
                                             send the logs to Rowsafe or not; keep literal values or not
  rowsafe log-destinations list [--json]     where the organization's logs are forwarded
  rowsafe log-destinations add --type datadog|betterstack|papertrail|loki|elasticsearch|webhook|syslog --name NAME
        [--site S] [--url U] [--host H --port P] [--username U] [--index I] [--kinds errors,locks]
        [--database NAME]... [--secret-env VAR] [--json]
                                             forward logs there; the API key or token comes from VAR, is typed or
                                             piped, never an argument
  rowsafe log-destinations test ID           send a test entry now
  rowsafe log-destinations off ID            pause forwarding there
  rowsafe log-destinations on ID             forward there again
  rowsafe log-destinations remove ID [--yes] stop forwarding there
  rowsafe pooling status [NAME] [--json]     connection pooling (PgBouncer): state, connection strings, pools
  rowsafe pooling on [NAME] [--mode transaction|session] [--pool-size N] [--max-client-conn N]
        [--listen local|private|public] [--port 6432] [--yes]
                                             turn pooling on (or change it); Rowsafe installs PgBouncer on the
                                             server. Only on servers where the installer allowed it
  rowsafe pooling off [NAME] [--yes]         stop PgBouncer and remove what Rowsafe installed; asks first
  rowsafe settings [NAME] [SETTING] [--all] [--json]
                                             PostgreSQL's settings that matter: value, default, where it is
                                             set, and whether a change needs a restart
  rowsafe settings set [NAME] SETTING=VALUE... [--yes] [--no-wait]
                                             change settings (ALTER SYSTEM + reload, a Mark first; VALUE
                                             default resets one). Rowsafe's archiving settings never change
  rowsafe settings undo [NAME] [CHANGE_ID] [--yes]
                                             undo the latest change made through Rowsafe (or CHANGE_ID)
  rowsafe tune [NAME] [--workload web|analytics|mixed] [--disk ssd|hdd] [--all] [--yes] [--json]
                                             settings that suit this server (memory, CPUs, disk) and apply
                                             them; asks first. Nothing restarts: see rowsafe restart

Guard: the safety net for AI agents
  rowsafe mcp [NAME] [--allow-restore-points | --allow-writes]
                                             MCP server on stdio for AI assistants (https://rowsafe.sh/docs/reference/mcp); read-only
                                             unless restore points or all write tools are allowed (changes to
                                             production run as the signed-in person, with their rights). NAME: a
                                             server saved over SSH (rowsafe add NAME ssh://...): its Marks, backups,
                                             restores and alerts
  rowsafe guard                              Claude Code PreToolUse hook: before a destructive database
                                             command, create a restore point (https://rowsafe.sh/docs/guides/ai-agents)
  rowsafe guard --check COMMAND              tell whether COMMAND looks destructive (exit 0 yes, 1 no)
  (rowsafe status NAME, above, exits 3 when a database is not protected: use it to gate risky changes)
  rowsafe preview [NAME] FILE [--db DB] [--json | --format text|json|markdown] [--fail-on careful|dangerous]
                                             run a migration (FILE, or - for stdin: SQL, or for MongoDB plain mongosh
                                             calls) on a fresh copy of the database and report locks, rewrites,
                                             dropped tables, rows and time with a verdict: safe, careful,
                                             dangerous, or failed (it fails on the copy). Never touches production.
                                             Exit 0 once the preview ran, 1 if it couldn't; with --fail-on, 3 at or
                                             above that verdict and 2 if the migration fails
  rowsafe previews [NAME] [ID] [--json]      recent previews, or one in full
  rowsafe copies [NAME] [--json]             safe copies: masked copies developers and AI agents can connect to
  rowsafe copies create [NAME] [--allow IP] [--listen private|public|localhost|IP|*] [--port PORT] [--hours 24] [--db DB] [--structure] [--json]
                                             make one: restore, mask (--masked, the default), open it on the server for the
                                             allowed addresses (default: this computer's; on a server Rowsafe protects on its
                                             own: localhost, on --port). Prints the connection string once.
                                             SQLite: a new file on the server (no password); --structure for the
                                             structure without rows
  rowsafe copies extend [NAME] ID [--hours 24]
                                             keep a safe copy longer
  rowsafe copies delete [NAME] ID [--yes]    delete a safe copy
  rowsafe copies password [NAME] ID          a new password for a safe copy (made here; Rowsafe never sees it)
  rowsafe masking [NAME] [--all] [--json]    which columns safe copies mask, and how
  rowsafe masking set [NAME] [DB:]TABLE.COLUMN STRATEGY
                                             change one column's masking (keep to leave it real)
  rowsafe masking refresh [NAME]             read the tables again (names and types only)

Databases & users: the databases, users and extensions inside a server (--on NAME: which server)
  rowsafe db [ls] [--on NAME] [--json]       databases, users and extensions on the server
  rowsafe db create DB [--owner USER | --new-owner USER] [--extension EXT]... [--template template0] [--locale L]
                                             create a database. Without --owner a new user owns it: its
                                             password is made on the server and shown here once
  rowsafe db drop DB [--yes]                 remove a database and everything in it (a Mark first; asks you
                                             to type its name)
  rowsafe db users [--json]                  users, what they can connect to and how their password is stored
  rowsafe db user add USER --db DB[,DB] [--access read_only|read_write|owner]
                                             a new user; its password is shown once (Redis and Valkey:
                                             no --db; --keys "session:*" limits the keys it reaches)
  rowsafe db user password USER              a new password for USER, shown once
  rowsafe db user remove USER [--reassign-to USER] [--yes]
                                             remove a user; what it owns goes to --reassign-to
  rowsafe db ext on|off DB EXTENSION [--allow-untrusted] [--restart]
                                             turn an extension on or off in one database (pgvector, PostGIS and
                                             TimescaleDB are installed first; TimescaleDB needs --restart: a Mark, one restart)
  Passwords are encrypted on the server for this terminal only; Rowsafe never sees them.

Admin
  rowsafe tasks [NAME] [--status S] [--type T] [--limit N]
                                             recent tasks for a database, or for all of them
  rowsafe task ID                            one task with its full log
  rowsafe hosts list                         hosts with agent version and update state
  rowsafe hosts pin HOST VERSION             keep a host's agent on VERSION (ignores rollout and halts)
  rowsafe hosts unpin HOST                   follow the host's update channel again
  rowsafe hosts channel HOST NAME            switch the host's update channel (e.g. stable, beta)
  rowsafe hosts remove HOST [--yes]          remove a host without databases and revoke its agent
  rowsafe hosts permissions HOST [--json]    what root allowed Rowsafe to do there (restart, updates, firewall...)
  rowsafe hosts update HOST [--version V] [--json]
                                             update the host's agent now, ahead of the staged rollout
  rowsafe org                                plan, limits and usage
  rowsafe api-keys list
  rowsafe api-keys create NAME [--read-only] the key is shown once; read-only keys can only read
  rowsafe api-keys revoke ID
  rowsafe audit [--limit N]                  who changed what, newest first

Usage counts: off unless you turn them on; nothing is sent by default
  rowsafe telemetry status [--json]          on or off, and exactly what would be sent after each command
  rowsafe telemetry on                       send anonymous counts of the commands you run: names from this
                                             list, version, OS, exit code, how long, terminal or AI agent,
                                             logged in or not, a random ID. Never arguments, names or errors
  rowsafe telemetry off                      stop, and forget the random ID (ROWSAFE_TELEMETRY=0 or
                                             DO_NOT_TRACK=1 also keep them off)
  rowsafe tips on | off | status             a short tip after a command, at most one an hour, only at a
                                             terminal (never with --json or for AI agents; ROWSAFE_NO_TIPS=1)

Backups, proof and mark wait for the task to finish; pass --no-wait to return at once.
Scripts and AI agents (rowsafe help agents):
  Changes ask first on a terminal. Pass --yes to confirm; without a terminal, a change without --yes is refused
  at once, it never waits for an answer.
  Every command takes --json: stdout is then only JSON, messages and progress go to stderr.
  Exit codes: 0 it worked, 1 it didn't (the error says what to do next), 2 the command was used the wrong way,
  3 not healthy or not protected (status, pulse, preview --fail-on).
The CLI acts as the person behind the key, with that person's rights; when it can't, the error says why.

Environment: ROWSAFE_URL and ROWSAFE_API_KEY override the saved login; ROWSAFE_DATABASE names the database.
`

type config struct {
	URL    string `json:"url"`
	APIKey string `json:"api_key"`
	// KeyID is set when `rowsafe login` created the key in the browser
	// flow; `rowsafe logout` revokes only such keys.
	KeyID string             `json:"key_id,omitempty"`
	Org   *protocol.OrgBrief `json:"org,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rowsafe", "config.json"), nil
}

var errNotLoggedIn = errors.New("not logged in: run `rowsafe login`")

func loadConfig() (config, error) {
	var c config
	if p, err := configPath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			if err := json.Unmarshal(data, &c); err != nil {
				return c, fmt.Errorf("reading %s: %w", p, err)
			}
		}
	}
	if v := os.Getenv("ROWSAFE_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("ROWSAFE_API_KEY"); v != "" {
		c.APIKey = v
	}
	if c.APIKey == "" {
		// Without an account, on a server whose agent runs its own control
		// plane: its socket (local.go).
		if url, err := localControl(c.URL); url != "" || err != nil {
			c.URL, c.APIKey = url, "local"
			return c, err
		}
	} else if os.Getenv("ROWSAFE_API_KEY") == "" && os.Getenv("ROWSAFE_URL") == "" {
		// A login saved on a server whose agent went back to running
		// without an account (the installer's --no-account, now its default): the agent's
		// socket only exists then, and commands here are about it.
		if url, err := localControl(""); url != "" && err == nil {
			c.URL, c.APIKey, c.KeyID = url, "local", ""
			return c, nil
		}
	}
	if c.URL == "" {
		c.URL = protocol.DefaultAPIURL
	}
	if c.APIKey == "" {
		return c, errNotLoggedIn
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return c, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cliMain(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// cliMain runs one command and returns its exit code (rowsafe help
// exit-codes). Errors go to stderr in plain words with the next step.
func cliMain(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) == 0 {
			fmt.Fprint(os.Stderr, shortHelp)
			return 2
		}
		fmt.Print(helpFor(args[1:]))
		return 0
	}
	if topic, ok := helpRequest(args); ok {
		// rowsafe COMMAND --help: the command's reference, logged in or not.
		fmt.Print(helpFor(topic))
		return 0
	}
	run := telemetryStart(args) // usage counts, off unless turned on (telemetry.go)
	if len(referenceLines(args[0])) == 0 {
		// Before the login check: an unknown command is a usage error, logged in or not.
		fmt.Fprintf(os.Stderr, "error: unknown command %q; run `rowsafe help`\n", args[0])
		return 2
	}
	finish := startJSON(args)
	err := dispatch(ctx, args)
	var exit exitError
	finish(err == nil || errors.As(err, &exit))
	run.done(err)
	if err == nil {
		showTip(ctx, args) // tips.go
		return 0
	}
	if errors.As(err, &exit) {
		return int(exit) // the command already said what happened
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0 // the flag package printed the command's flags
	}
	fmt.Fprintln(os.Stderr, "error:", explain(err))
	var ue usageError
	if errors.As(err, &ue) {
		if topic := helpTopic(args); len(topic) > 0 && len(referenceLines(strings.Join(topic, " "))) > 0 {
			fmt.Fprintf(os.Stderr, "How to use it: rowsafe help %s\n", strings.Join(topic, " "))
		}
		return 2
	}
	return 1
}

// helpRequest reports whether args ask for a command's help (rowsafe cloud
// create --help, rowsafe mark -h) and returns the help topic: the longest
// run of leading words with a reference entry (rowsafe cloud create mydb
// --help is about cloud create). Words after "--" belong to another program
// (rowsafe connect app -- psql --help), and guard --check takes a command.
func helpRequest(args []string) ([]string, bool) {
	help := false
	for i, a := range args {
		if a == "--" || (a == "--check" && i > 0 && args[0] == "guard") {
			break
		}
		if a == "--help" || a == "-help" || a == "-h" {
			help = true
			break
		}
	}
	if !help {
		return nil, false
	}
	return helpTopic(args), true
}

// helpTopic is the longest run of args' leading words with a reference
// entry (rowsafe cloud create mydb is about cloud create).
func helpTopic(args []string) []string {
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		words = append(words, a)
	}
	for n := len(words); n > 1; n-- {
		if len(referenceLines(strings.Join(words[:n], " "))) > 0 {
			return words[:n]
		}
	}
	return words[:min(len(words), 1)]
}

// exitError carries a non-zero exit code for failed tasks.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func dispatch(ctx context.Context, args []string) error {
	cmd, rest := args[0], args[1:]
	// Commands that work without a saved login.
	switch cmd {
	case "version":
		fmt.Println(version)
		return nil
	case "login":
		return login(ctx, rest)
	case "logout":
		return logout(ctx, rest)
	case "tips": // tips.go
		return tipsCmd(rest)
	case "telemetry":
		return telemetryCmd(rest)
	case "whoami":
		return whoami(ctx, rest)
	case "guard":
		return guard(ctx, rest)
	case "add", "use", "databases", "forget": // saved databases (saved.go)
		return savedCmd(ctx, cmd, rest)
	}
	cfg, err := loadConfig()
	// This server's agent (server_saved.go): saved names reach its databases.
	onServer = err == nil && cfg.APIKey == "local"
	// A server saved over SSH (ssh_saved.go): its agent, through ssh.
	if s, args, explicit, ok, serr := sshRoute(cmd, rest, err == nil && !onServer); ok {
		if serr != nil {
			return serr
		}
		return runOverSSH(ctx, s, cmd, args, explicit, cfg)
	}
	// A preview on a database this server backs up runs on a full copy of
	// its data (server_guard.go).
	if cmd == "preview" && onServer && fullCopyPreview(ctx, client.New(cfg.URL, cfg.APIKey), rest) {
		return previewCmd(ctx, client.New(cfg.URL, cfg.APIKey), rest)
	}
	// Directly on a database: a connection string, a saved name, or
	// $DATABASE_URL with no saved login (local.go).
	if run, ok := localCommands[cmd]; ok {
		db, args, isLocal, lerr := localArgs(rest, err == nil && !onServer)
		if lerr != nil {
			return lerr
		}
		if isLocal {
			return run(ctx, db, args)
		}
	}
	if cmd == "schema" || cmd == "explain" { // only without an account (schema.go)
		return localOnly(ctx, cmd, rest)
	}
	if err != nil {
		if errors.Is(err, errNotLoggedIn) {
			if cmd == "ls" {
				return savedList(rest)
			}
			return notLoggedInError()
		}
		return err
	}
	return runCommand(ctx, client.New(cfg.URL, cfg.APIKey), cfg, cmd, rest)
}

// runCommand runs a command that goes to a control plane: the account's,
// this server's agent, or a saved server's over SSH.
func runCommand(ctx context.Context, c *client.Client, cfg config, cmd string, rest []string) error {
	switch cmd {
	// Rowsafe Cloud (cloud.go), and connecting apps and people (env.go, connect.go)
	case "cloud":
		return cloudCmd(ctx, c, rest)
	case "env":
		return envCmd(ctx, c, rest)
	case "connect":
		return connectCmd(ctx, c, rest)
	// Getting started and manual setup
	case "init":
		return initCmd(ctx, c, rest)
	case "restart":
		return restartCmd(ctx, c, rest)
	case "adopt":
		return adoptCmd(ctx, c, rest)
	case "plan":
		return planCmd(ctx, c, rest)
	case "apply":
		return applyCmd(ctx, c, rest)
	case "verify":
		return verifyCmd(ctx, c, rest)
	// Rewind
	case "ls":
		return listCmd(ctx, c, rest)
	case "show":
		return showCmd(ctx, c, rest)
	case "status":
		return statusCmd(ctx, c, rest)
	case "backup":
		return backupCmd(ctx, c, rest)
	case "backups":
		return backupsCmd(ctx, c, rest)
	case "mark":
		return markCmd(ctx, c, rest)
	case "marks":
		return marksCmd(ctx, c, rest)
	case "set":
		return setCmd(ctx, c, rest)
	case "remove":
		return removeCmd(ctx, c, rest)
	case "rewind":
		return rewindCmd(ctx, c, rest)
	case "restore":
		return restoreCmd(ctx, c, rest)
	case "restores":
		return rewindShow(ctx, c, rest)
	case "files":
		return filesCmd(ctx, c, rest) // files.go
	case "migrate": // move in from a managed database (migrate.go)
		return migrateCmd(ctx, c, rest)
	// Updates and upgrades (upgrade.go)
	case "update":
		return updateCmd(ctx, c, rest)
	case "upgrade":
		return upgradeCmd(ctx, c, rest)
	case "fork": // fork.go
		return forkCmd(ctx, c, rest)
	case "forks":
		return forksCmd(ctx, c, rest)
	case "standby":
		return standbyCmd(ctx, c, rest)
	case "move":
		return moveCmd(ctx, c, rest)
	// Proof
	case "proof":
		return proofCmd(ctx, c, rest)
	case "proofs":
		return proofsCmd(ctx, c, rest)
	// Pulse
	case "pulse":
		return pulseCmd(ctx, c, rest)
	case "fix":
		return fixCmd(ctx, c, rest)
	case "insights":
		return insightsCmd(ctx, c, rest)
	case "top":
		return topCmd(ctx, c, rest)
	case "recommendations": // advisor (recommendations.go)
		return recommendationsCmd(ctx, c, rest)
	case "activity":
		return activityCmd(ctx, c, rest)
	case "report":
		return reportCmd(ctx, c, rest)
	case "pooling":
		return poolingCmd(ctx, c, rest)
	case "security": // security.go
		return securityCmd(ctx, c, rest)
	case "security-updates":
		return securityUpdatesCmd(ctx, c, rest)
	case "reboot":
		return rebootCmd(ctx, c, rest)
	case "logs": // logs.go
		return logsCmd(ctx, c, rest)
	case "log-destinations":
		return group(ctx, c, "log-destinations", rest, map[string]subcommand{
			"list": logDestList, "add": logDestAdd, "remove": logDestRemove, "test": logDestTest,
			"on": logDestToggle(true), "off": logDestToggle(false),
		})
	case "storage":
		return storageCmd(ctx, c, rest)
	case "secondcopy", "second-copy": // secondcopy.go
		return secondCopyCmd(ctx, c, rest)
	case "settings": // settings.go
		return settingsCmd(ctx, c, rest)
	case "tune":
		return tuneCmd(ctx, c, rest)
	case "alerts":
		return alertsCmd(ctx, c, rest)
	case "channels":
		return group(ctx, c, "channels", rest, map[string]subcommand{
			"list": channelsList, "add": channelsAdd, "remove": channelsRemove, "test": channelsTest,
		})
	// Guard
	case "mcp":
		return mcpServe(ctx, c, rest)
	case "preview": // copies.go
		return previewCmd(ctx, c, rest)
	case "previews":
		return previewsCmd(ctx, c, rest)
	case "copies":
		return copiesCmd(ctx, c, rest)
	case "masking":
		return maskingCmd(ctx, c, rest)
	// Databases & users
	case "db":
		return dbCmd(ctx, c, rest)
	// Admin
	case "tasks":
		return tasksList(ctx, c, rest)
	case "task":
		return taskShow(ctx, c, rest)
	case "hosts":
		return group(ctx, c, "hosts", rest, map[string]subcommand{
			"list": hostsList, "pin": hostsPin, "unpin": hostsUnpin, "channel": hostsChannel, "remove": hostsRemove,
			"permissions": hostsPermissions, "update": hostsUpdate,
			"enroll-token": func(ctx context.Context, c *client.Client, args []string) error {
				return hostsEnrollToken(ctx, c, cfg, args)
			},
			"add": func(ctx context.Context, c *client.Client, args []string) error {
				return hostsAdd(ctx, c, cfg, args)
			},
		})
	case "api-keys":
		return group(ctx, c, "api-keys", rest, map[string]subcommand{
			"list": apiKeysList, "create": apiKeysCreate, "revoke": apiKeysRevoke,
		})
	case "org":
		return orgShow(ctx, c, rest)
	case "audit":
		return auditList(ctx, c, rest)
	}
	return usageErrorf("unknown command %q; run `rowsafe help`", cmd)
}

// subcommand runs one command of a group such as rowsafe hosts.
type subcommand func(ctx context.Context, c *client.Client, args []string) error

// group runs "rowsafe NAME SUB ...", or lists the group's commands.
func group(ctx context.Context, c *client.Client, name string, args []string, subs map[string]subcommand) error {
	if len(args) > 0 {
		if run, ok := subs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
		return usageErrorf("unknown command %q. The %s commands:\n%s", name+" "+args[0], name, strings.TrimSpace(helpFor([]string{name})))
	}
	return usageErrorf("which one? The %s commands:\n%s", name, strings.TrimSpace(helpFor([]string{name})))
}
