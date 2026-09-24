# Rowsafe Mark: a restore point before every deploy

Save a **Mark** of your PostgreSQL right before each deploy. If a migration drops the wrong column or a backfill goes wrong, you can [rewind](https://rowsafe.sh/docs/guides/restore) the database to the moment just before the deploy.

[Rowsafe](https://rowsafe.sh) runs backups to your own bucket, restore to any second (Rewind), a weekly restore test (Proof) and monitoring (Pulse) for the PostgreSQL you run on your own servers. This action is part of **Guard**, the safety net for changes made by CI and AI agents.

```yaml
- uses: rowsafe/action@v1
  with:
    api-key: ${{ secrets.ROWSAFE_API_KEY }}
    database: app

- run: npx prisma migrate deploy # or rails db:migrate, manage.py migrate, ...
```

Before the next step runs, the action:

1. **Checks that the database can be restored right now**: backups, WAL archiving and the latest restore test are OK. If not, it warns, or stops the deploy with `require-protected: true`.
2. **Previews the migration on a copy** (optional, `preview-sql`): the new migration files run on a restored copy next to production, never on production, and you get a verdict: safe, careful, dangerous, or failed. A migration that fails on the copy stops the job; careful and dangerous warn, or stop it with `fail-on`.
3. **Saves the Mark** `before-deploy-<commit>` and waits until it is confirmed in your storage, usually in a few seconds.
4. **Writes a job summary** with the Mark, the preview report, the backup a rewind starts from and a Rewind link.

## Set it up

1. In the Rowsafe dashboard, create a read-write API key (Settings > API keys), or run `rowsafe api-keys create deploy-ci`.
2. Save it in your repository as the secret `ROWSAFE_API_KEY` (Settings > Secrets and variables > Actions).
3. Add the step right before your migrations. The database name is the one in the dashboard; leave `database` out when your repository has a `.rowsafe.json` (`rowsafe init app`) or your organization has a single database.

Complete workflows: [Prisma](examples/prisma.yml), [Rails](examples/rails.yml), [Django](examples/django.yml), [Laravel](examples/laravel.yml), [Drizzle](examples/drizzle.yml), [Flyway](examples/flyway.yml).

## Inputs

| Input | Default | What it does |
|---|---|---|
| `api-key` | (required) | A read-write Rowsafe API key. Use a secret. |
| `database` | from `.rowsafe.json`, or the only database | The Rowsafe database to mark. |
| `label` | `before-deploy-<short SHA>` | The Mark's name. Lowercased; other characters become dashes. A re-run of the same commit gets `-2`, `-3`, ... |
| `wait` | `true` | Wait until the Mark is confirmed in your storage. `false` only requests it. |
| `require-protected` | `false` | Stop the deploy when the database can't be restored right now, instead of warning. |
| `preview-sql` | | Glob patterns of migration SQL files (`**` works) to preview on a copy first. |
| `fail-on` | `never` | Stop the deploy when the preview's verdict is at least `careful` or `dangerous`, instead of warning. |

### More options

| Input | Default | What it does |
|---|---|---|
| `preview-changed-only` | `true` | Preview only the files this push or pull request adds or changes. Needs `actions/checkout` with `fetch-depth: 0`, or the action fetches the base commit itself. |
| `wait-timeout-minutes` | `10` | Give up waiting for the Mark or the preview after this long. |
| `working-directory` | `.` | Where `.rowsafe.json` and `preview-sql` are looked up (monorepos). |
| `version` | `latest` | The rowsafe CLI version, e.g. `0.4.0`. |
| `verify-provenance` | `auto` | Check the CLI's build provenance before running it: `auto` (when the GitHub CLI is available, as on GitHub-hosted runners), `true` or `false`. |
| `api-url` | `https://api.rowsafe.sh` | The Rowsafe API. |
| `cli-path` | | Use this `rowsafe` binary instead of downloading one. |
| `github-token` | `github.token` | Used only to look up the CLI's build attestations. |

## Outputs

| Output | Example |
|---|---|
| `mark` | `before-deploy-3f2a1c9` |
| `restore-from-backup` | `20260924-020000F`: the backup a rewind to this Mark starts from |
| `dashboard-url` | `https://app.rowsafe.sh/databases/app/restore-points`: rewind from here |
| `database` | `app` |
| `protected` | `true` or `false` |
| `preview-verdict` | `safe`, `careful`, `dangerous` or `failed`, when a preview ran |

## If the deploy goes wrong

Open the link in the job summary (Marks in the dashboard) and rewind to the Mark: restore a copy of the database as it was at the Mark next to production, compare, and bring back the rows you lost, or rewind the whole database. Nothing is restored automatically. From a terminal:

```sh
rowsafe rewind copy app --mark before-deploy-3f2a1c9
rowsafe rewind compare app
```

## Security

- **The CLI is verified before it runs.** It is downloaded from the [rowsafe/rowsafe release](https://github.com/rowsafe/rowsafe/releases), checked against the release's `SHA256SUMS`, and its [SLSA build provenance](https://github.com/rowsafe/rowsafe/blob/main/docs/verifying-releases.md) is verified with `gh attestation verify`: GitHub Actions built exactly this file from rowsafe/rowsafe with the release workflow at that version's tag. A cached copy is checked again on every run.
- **Rowsafe never sees your data.** A Mark is a PostgreSQL restore point written by the Rowsafe agent on your server; no connection string or database password goes to the action. The preview runs on a copy on your server.
- **The API key stays a secret.** It's passed to the CLI in the environment and masked in logs. It can save Marks, so keep it in a secret, scoped to the deploy environment if you can.
- Pull requests from forks don't get secrets, so run the action on pushes to your deploy branch (or in a protected environment), not on `pull_request` from forks.

## Limits

- Linux and macOS runners, x64 and ARM64.
- A Mark lets you go back to the moment before the deploy; it doesn't undo the deploy by itself. Writes made after the Mark (by your app, after the deploy) are also rolled back by a rewind of the whole database; a rewind to a copy lets you pick what to bring back.
- The migration preview needs a version of the rowsafe CLI that has `rowsafe preview`; with an older one the action skips the preview and says so.
- Don't want a Rowsafe outage to block deploys? Add `continue-on-error: true` to the step.

## GitLab CI, Bitbucket and others

The action runs the `rowsafe` CLI, which works in any CI. See [Save a Mark before every deploy](https://rowsafe.sh/docs/guides/deploys).

## License

Apache-2.0. Developed in [rowsafe/rowsafe](https://github.com/rowsafe/rowsafe/tree/main/integrations/github-action); issues and changes go there.
