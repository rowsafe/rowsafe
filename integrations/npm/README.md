# rowsafe

The [Rowsafe](https://rowsafe.sh) CLI on npm, for macOS, Linux and Windows (x86-64 and ARM64).

```sh
npx rowsafe pulse postgres://user:pass@host:5432/app   # health check, no account needed
npm install -g rowsafe                                  # or keep it installed
```

Without an account, `rowsafe` works on a connection string (or `DATABASE_URL`): `pulse`, `insights`, `top`, `activity`, `settings`, `tune` and `mcp`, plus `fix` on macOS and Linux. See `rowsafe help local`. With an account (`rowsafe login`), it also sets restore points (`rowsafe mark`), checks backups and runs everything in the [CLI reference](https://rowsafe.sh/docs/reference/cli).

For AI agents, as an MCP server:

```json
{ "mcpServers": { "rowsafe": { "command": "npx", "args": ["-y", "rowsafe", "mcp", "postgres://user:pass@host:5432/app"] } } }
```

## How it works

Nothing runs when you install. The first time you run `rowsafe`, it downloads the CLI for your computer from the [GitHub release](https://github.com/rowsafe/rowsafe/releases) of the same version as this package, checks it against the release's `SHA256SUMS` (included in this package), and keeps it in your cache folder (`~/Library/Caches/rowsafe`, `~/.cache/rowsafe` or `%LOCALAPPDATA%\rowsafe\cache`). Later runs start it from there. Download messages go to stderr, so `--json` output and `rowsafe mcp` stay clean.

| Variable | |
|---|---|
| `ROWSAFE_VERSION` | run another release, such as `0.10.18` |
| `ROWSAFE_CACHE_DIR` | keep the CLI in this folder |

Without Node.js: `curl -fsSL https://rowsafe.sh/cli | sh` (macOS and Linux), or download `rowsafe-windows-amd64.exe` from the release.

License: Apache-2.0.
