# Contributing

Thanks for helping make Rowsafe better.

- **Bugs and ideas:** open an issue. For anything security-related, use [private reporting](https://github.com/rowsafe/rowsafe/security/advisories/new) instead.
- **Pull requests:** welcome. Small, focused changes with tests are easiest to review. Run `make lint test` first.
- **Documentation** lives in [rowsafe/docs](https://github.com/rowsafe/docs).

The agent runs with access to people's databases, so changes to `internal/agent`, the installer and release verification get extra review. Behaviour that touches production (anything that writes to a database, restarts services or deletes files) needs a test that proves the safe path.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
