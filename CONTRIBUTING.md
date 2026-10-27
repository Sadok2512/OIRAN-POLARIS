# Contributing

## Branches

- `chore/*` — repository foundation and maintenance
- `feat/backend-*` — backend work, normally owned by Codex
- `feat/frontend-*` — frontend work, normally owned by Claude Code
- `fix/*` — focused corrections
- `release/*` — release preparation

Create a focused branch from the latest intended base. Do not push feature work
directly to `main`.

## Pull requests

Every integration uses a pull request. A pull request must:

1. Name the affected application, service, package, or contract.
2. Describe the responsibility changed and the contracts affected.
3. Include targeted tests and contract tests when implementation exists.
4. Avoid unrelated formatting, generated artifacts, captures, datasets, or secrets.
5. State deployment impact and rollback scope.

Do not merge another agent's pull request. Resolve overlapping work by coordinating
branches and reviewing the remote state before pushing.

## Scope

Keep application responsibilities separate. Shared types belong in versioned
contract packages; application-specific business logic remains in its owner.
The Portal must remain a launcher and must not absorb backend or domain logic.

## Security

Never commit credentials, tokens, private keys, production configuration, runtime
registries, packet captures, raw datasets, database dumps, or backups. Inspect the
staged diff and run the repository security checks before every commit.
