# Agent workflow

## Before work

1. Fetch all remote branches and inspect recent commits.
2. Confirm the intended base and check for overlapping agent work.
3. Create an isolated branch using the repository convention.
4. Keep credentials outside the repository.

## During work

- Codex backend branches use `feat/backend-*`.
- Claude Code frontend branches use `feat/frontend-*`.
- Keep changes inside the owning module unless a contract change is explicit.
- Update versioned contracts before changing consumers.
- Add targeted tests and contract compatibility tests with implementation.
- Never change production services from a development branch.

## Integration

1. Fetch again before pushing.
2. Review the staged diff for secrets, captures, datasets, dumps, and backups.
3. Push the topic branch without force.
4. Open a pull request with test and deployment scope.
5. Do not merge another agent's pull request.

If concurrent changes overlap, stop and coordinate rather than resetting or
overwriting remote work.
