---
tags: [workflow, release]
updated: 2026-10-01
---
# Release

- Every push to `master` runs `.github/workflows/publish.yml`: build → test → **semantic-release** (v24, `.releaserc`) → when a release is published, `dotnet pack -p:PackageVersion=<new>` → push to nuget.org (`NUGET_AUTH_TOKEN`).
- semantic-release computes the version from **Conventional Commits** since the last tag (`v9.0.4` → the next breaking change gives `v10.0.0`). It updates `CHANGELOG.md`, so **don't edit the changelog by hand**.
- `Version` in `src/Directory.Build.props` is only the local/default version. CI overrides it with `PackageVersion`. Keep it aligned with the next major.

## Commit messages
There is **no local git hook**: it was removed on 2026-10-01. Following the convention is up to the author and reviewer, because semantic-release only understands Conventional Commits.
- `feat` → minor, `fix` → patch. `chore | ci | docs | test | style | refactor` don't trigger a release
- Use `chore(deps)` for dependency bumps, with an optional scope, and keep the first line short
- Breaking: `feat!: ...` + footer `BREAKING CHANGE: ...` → major
