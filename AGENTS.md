# NetDevPack.Security.Jwt

.NET library (NuGet) that generates, rotates, stores and publishes (JWKS) JWT signing/encryption keys. Targets net8.0/net9.0/net10.0.

**Knowledge base:** `docs/` is an Obsidian vault. Start at `docs/00-Index.md`, then read `docs/Workflows/Agent-Playbook.md` before making changes.

## Commands (run from `src/`)
```bash
dotnet restore && dotnet build -c Release
dotnet test -c Release            # add -f net10.0 for a single TFM
dotnet list NetDevPack.Security.Jwt.sln package --vulnerable --include-transitive
```

## Rules
- Package versions only in `Directory.Packages.props` (Central Package Management). Never add `Version=` to a csproj. Microsoft.* packages are versioned per TFM (8.0.x / 9.0.x / 10.0.x). See `docs/Dependencies/Policy.md`.
- NuGet Audit warnings NU1901-NU1904 are build errors. IdentityServer4 is the only deliberate exception (deprecated, ADR-002).
- Commits: Conventional Commits (no local hook enforces it; semantic-release reads the messages). Use `chore(deps)` for dependency bumps. Breaking change = `feat!:` + `BREAKING CHANGE:` footer. semantic-release owns `CHANGELOG.md` and versions.
- Public API in `src/` is a NuGet contract. Treat changes to it as breaking.
- Encoding: UTF-8 with BOM + CRLF for C#/MSBuild files (enforced by `.editorconfig`). Never save files as UTF-16.
- When behaviour, architecture or decisions change, update the matching vault note (and add an ADR in `docs/Decisions/` for non-obvious decisions).
