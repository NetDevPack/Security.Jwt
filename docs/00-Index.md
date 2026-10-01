---
tags: [moc, index]
updated: 2026-10-01
---
# NetDevPack.Security.Jwt — Knowledge Base

Entry point of this vault, for maintainers and AI agents (Claude Code reads `CLAUDE.md` at the repo root, which points here).
Open the `docs/` folder as an Obsidian vault, or just read the Markdown on GitHub.

## Start here
- [[Agent-Playbook]]: rules, where to change things, how to validate. **Read this first if you are an agent.**
- [[Build-Test]]: exact commands
- [[Release]]: how versions and NuGet packages are produced

## Architecture
- [[Overview]]: packages, layers and main flow
- [[Key-Lifecycle]]: generation, rotation, revocation
- [[Stores]]: where keys live (DataProtection, InMemory, FileSystem, EF Core)
- [[AspNetCore-Integration]]: `/jwks` endpoint and `JwtBearer` validation
- [[Algorithms]]: JWS/JWE algorithms and defaults
- [[Samples]]

## Dependencies
- [[Policy]]: Central Package Management, per-TFM versions, how to update
- [[Known-Issues]]: tech debt and pending migrations

## Decisions (ADRs)
- [[ADR-001-drop-netstandard21]]
- [[ADR-002-identityserver4-deprecated]]
- [[ADR-003-central-package-management]]
- [[ADR-004-remove-legacy-asymmetric-sample]]
