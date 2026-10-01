---
tags: [agent, workflow]
updated: 2026-10-01
---
# Agent Playbook

Checklist for an AI agent (or a new maintainer) working in this repo.

## Before changing anything
1. Read [[Overview]] and the note for the area you're touching ([[Stores]], [[AspNetCore-Integration]], [[Algorithms]], [[Key-Lifecycle]]).
2. Check [[Known-Issues]]. The problem may already be known.

## Rules
- **Dependencies**: only via `Directory.Packages.props`, following [[Policy]]. Never put `Version=` in a csproj. Keep Microsoft packages on their TFM line.
- **Public API** = NuGet contract. Changing or removing a public type or member in `src/` is a breaking change: use `feat!` + `BREAKING CHANGE:` and write an ADR.
- **Security**: never log or return private key material. `/jwks` must expose public keys only. Revoked keys must keep only public parameters.
- New store → implement `IJsonWebKeyStore`, add a builder extension in the `Microsoft.Extensions.DependencyInjection` namespace, and add a `Warmup` + a test class that inherits `GenericStoreServiceTest`.
- `samples/1_AspNet.Default` is the test host for `AspNetCoreTests`.
- Encoding: UTF-8 with BOM + CRLF for `.cs`/`.csproj`/`.props` (`.editorconfig`). Never save as UTF-16.
- Commits: Conventional Commits with a short first line; nothing enforces it locally ([[Release]]).

## Validate
```bash
cd src && dotnet build -c Release && dotnet test -c Release
dotnet list NetDevPack.Security.Jwt.sln package --vulnerable --include-transitive
```

## Keep this vault alive
- Behaviour or architecture changed → update the matching note and its `updated:` date.
- Non-obvious decision → new `Decisions/ADR-NNN-*.md` with a link from [[00-Index]].
- New tech debt found → [[Known-Issues]].
