---
tags: [dependencies, policy]
updated: 2026-10-01
---
# Dependency Policy

## Where versions live
- **`Directory.Packages.props`** (repo root) — Central Package Management (CPM). csproj files only have `<PackageReference Include="X" />`. **Never add `Version=` in a csproj.**
- `Microsoft.*` / `System.*` packages that ship with .NET are versioned **per TFM** (`ItemGroup Condition="'$(TargetFramework)' == 'net8.0'"`): net8 → 8.0.x, net9 → 9.0.x, net10 → 10.0.x. Never put a 10.x package in the net8 group.
- TFM-independent packages (IdentityModel, Swashbuckle, test libs) are in the unconditional group.
- `CentralPackageTransitivePinningEnabled=true`: a `PackageVersion` also pins the **transitive** version. Used for `System.Security.Cryptography.Xml`, which comes in through DataProtection. It ends up as a direct dependency of the Core nuspec, so consumers get the patched version too.
- `Directory.Build.props` (root): `LangVersion`, NuGet Audit (`NU1901-NU1904` = **errors**).
- `src/Directory.Build.props`: TFMs, package metadata, `Version` for all packable projects.

## Updating
```bash
cd src
dotnet list NetDevPack.Security.Jwt.sln package --outdated
dotnet list NetDevPack.Security.Jwt.sln package --vulnerable --include-transitive
```
1. Bump only **patch** versions inside each TFM line (`8.0.x`, `9.0.x`, `10.0.x`).
2. Bump TFM-independent packages freely, but read the release notes for majors.
3. `dotnet build -c Release` + `dotnet test -c Release` (see [[Build-Test]]).
4. Commit as `chore(deps): ...` (see [[Release]]).

Dependabot (`.github/dependabot.yml`) runs weekly and ignores majors for `Microsoft.*` and also ignores `IdentityServer4`. Dependabot handles the per-TFM groups poorly. If a PR changes the wrong TFM line, fix it by hand.

## Adding a new TFM (e.g. net11.0)
1. `src/Directory.Build.props` `TargetFrameworks` + every test/sample csproj.
2. Add a `net11.0` `ItemGroup` in `Directory.Packages.props` mirroring the others.
3. Add `11.0.x` to `actions/setup-dotnet` in both workflows.
4. Write an ADR in `Decisions/`.

Snapshot of the 2026-10-01 update: [[Known-Issues]].
