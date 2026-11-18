---
tags: [dependencies, policy]
updated: 2026-11-18
---
# Dependency Policy

## Where versions live
- **`Directory.Packages.props`** (repo root) — Central Package Management (CPM). csproj files only have `<PackageReference Include="X" />`. **Never add `Version=` in a csproj.**
- `Microsoft.*` / `System.*` packages that ship with .NET follow the target framework: net10 → **10.0.x**. Never move them to 11.x while the TFM is net10.0.
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
1. Bump only **patch** versions of the .NET packages (`10.0.x`).
2. Bump TFM-independent packages freely, but read the release notes for majors.
3. `dotnet build -c Release` + `dotnet test -c Release` (see [[Build-Test]]).
4. Commit as `chore(deps): ...` (see [[Release]]).

Dependabot (`.github/dependabot.yml`) runs weekly and ignores majors for `Microsoft.*`.

## Adding a new TFM (e.g. net11.0)
1. `src/Directory.Build.props` `TargetFramework` → `TargetFrameworks` + every test/sample csproj.
2. Move the .NET packages in `Directory.Packages.props` into per-TFM `ItemGroup Condition="'$(TargetFramework)' == 'net10.0'"` groups (10.0.x / 11.0.x).
3. Make sure the SDK in `global.json` can build every TFM (CI reads it through `setup-dotnet` `global-json-file`).
4. Write an ADR in `Decisions/`.

Snapshot of the 2026-10-01 update: [[Known-Issues]].
