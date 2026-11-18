---
tags: [workflow]
updated: 2026-11-18
---
# Build & Test

Prerequisites: .NET **10 SDK** (pinned by `global.json`). Tests use **xunit.v3 on Microsoft.Testing.Platform** (MTP), enabled in `global.json`.

```bash
cd src
dotnet restore                       # fails on NU1901-NU1904 (vulnerabilities)
dotnet build -c Release
dotnet test -c Release
dotnet test --project ../tests/NetDevPack.Security.Jwt.Tests -c Release --filter-class "*FileSystemStore*"
dotnet list NetDevPack.Security.Jwt.sln package --vulnerable --include-transitive
dotnet pack -c Release -o ./out      # 5 .nupkg + .snupkg, lib/net10.0
```

- Solution: `src/NetDevPack.Security.Jwt.sln` (src + tests + samples).
- Test projects: `NetDevPack.Security.Jwt.Tests` (about 514 tests) and `NetDevPack.Security.Jwt.AspNetCoreTests`.
- A test can be flaky, see [[Known-Issues]].

CI: `.github/workflows/pull-request.yml` runs restore, build, test and the vulnerability check (no accepted advisories, see [[ADR-006-drop-identityserver4]]).
