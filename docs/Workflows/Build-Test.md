---
tags: [workflow]
updated: 2026-10-01
---
# Build & Test

Prerequisites: .NET **10 SDK** plus the .NET 8 and 9 runtimes (tests run on every TFM).

```bash
cd src
dotnet restore                       # fails on NU1901-NU1904 (vulnerabilities)
dotnet build -c Release
dotnet test -c Release               # all TFMs
dotnet test -c Release -f net10.0    # one TFM
dotnet test ../tests/NetDevPack.Security.Jwt.Tests -c Release -f net10.0 --filter "FullyQualifiedName~FileSystemStore"
dotnet list NetDevPack.Security.Jwt.sln package --vulnerable --include-transitive
dotnet pack -c Release -o ./out      # 5 .nupkg + .snupkg, lib/net8.0|net9.0|net10.0
```

- Solution: `src/NetDevPack.Security.Jwt.sln` (src + tests + samples).
- Test projects: `NetDevPack.Security.Jwt.Tests` (about 514 tests per TFM) and `NetDevPack.Security.Jwt.AspNetCoreTests`.
- A test can be flaky on net10, see [[Known-Issues]].

CI: `.github/workflows/pull-request.yml` runs restore, build, test and the vulnerability check on .NET 8/9/10.
