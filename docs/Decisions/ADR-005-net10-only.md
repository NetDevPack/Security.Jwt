---
tags: [adr]
status: accepted
date: 2026-11-17
---
# ADR-005 — Target net10.0 only

**Context.** .NET 8 (LTS) and .NET 9 (STS) reached end of support on 2026-11-10. They no longer get servicing updates, so a new advisory on an `8.0.x`/`9.0.x` package could never be fixed. Because NuGet Audit fails the build ([[Policy]]), that would block every release. Keeping them also meant three versions of each `Microsoft.*` package in `Directory.Packages.props` and three test runs in CI.

**Decision.** All packages, tests and samples target `net10.0` (current LTS, supported until 2028-11). `Directory.Packages.props` has a single version line for packages that ship with .NET (`10.0.x`). The same move was applied to all NetDevPack repos in this round.

**Consequences.**
- Breaking change, shipped as **v11.0.0**. Consumers on .NET 8/9 stay on v10.x.
- CI installs only the SDK from `global.json`. Tests run once.
- Tests moved to `xunit.v3` on Microsoft.Testing.Platform. `global.json` opts in with `"test": { "runner": "Microsoft.Testing.Platform" }`, and `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio` and `coverlet.collector` were removed.

Related: [[ADR-001-drop-netstandard21]], [[Known-Issues]].
