---
tags: [adr]
status: accepted
date: 2026-10-01
---
# ADR-003 — Central Package Management

**Context.** Every csproj repeated per-TFM `ItemGroup`s with hardcoded versions. Versions drifted (10.0.2 vs 9.0.12 vs 8.0.23 across projects), and there were dead net6/net7 groups and duplicated package metadata. That made dependency updates error-prone.

**Decision.** Use `Directory.Packages.props` (CPM + transitive pinning) and `Directory.Build.props` (root and `src/`). One `Version` for all packages lives in `src/Directory.Build.props`. NuGet Audit turns vulnerabilities into build errors.

**Consequences.** One file to update. A vulnerable transitive dependency fails the restore, which is intended. See [[Policy]].
