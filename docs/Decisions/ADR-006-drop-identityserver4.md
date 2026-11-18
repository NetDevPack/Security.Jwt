---
tags: [adr]
status: accepted
date: 2026-11-18
---
# ADR-006 — Stop publishing the IdentityServer4 package

**Context.** [[ADR-002-identityserver4-deprecated]] kept `NetDevPack.Security.Jwt.IdentityServer4` building and publishing for backward compatibility. Since [[ADR-005-net10-only]] every package targets .NET 10. IdentityServer4 4.1.2 was built for .NET Core 3.1, has been EOL since 2022 and has advisories that will never be fixed (GHSA-55p7-v223-x366, GHSA-ff4q-64jc-gx98). Keeping it meant the only `NU1902` suppression in the repo, an exception in the CI vulnerability check and a Dependabot ignore rule. It also kept shipping a new version of a package nobody should adopt.

**Decision.**
- Remove `src/NetDevPack.Security.Jwt.IdentityServer4` and `samples/3_IdentityServer4` from the repo and the solution. **11.0.0 is the last version.**
- Mark every version of the package as **deprecated** on nuget.org (reason: legacy, has critical bugs). Point users to `NetDevPack.Security.Jwt.AspNetCore` plus Duende IdentityServer or OpenIddict.
- NuGet Audit and the CI vulnerability check now run with no exceptions.

**Consequences.**
- Existing consumers keep working on ≤ 11.0.0, and NuGet shows them the deprecation warning.
- Not a breaking change for the other packages: the public API of `NetDevPack.Security.Jwt*` doesn't change, so this ships with no release (`chore:`).
- An integration for a maintained server (OpenIddict) can be a new package in the future.

Related: [[Known-Issues]], [[Policy]].
