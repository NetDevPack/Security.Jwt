---
tags: [adr]
status: accepted
date: 2026-10-01
---
# ADR-004 — Remove legacy `samples/Server.AsymmetricKey`

**Context.** A `netcoreapp3.1` sample (Identity API + API + MVC) built on the old `NetDevPack.Security.JwtSigningCredentials.*` packages. It was outside the solution, was never built in CI, and its dependencies were vulnerable.

**Decision.** Removed (maintainer decision, 2026-10-01). `samples/Microservice.Sample` covers the same scenario (issuer + `/jwks` + client API) with current packages.

Related: [[Samples]].
