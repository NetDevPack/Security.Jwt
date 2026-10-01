---
tags: [samples]
updated: 2026-10-01
---
# Samples (`samples/`)

All samples are in `src/NetDevPack.Security.Jwt.sln`, target net8/9/10 and use project references (except `Api.Sample`).

| Sample | Shows |
| --- | --- |
| `1_AspNet.Default` | Minimal API: generate/validate JWS & JWE, `[Authorize]` endpoint. **Also the host for `AspNetCoreTests`.** Changing it can break tests |
| `2_AspNet.Store.EntityFramework` | Same, with `PersistKeysToDatabaseStore<DbExample>()` (SQLite/SQL Server) |
| `3_IdentityServer4` | Deprecated IdS4 integration ([[ADR-002-identityserver4-deprecated]]) |
| `Microservice.Sample/Identity` | Token issuer exposing `/jwks` (EF Core store) |
| `Microservice.Sample/Api.Sample` | Client API validating via NuGet `NetDevPack.Security.JwtExtensions` |

The old `Server.AsymmetricKey` sample was removed, see [[ADR-004-remove-legacy-asymmetric-sample]].
