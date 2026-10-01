---
tags: [dependencies, tech-debt]
updated: 2026-10-01
---
# Known Issues / Tech Debt

## Dependencies
- **IdentityServer4 4.1.2**: EOL, moderate vulnerabilities (GHSA-55p7-v223-x366, GHSA-ff4q-64jc-gx98). `NU1902` is suppressed only in `NetDevPack.Security.Jwt.IdentityServer4` and `samples/3_IdentityServer4`. See [[ADR-002-identityserver4-deprecated]].
- **xunit v2** (2.9.3) is still in use. v3 (`xunit.v3`) is a separate migration: new package, `OutputType=Exe`, API changes. `xunit.runner.visualstudio` 3.x already supports both.
- `Microsoft.NET.Test.Sdk` 18.x.

## Code
- `JwtServiceValidationHandler` extends the legacy `JwtSecurityTokenHandler` and blocks on `Task.WaitAll(jwtService.GetLastKeys())`. Better: a `JsonWebTokenHandler` + async `IssuerSigningKeyResolver`, or set the keys in `OnMessageReceived`.
- Some tests use the obsolete sync `JsonWebTokenHandler.ValidateToken` (CS0618). Migrate them to `ValidateTokenAsync`.
- Many nullable warnings (CS86xx) and missing XML docs (CS1591) on public APIs (about 700 warnings in a clean build).
- `IJsonWebKeySetService` is `[Obsolete]`. Remove it in the next major.
- Model file names are swapped: `Model/Key.cs` holds `KeyMaterial`, `Model/KeyMaterial.cs` holds `CryptographicKey`.
- The `DataProtectionStore` fallback exception message still mentions the old `JwtSigningCredentials` package names.

## Resolved
- 2026-10-01: migrated FluentAssertions 8.11 (Xceed commercial license) → **AwesomeAssertions 9.6** (Apache-2.0 fork, same API, namespace `AwesomeAssertions`). Do not reintroduce FluentAssertions.
- 2026-10-01: 6 `.cs` files in UTF-16 LE (`CryptoService`, `IdentityServer4KeyStore`, `IdentityServerBuilderKeysExtensions`, `EFCoreServiceExtensions`, `ISecurityKeyContext`, `KeyMaterialMap`) were converted to UTF-8 BOM + CRLF. `.editorconfig` now enforces the encoding.

## Tests
- A flaky test in `NetDevPack.Security.Jwt.Tests` on net10 failed 1 of 4 local runs (2026-10-01). It is probably a race in a store test that shares the filesystem/DataProtection folder. Not investigated yet.
- The local machine may not have the .NET 8 runtime. CI installs 8/9/10.
