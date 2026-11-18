---
tags: [dependencies, tech-debt]
updated: 2026-11-18
---
# Known Issues / Tech Debt

## Dependencies
- None known. NuGet Audit runs with no exceptions.

## Code
- `JwtServiceValidationHandler` extends the legacy `JwtSecurityTokenHandler` and blocks on `Task.WaitAll(jwtService.GetLastKeys())`. Better: a `JsonWebTokenHandler` + async `IssuerSigningKeyResolver`, or set the keys in `OnMessageReceived`.
- Some tests use the obsolete sync `JsonWebTokenHandler.ValidateToken` (CS0618). Migrate them to `ValidateTokenAsync`.
- Many nullable warnings (CS86xx) and missing XML docs (CS1591) on public APIs (about 450 warnings in a clean build).
- `IJsonWebKeySetService` is `[Obsolete]`. Remove it in the next major.
- Model file names are swapped: `Model/Key.cs` holds `KeyMaterial`, `Model/KeyMaterial.cs` holds `CryptographicKey`.
- The `DataProtectionStore` fallback exception message still mentions the old `JwtSigningCredentials` package names.

## Resolved
- 2026-11-18: removed `NetDevPack.Security.Jwt.IdentityServer4` and `samples/3_IdentityServer4` ([[ADR-006-drop-identityserver4]]). IdentityServer4 4.1.2 (EOL, GHSA-55p7-v223-x366, GHSA-ff4q-64jc-gx98) is no longer a dependency, so the `NU1902` suppression and the CI exception are gone.
- 2026-11-17: dropped net8.0/net9.0 ([[ADR-005-net10-only]]). Migrated xunit 2 → **xunit.v3** on Microsoft.Testing.Platform; `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio` and `coverlet.collector` removed. Fixed the xUnit1051 warnings in `AspNetCoreTests`.
- 2026-10-01: migrated FluentAssertions 8.11 (Xceed commercial license) → **AwesomeAssertions 9.6** (Apache-2.0 fork, same API, namespace `AwesomeAssertions`). Do not reintroduce FluentAssertions.
- 2026-10-01: 6 `.cs` files in UTF-16 LE (`CryptoService`, `IdentityServer4KeyStore`, `IdentityServerBuilderKeysExtensions`, `EFCoreServiceExtensions`, `ISecurityKeyContext`, `KeyMaterialMap`) were converted to UTF-8 BOM + CRLF. `.editorconfig` now enforces the encoding.

## Tests
- A flaky test in `NetDevPack.Security.Jwt.Tests` on net10 failed 1 of 4 local runs on net10 (2026-10-01). It is probably a race in a store test that shares the filesystem/DataProtection folder. Not investigated yet.
- The local machine may not have the .NET 8 runtime. CI installs 8/9/10.
