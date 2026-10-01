---
tags: [architecture]
updated: 2026-10-01
---
# Overview

Library that **generates, stores, rotates and publishes** the keys used to sign (JWS) and encrypt (JWE) JWTs, so apps don't hardcode symmetric secrets. See [[Key-Lifecycle]].

## Packages (all `net8.0;net9.0;net10.0`)

| Project (`src/`) | NuGet id | Role |
| --- | --- | --- |
| `NetDevPack.Security.Jwt.Core` | `NetDevPack.Security.Jwt` | `IJwtService`, `JwtOptions`, `Algorithm`, default stores (DataProtection, InMemory) |
| `NetDevPack.Security.Jwt.AspNetCore` | `NetDevPack.Security.Jwt.AspNetCore` | `UseJwksDiscovery()` endpoint + `UseJwtValidation()` — see [[AspNetCore-Integration]] |
| `NetDevPack.Security.Jwt.Store.EntityFrameworkCore` | same | `PersistKeysToDatabaseStore<TContext>()` — see [[Stores]] |
| `NetDevPack.Security.Jwt.Store.FileSystem` | same | `PersistKeysToFileSystem(DirectoryInfo)` |
| `NetDevPack.Security.Jwt.IdentityServer4` | same | **Deprecated**, see [[ADR-002-identityserver4-deprecated]] |

Note: the Core *project* name differs from its *package id* (`NetDevPack.Security.Jwt`).

## Main flow

```
AddJwksManager(options)            // JsonWebKeySetManagerDependencyInjection.cs
  ├─ IJwtService  -> JwtService (scoped, internal)     // Jwt/JwtService.cs
  └─ IJsonWebKeyStore -> DataProtectionStore (default) // DefaultStore/DataProtectionStore.cs
        replaced by .PersistKeysInMemory() / .PersistKeysToFileSystem() / .PersistKeysToDatabaseStore<T>()

JwtService.GetCurrentSigningCredentials()
  └─ GetCurrentSecurityKey(Jws)
       ├─ store.GetCurrent()   (memory-cached, JwtOptions.CacheTime)
       ├─ null / expired / revoked → store.Revoke(old) + GenerateKey()
       └─ key type (kty) differs from options → GenerateKey()
  └─ new SigningCredentials(key, options.Jws)
```

- `IJwksBuilder` (`Interfaces/IJwksBuilder.cs`) is the fluent builder every extension hangs off.
- Extension methods live in the `Microsoft.Extensions.DependencyInjection` namespace on purpose (discoverability).
- Key model: `KeyMaterial` (`Model/Key.cs`) is persisted. `CryptographicKey` (`Model/KeyMaterial.cs`) builds a new key from an `Algorithm`. Yes, the file names are swapped.

Related: [[Algorithms]], [[Stores]], [[Known-Issues]].
