---
tags: [architecture, storage]
updated: 2026-10-01
---
# Stores (`IJsonWebKeyStore`)

Contract (`Interfaces/IJsonWebKeyStore.cs`): `Store`, `GetCurrent(type)`, `Revoke(key, reason)`, `GetLastKeys(qty, type?)`, `Get(keyId)`, `Clear()`.

| Store | Registration | Persistence | Notes |
| --- | --- | --- | --- |
| `DataProtectionStore` (default, internal) | `AddJwksManager()` | ASP.NET DataProtection `IXmlRepository` (same place as cookie keys) | Payload protected with `IDataProtector`. Revocation is a separate XML element because `IXmlRepository` can't update. If no repository can be found, it falls back to Azure WebSites → default folder → Windows registry, then throws |
| `InMemoryStore` | `.PersistKeysInMemory()` | Process memory | Tests/dev only |
| `FileSystemStore` | `.PersistKeysToFileSystem(dir)` | JSON files in a folder | Needs `IMemoryCache` |
| `DatabaseJsonWebKeyStore<TContext>` | `.PersistKeysToDatabaseStore<TContext>()` | EF Core, `TContext : DbContext, ISecurityKeyContext` (`DbSet<KeyMaterial> SecurityKeys`) | Mapping in `KeyMaterialMap.cs`; uses `AsNoTrackingWithIdentityResolution` |

All stores cache the current key and the JWKS list in `IMemoryCache` (`JwkContants` cache keys), and clear the cache on `Store`/`Revoke`.

**Load-balanced deployments** need a shared store (DB or a shared DataProtection repository). Otherwise each instance generates its own key. See [[Key-Lifecycle]].

Tests: `tests/NetDevPack.Security.Jwt.Tests/StoreTests/GenericStoreServiceTest.cs` runs the same suite against every store through `Warmups/*`. **A new store must get a warmup + test class.**
