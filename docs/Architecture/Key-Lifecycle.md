---
tags: [architecture, security]
updated: 2026-10-01
---
# Key Lifecycle

| Stage | Where | Notes |
| --- | --- | --- |
| Generate | `JwtService.GenerateKey` → `new CryptographicKey(options.Jws/Jwe)` → `new KeyMaterial(key)` → `store.Store` | Lazily, on first `GetCurrent*` call |
| Use | `GetCurrentSigningCredentials` / `GetCurrentEncryptingCredentials` | Current key = newest non-revoked key for that `use` (`sig`/`enc`) |
| Rotate | `JwtService.NeedsUpdate` | Expired when `CreationDate + DaysUntilExpire (90) < today` (UTC), or revoked |
| Revoke | `KeyMaterial.Revoke(reason)` | Sets `IsRevoked`, `ExpiredAt`, `RevokedReason` and **replaces `Parameters` with the public key only** (NIST SP 800-57: drop private keys you no longer need) |
| Publish | `GetLastKeys` → `/jwks` | Publishes `AlgorithmsToKeep` (default 2) keys per use, so tokens signed by the previous key still validate after rotation |
| Force | `GenerateNewKey(type)` / `RevokeKey(keyId, reason)` | Manual rotation / compromise (`StolenKey`, `ManualRevocation` reasons are used in tests) |

## Options (`JwtOptions.cs`)
- `Jws` default `Algorithm.Create(AlgorithmType.RSA, JwtType.Jws)` → **PS256**
- `Jwe` default `Algorithm.Create(AlgorithmType.RSA, JwtType.Jwe)` → **RSA-OAEP + A128CBC-HS256**
- `DaysUntilExpire = 90`, `AlgorithmsToKeep = 2`, `CacheTime = 15 min` (sliding), `KeyPrefix = "{MachineName}_"`

## Algorithm change
`CheckCompatibility` only compares **`kty`** (RSA / EC / oct). Switching RS256 → PS256 keeps the existing RSA key. Switching RSA → ECDsa generates a new key on the next call.

Related: [[Stores]], [[Algorithms]].
