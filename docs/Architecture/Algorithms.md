---
tags: [architecture, crypto]
updated: 2026-10-01
---
# Algorithms (`src/NetDevPack.Security.Jwt.Core/Jwa/`)

`Algorithm.Create(string alg)` or `Algorithm.Create(AlgorithmType, JwtType)`. There are implicit conversions to and from `string`.

| `AlgorithmType` + `Jws` | Result |
| --- | --- |
| RSA (**default**) | PS256 |
| ECDsa | ES256 + P-256 |
| HMAC | HS256 |

| `AlgorithmType` + `Jwe` | Result |
| --- | --- |
| RSA (**default**) | RSA-OAEP + A128CBC-HS256 |
| AES | A128KW + A128CBC-HS256 |

- Supported JWS: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512 (`DigitalSignaturesAlgorithm.cs`).
- Supported JWE key mgmt: RSA1_5, RSA-OAEP, A128KW, A256KW (`EncryptionAlgorithmKey.cs`). Content: `EncryptionAlgorithmContent.cs`.
- `.WithCurve()` only for ECDsa. `.WithContentEncryption()` only for JWE.
- Tests: `tests/NetDevPack.Security.Jwt.Tests/JwaTests`, `JwtTests/JweTests.cs`.

Related: [[Key-Lifecycle]].
