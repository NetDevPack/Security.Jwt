---
tags: [adr]
status: accepted
date: 2026-10-01
---
# ADR-001 — Drop netstandard2.1

**Context.** `netstandard2.1` forced EF Core **3.1.32** (out of support) in the EF store and a separate dependency set in Core (`System.Text.Json`, `Pkcs`, `Asn1`, 10.x packages on a netstandard target). It also needed `#if NET5_0_OR_GREATER` branches.

**Decision.** All packages target `net8.0;net9.0;net10.0` only. The dead `net6.0`/`net7.0` conditions were removed as well.

**Consequences.** Breaking change, shipped as **v10.0.0** (the commit carries `BREAKING CHANGE:`). Consumers on .NET Framework / .NET Core 3.1 / .NET 6-7 stay on v9.x. The csproj files and code are simpler, and `System.Security.Cryptography.Pkcs`/`Formats.Asn1` are no longer explicit references.

Related: [[Policy]].
