---
tags: [adr]
status: accepted
date: 2026-10-01
---
# ADR-002 — Keep IdentityServer4 package as deprecated

**Context.** IdentityServer4 4.1.2 has been EOL since 2022 and has known moderate advisories. It will never get a fix. Some users still depend on `NetDevPack.Security.Jwt.IdentityServer4`.

**Decision.** Keep publishing it for backward compatibility, marked **[DEPRECATED]** in title, description, tags and README. Suppress `NU1902` only in that project and in `samples/3_IdentityServer4`. Dependabot ignores `IdentityServer4`. No new features.

**Alternatives considered.** Removing it (breaks users). Migrating to Duende (commercial license, big scope). OpenIddict could get a future integration package.

Related: [[Known-Issues]].
