---
tags: [architecture, aspnetcore]
updated: 2026-10-01
---
# ASP.NET Core Integration

File: `src/NetDevPack.Security.Jwt.AspNetCore/AspNetBuilderExtensions.cs`

## `app.UseJwksDiscovery(path = "/jwks")`
Maps `JwtServiceDiscoveryMiddleware`, which returns `{ "keys": [...] }` with **public** keys only (`PublicJsonWebKey.FromJwk`) for the last `AlgorithmsToKeep` keys. Client APIs consume it through `NetDevPack.Security.JwtExtensions` (`SetJwksOptions(new JwkOptions(url))`). See `samples/Microservice.Sample`.

## `services.AddJwksManager().UseJwtValidation()`
Registers `JwtPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>`, which clears `options.TokenHandlers` and adds `JwtServiceValidationHandler`. On every token the handler loads `GetLastKeys()` and sets them as `IssuerSigningKeys`. Issuer/audience/lifetime validation still comes from the app's `TokenValidationParameters`.

⚠️ The handler extends the legacy `JwtSecurityTokenHandler` and blocks on async (`Task.WaitAll`). See [[Known-Issues]].

Tests: `tests/NetDevPack.Security.Jwt.AspNetCoreTests` (WebApplicationFactory over `samples/1_AspNet.Default`).
