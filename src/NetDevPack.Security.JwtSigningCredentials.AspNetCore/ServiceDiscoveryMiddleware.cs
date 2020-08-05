using System;
using System.Collections.Generic;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace NetDevPack.Security.JwtSigningCredentials.AspNetCore
{
    public class ServiceDiscoveryMiddleware
    {
        private readonly RequestDelegate _next;

        public ServiceDiscoveryMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext, IJsonWebKeySetService keyService, IOptions<JwksOptions> options, IMemoryCache memoryCache)
        {
            IReadOnlyCollection<JsonWebKey> credentials;
            if (!memoryCache.TryGetValue("NETDEVPACK-ASPNET-JWKS", out credentials))
            {
                keyService.GetCurrent();
                credentials = keyService.GetLastKeysCredentials(options.Value.AlgorithmsToKeep);

                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(TimeSpan.FromMinutes(15));

                memoryCache.Set("NETDEVPACK-ASPNET-JWKS", credentials, cacheEntryOptions);
            }

            var keys = new
            {
                keys = credentials?.Select(PublicJsonWebKey.FromJwk)
            };

            await httpContext.Response.WriteAsync(JsonSerializer.Serialize(keys, new JsonSerializerOptions() { IgnoreNullValues = true }));
        }
    }
}
