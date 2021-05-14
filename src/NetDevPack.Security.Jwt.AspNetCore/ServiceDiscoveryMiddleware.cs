using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

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
            var keys = new
            {
                keys = keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, options.Value.AlgorithmsToKeep)?.Select(PublicJsonWebKey.FromJwk)
            };

            await httpContext.Response.WriteAsync(JsonSerializer.Serialize(keys, new JsonSerializerOptions() { IgnoreNullValues = true }));
        }
    }
}
