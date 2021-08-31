using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.Interfaces;
using NetDevPack.Security.Jwt.Model;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetDevPack.Security.Jwt.AspNetCore
{
    public class JwtServiceDiscoveryMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtServiceDiscoveryMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext, IJsonWebKeySetService keyService, IOptions<JwksOptions> options)
        {
            var keys = new
            {
                keys = keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, options.Value.AlgorithmsToKeep)?.Select(PublicJsonWebKey.FromJwk)
            };

            await httpContext.Response.WriteAsync(JsonSerializer.Serialize(keys, new JsonSerializerOptions() { IgnoreNullValues = true }));
        }
    }
}
