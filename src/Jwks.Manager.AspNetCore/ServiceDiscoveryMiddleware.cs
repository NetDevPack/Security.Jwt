using System.Linq;
using System.Threading.Tasks;
using Jwks.Manager.Interfaces;
using Jwks.Manager.Jwks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace Jwks.Manager.AspNetCore
{
    public class ServiceDiscoveryMiddleware
    {
        private readonly RequestDelegate _next;

        public ServiceDiscoveryMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext, IJsonWebKeySetService keyService, IOptions<JwksOptions> options)
        {
            var keys = keyService.GetLastKeysCredentials(options.Value.AlgorithmsToKeep)?.Select(JwksService.RemovePrivateKey);

            await httpContext.Response.WriteAsync(JsonConvert.SerializeObject(keys));
        }
    }
}
