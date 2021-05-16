using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.Interfaces;
using NetDevPack.Security.Jwt.Model;

namespace NetDevPack.Security.Jwt.Tests.Infra
{
    public class JwkRenewMiddleware
    {
        private readonly RequestDelegate _next;
        public JwkRenewMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext, IJsonWebKeySetService keyService, IJsonWebKeyStore store, IOptions<JwksOptions> options)
        {
            foreach (var securityKeyWithPrivate in store.Get(JsonWebKeyType.Jws, options.Value.AlgorithmsToKeep))
            {
                store.Revoke(securityKeyWithPrivate);
            }

            keyService.GenerateSigningCredentials();
            await httpContext.Response.CompleteAsync();
        }
    }
}