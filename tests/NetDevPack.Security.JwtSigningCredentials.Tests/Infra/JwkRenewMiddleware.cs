using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System.Threading.Tasks;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Infra
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
                securityKeyWithPrivate.SetParameters();
                store.Update(securityKeyWithPrivate);
            }

            keyService.GenerateSigningCredentials();
            await httpContext.Response.CompleteAsync();
        }
    }
}