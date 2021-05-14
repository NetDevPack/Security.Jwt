using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace NetDevPack.Security.JwtSigningCredentials.AspNetCore
{
    public static class AspNetBuilderExtensions
    {
        public static IApplicationBuilder UseJwksDiscovery(this IApplicationBuilder app, string jwksUri = "/jwks")
        {
            if (!jwksUri.StartsWith('/')) throw new ArgumentException("The Jwks URI must starts with '/'");

            app.Map(new PathString(jwksUri), x =>
                x.UseMiddleware<ServiceDiscoveryMiddleware>());

            if (app.ApplicationServices.GetService<IMemoryCache>() == null)
                throw new InvalidOperationException("Service Discovery relies on IMemoryCache. Add services.AddMemoryCache() in your application");
            return app;
        }
    }
}