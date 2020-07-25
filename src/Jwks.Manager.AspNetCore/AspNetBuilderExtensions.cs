using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Jwks.Manager.AspNetCore
{
    public static class AspNetBuilderExtensions
    {
        public static IApplicationBuilder UseJwksManager(this IApplicationBuilder app, string jwksUri = "/jwks")
        {
            if(!jwksUri.StartsWith('/')) throw new ArgumentException("The Jwks URI must starts with '/'");

            app.Map(new PathString(jwksUri), x => 
                x.UseMiddleware<ServiceDiscoveryMiddleware>());

            return app;
        }
    }
}