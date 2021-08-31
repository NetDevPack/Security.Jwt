using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;

namespace NetDevPack.Security.Jwt.AspNetCore
{
    public static class AspNetBuilderExtensions
    {
        public static IApplicationBuilder UseJwksDiscovery(this IApplicationBuilder app, string jwtDiscoveryEndpoint = "/jwks", string jweDiscoveryEndpoint = "/jwks_e")
        {
            if (!jwtDiscoveryEndpoint.StartsWith('/')) throw new ArgumentException("The Jwks URI must starts with '/'");

            app.Map(new PathString(jwtDiscoveryEndpoint), x =>
                x.UseMiddleware<JwtServiceDiscoveryMiddleware>());


            app.Map(new PathString(jweDiscoveryEndpoint), x =>
                x.UseMiddleware<JweServiceDiscoveryMiddleware>());
            
            return app;
        }
    }
}