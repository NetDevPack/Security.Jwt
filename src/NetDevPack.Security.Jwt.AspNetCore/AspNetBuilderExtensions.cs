using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.Core.Interfaces;

namespace Microsoft.Extensions.DependencyInjection;

public static class AspNetBuilderExtensions
{
    public static IApplicationBuilder UseJwksDiscovery(this IApplicationBuilder app, string jwtDiscoveryEndpoint = "/jwks")
    {
        if (!jwtDiscoveryEndpoint.StartsWith('/')) throw new ArgumentException("The Jwks URI must starts with '/'");

        app.Map(new PathString(jwtDiscoveryEndpoint), x =>
            x.UseMiddleware<JwtServiceDiscoveryMiddleware>());
            
        return app;
    }

    /// <summary>
    /// Sets the signing credential.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="credential">The credential.</param>
    /// <returns></returns>
    public static IJwksBuilder UseJwtValidation(this IJwksBuilder builder)
    {

        builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>>(s => new JwtPostConfigureOptions(s));

        return builder;
    }
}

    