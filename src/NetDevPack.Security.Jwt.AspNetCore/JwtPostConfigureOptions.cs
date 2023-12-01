using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace NetDevPack.Security.Jwt.AspNetCore;

public class JwtPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly IServiceProvider _serviceProvider;

    public JwtPostConfigureOptions(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public void PostConfigure(string? name, JwtBearerOptions options)
    {
#if NET8_0_OR_GREATER
        options.TokenHandlers.Clear();
        options.TokenHandlers.Add(new JwtServiceValidationHandler(_serviceProvider));
#else
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new JwtServiceValidationHandler(_serviceProvider));
#endif
    }
}