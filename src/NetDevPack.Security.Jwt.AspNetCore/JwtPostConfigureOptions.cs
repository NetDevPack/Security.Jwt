using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.Core.Interfaces;

namespace NetDevPack.Security.Jwt.AspNetCore;

public class JwtPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly IServiceProvider _serviceProvider;
    // private readonly MyCustomSecurityTokenValidator _tokenValidator; //example dependancy

    public JwtPostConfigureOptions(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public void PostConfigure(string name, JwtBearerOptions options)
    {
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new JwtServiceValidationHandler(_serviceProvider));
    }
}