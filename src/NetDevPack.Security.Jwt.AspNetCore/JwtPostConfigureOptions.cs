using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.Core.Interfaces;

namespace NetDevPack.Security.Jwt.AspNetCore;

public class JwtPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly IJwtService _jwtService;
    // private readonly MyCustomSecurityTokenValidator _tokenValidator; //example dependancy

    public JwtPostConfigureOptions(IJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    public void PostConfigure(string name, JwtBearerOptions options)
    {
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new JwtServiceValidationHandler(_jwtService));
    }
}