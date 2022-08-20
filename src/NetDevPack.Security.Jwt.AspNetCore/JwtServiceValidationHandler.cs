using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace NetDevPack.Security.Jwt.AspNetCore;

public class JwtServiceValidationHandler : JwtSecurityTokenHandler
{
    private readonly IServiceProvider _serviceProvider;

    public JwtServiceValidationHandler(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var jwtService = scope.ServiceProvider.GetRequiredService<IJwtService>();

        //We can read the token before we've begun validating it.
        //JwtSecurityToken incomingToken = ReadJwtToken(token);

        //Retrieve the corresponding Public Key from our data store
        var keyMaterialTask = jwtService.GetCurrentSecurityKey();
        Task.WaitAll(keyMaterialTask);
        validationParameters.IssuerSigningKey = keyMaterialTask.Result;

        //And let the framework take it from here.
        //var handler = new JsonWebTokenHandler();
        //var result = handler.ValidateToken(token, validationParameters);
        //validatedToken = result.SecurityToken;

        //return new ClaimsPrincipal(result.ClaimsIdentity);
        return base.ValidateToken(token, validationParameters, out validatedToken);
    }
}