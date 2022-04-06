using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NetDevPack.Security.Jwt.AspNet.SymetricKey;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] { }
        }
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "NetDevPack",
        ValidAudience = "NetDevPack.AspNet.SymetricKey"
    };
});
builder.Services.AddAuthorization();
builder.Services.AddJwksManager().UseJwtValidation().PersistKeysInMemory();
builder.Services.AddMemoryCache();

var app = builder.Build();
IdentityModelEventSource.ShowPII = true;
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection();

app.MapGet("/random-jws", [AllowAnonymous]async (IJwtService service) =>
   {
       var handler = new JsonWebTokenHandler();
       var now = DateTime.Now;
       var descriptor = new SecurityTokenDescriptor
       {
           Issuer = "NetDevPack",
           Audience = "NetDevPack.Security.Jwt.AspNet",
           IssuedAt = now,
           NotBefore = now,
           Expires = now.AddMinutes(5),
           Subject = new ClaimsIdentity(FakeClaims.GenerateClaim().Generate(5)),
           SigningCredentials = await service.GetCurrentSigningCredentials()
       };

       return handler.CreateToken(descriptor);
   })
    .WithName("Generate random JWS")
    .WithTags("JWS");

app.MapGet("/random-jwe", [AllowAnonymous] async (IJwtService service) =>
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "NetDevPack",
            Audience = "NetDevPack.Security.Jwt.AspNet",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = new ClaimsIdentity(FakeClaims.GenerateClaim().Generate(5)),
            EncryptingCredentials = await service.GetCurrentEncryptingCredentials()
        };

        return handler.CreateToken(descriptor);
    })
    .WithName("Generate random JWE")
    .WithTags("JWE");

app.MapGet("/validate-jwt/{jwt}", [Authorize]async (IJwtService service, string jwt) =>
{
    var handler = new JsonWebTokenHandler();

    var result = handler.ValidateToken(jwt,
        new TokenValidationParameters
        {
            ValidIssuer = "NetDevPack",
            ValidAudience = "NetDevPack.Security.Jwt.AspNet",
            RequireSignedTokens = false,
            IssuerSigningKey = await service.GetCurrentSecurityKey(),
        });

    return result.Claims;
})
.WithName("Validate JWT")
.WithTags("Validate");


app.MapGet("/validate-jwe/{jwe}", async (IJwtService service, string jwe) =>
    {
        var handler = new JsonWebTokenHandler();

        var result = handler.ValidateToken(jwe,
            new TokenValidationParameters
            {
                ValidIssuer = "NetDevPack",
                ValidAudience = "NetDevPack.Security.Jwt.AspNet",
                RequireSignedTokens = false,
                TokenDecryptionKey = await service.GetCurrentSecurityKey(),
            });

        return result.Claims;
    })
    .WithName("Validate JWE")
    .WithTags("Validate");


app.Run();
