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
builder.Services.AddJwksManager().UseJwtValidation();
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

app.MapGet("/get-random-jwt", [AllowAnonymous]async (IJwtService service) =>
   {
       var handler = new JsonWebTokenHandler();
       var now = DateTime.Now;
       var descriptor = new SecurityTokenDescriptor
       {
           Issuer = "NetDevPack",
           Audience = "NetDevPack.AspNet.SymetricKey",
           IssuedAt = now,
           NotBefore = now,
           Expires = now.AddMinutes(5),
           Subject = new ClaimsIdentity(FakeClaims.GenerateClaim().Generate(5)),
           SigningCredentials = await service.GetCurrentSigningCredentials()
       };

       return handler.CreateToken(descriptor);
   })
    .WithName("Generate random JWT");

app.MapGet("/validate-jwt/{jwt}", [Authorize]async (IJwtService service, string jwt) =>
{
    var handler = new JsonWebTokenHandler();

    var result = handler.ValidateToken(jwt,
        new TokenValidationParameters
        {
            ValidIssuer = "NetDevPack",
            ValidAudience = "NetDevPack.AspNet.SymetricKey",
            RequireSignedTokens = false,
            IssuerSigningKey = await service.GetCurrentSecurityKey(),
        });

    return result.Claims;
})
.WithName("Validate JWT");

app.Run();
