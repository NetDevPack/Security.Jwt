using System.Security.Claims;
using AspNet.Store.EntityFramework;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NetDevPack.Security.Jwt.Core.Interfaces;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwagger();

// Configure Database
builder.Services.AddDbContext<DbExample>(
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddJwksManager()
    .UseJwtValidation()
    .PersistKeysToDatabaseStore<DbExample>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://www.devstore.academy", // <- Your website
        ValidAudience = "NetDevPack.Security.Jwt.AspNet"
    };
});

builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
    app.UseSwagger();
    app.UseSwaggerUI();

    // Create database
    using var scope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<DbExample>();
    await db.Database.EnsureCreatedAsync();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseHttpsRedirection();

app.MapGet("/random-jws", async (IJwtService service) =>
   {
       var handler = new JsonWebTokenHandler();
       var now = DateTime.Now;
       var descriptor = new SecurityTokenDescriptor
       {
           Issuer = "https://www.devstore.academy", // <- Your website
           Audience = "NetDevPack.Security.Jwt.AspNet",
           IssuedAt = now,
           NotBefore = now,
           Expires = now.AddMinutes(60),
           Subject = new ClaimsIdentity(FakeClaims.GenerateClaim().Generate(5)),
           SigningCredentials = await service.GetCurrentSigningCredentials()
       };

       return handler.CreateToken(descriptor);
   })
    .WithName("Generate random JWS")
    .WithTags("JWS");

app.MapGet("/random-jwe", async (IJwtService service) =>
   {
       var handler = new JsonWebTokenHandler();
       var now = DateTime.Now;
       var descriptor = new SecurityTokenDescriptor
       {
           Issuer = "https://www.devstore.academy",
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

app.MapGet("/validate-jws/{jws}", async (IJwtService service, string jws) =>
{
    var handler = new JsonWebTokenHandler();

    var result = handler.ValidateToken(jws,
        new TokenValidationParameters
        {
            ValidIssuer = "https://www.devstore.academy",
            ValidAudience = "NetDevPack.Security.Jwt.AspNet",
            RequireSignedTokens = false,
            IssuerSigningKey = await service.GetCurrentSecurityKey(),
        });

    return result.Claims;
})
.WithName("Validate JWT (In fact jws, but no one cares)")
.WithTags("Validate");


app.MapGet("/validate-jwe/{jwe}", async (IJwtService service, string jwe) =>
    {
        var handler = new JsonWebTokenHandler();

        var result = handler.ValidateToken(jwe,
            new TokenValidationParameters
            {
                ValidIssuer = "https://www.devstore.academy",
                ValidAudience = "NetDevPack.Security.Jwt.AspNet",
                RequireSignedTokens = false,
                TokenDecryptionKey = await service.GetCurrentSecurityKey(),
            });

        return result.Claims;
    })
    .WithName("Validate JWE")
    .WithTags("Validate");

app.MapGet("/protected-endpoint", [Authorize] ([FromServices] IHttpContextAccessor context) =>
{
    return Results.Ok(context.HttpContext?.User.Claims.Select(s => new { s.Type, s.Value }));
}).WithName("Protected Endpoint")
    .WithTags("Validate");

app.Run();
