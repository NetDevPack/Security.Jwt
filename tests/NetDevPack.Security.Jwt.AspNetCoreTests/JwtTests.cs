using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using System.Security.Claims;
using AspNet.Default;
using FluentAssertions;
using System.Net.Http.Headers;
using System.Text.Json;

namespace NetDevPack.Security.Jwt.AspNetCoreTests;

public class JwtTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    // Top level statement Program.cs problem.
    class FakeApplication : WebApplicationFactory<Program>
    {
    }
    public JwtTests()
    {
        _factory = new FakeApplication();
    }

    [Fact]
    public async Task Should_Validate_Jws()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var scopedServices = scope.ServiceProvider;
        var jwtService = scopedServices.GetRequiredService<IJwtService>();
        var customClaims = FakeClaims.GenerateClaim().Generate(5);
        var currentKey = await jwtService.GetCurrentSigningCredentials();
        var jws = CreateJws(currentKey, customClaims);

        var client = _factory.CreateClient();
        var response = await client.GetAsync($"validate-jws/{jws}");

        response.IsSuccessStatusCode.Should().BeTrue();

        var claims = await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, object>>(await response.Content.ReadAsStreamAsync());
        claims.Should().Contain(a => a.Key == customClaims.First().Type);
    }

    [Fact]
    public async Task Should_Validate_Jws_With_A_Revoked_Key()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var scopedServices = scope.ServiceProvider;
        var jwtService = scopedServices.GetRequiredService<IJwtService>();
        var customClaims = FakeClaims.GenerateClaim().Generate(5);
        var currentKey = await jwtService.GetCurrentSigningCredentials();
        var jws = CreateJws(currentKey, customClaims);

        await jwtService.RevokeKey(currentKey.Key.KeyId);


        var client = _factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/protected-endpoint");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jws);
        var response = await client.SendAsync(request);

        response.IsSuccessStatusCode.Should().BeTrue();
    }


    private static string CreateJws(SigningCredentials key, List<Claim> claims)
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
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = key
        };

        return handler.CreateToken(descriptor);
    }

}
