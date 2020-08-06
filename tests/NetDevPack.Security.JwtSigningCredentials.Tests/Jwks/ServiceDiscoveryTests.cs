using System;
using FluentAssertions;
using NetDevPack.Security.JwtSigningCredentials.Tests.Infra;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    public class ServiceDiscoveryTests
    {
        [Fact]
        public async Task ShouldGetJwks()
        {
            var server = new Server();

            var client = server.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");

            var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
        }

        [Fact]
        public async Task ShouldJwksHasKeys()
        {
            var server = new Server();

            var client = server.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");

            var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();

            var keys = JsonConvert.DeserializeObject<JsonWebKeySet>(await response.Content.ReadAsStringAsync());

            keys.Should().NotBeNull();
            keys.Keys.Should().NotBeEmpty();
            keys.Keys.Should().NotContainNulls();
        }


        [Fact]
        public void ShouldThrowErrorWhenAppDoesntUseMemoryCache()
        {
            var server = new Server();

            var ex = Assert.Throws<InvalidOperationException>(() => server.CreateClient(false));
            ex.Message.Should().Be("Service Discovery relies on IMemoryCache. Add services.AddMemoryCache() in your application");
        }


        [Fact]
        public async Task ShouldUpdateCacheAfterKeyRotation()
        {
            var server = new Server();

            var client = server.CreateClient();

            // GET JWK
            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");
            var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
            var jwks = new JsonWebKeySet(await response.Content.ReadAsStringAsync());
            jwks.Keys.Should().HaveCount(1);

            // Force Generate a new one
            request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/renew");

            response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            // GET JWK Again - now it needs to have 2 keys.
            request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");
            response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
            jwks = new JsonWebKeySet(await response.Content.ReadAsStringAsync());
            jwks.Keys.Should().HaveCount(2);
        }
    }
}
