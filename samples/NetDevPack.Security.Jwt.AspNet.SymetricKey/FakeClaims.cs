using System.Security.Claims;
using Bogus;

namespace NetDevPack.Security.Jwt.AspNet.SymetricKey
{
    public static class FakeClaims
    {
        public static Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
