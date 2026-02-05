using System.Security.Claims;
using Bogus;
using Microsoft.OpenApi;

namespace AspNet.Default
{
    public static class FakeClaims
    {
        public static Faker<Claim> GenerateClaim()
            => new Faker<Claim>()
                .CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
    }

    public static class CustomSwagger
    {
        public static void AddSwagger(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "Bearer {token}",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                });

            });
        }
    }
}