using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core.DefaultStore;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwt;

namespace NetDevPack.Security.Jwt.Core
{
    public static class JsonWebKeySetManagerDependencyInjection
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IJwksBuilder AddJwksManager(this IServiceCollection services, Action<JwtOptions> action = null)
        {
            if (action != null)
                services.Configure(action);

            services.AddDataProtection();
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IJsonWebKeyStore, DataProtectionStore>();
            
            return new JwksBuilder(services);
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IJwksBuilder PersistKeysInMemory(this IJwksBuilder builder)
        {
            builder.Services.AddScoped<IJsonWebKeyStore, InMemoryStore>();

            return builder;
        }
    }
}
