using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.DefaultStore;
using NetDevPack.Security.Jwt.DefaultStore.Memory;
using NetDevPack.Security.Jwt.Interfaces;
using NetDevPack.Security.Jwt.Jwk;
using NetDevPack.Security.Jwt.Jwks;
using System;

namespace NetDevPack.Security.Jwt
{
    public static class JsonWebKeySetManagerDependencyInjection
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IJwksBuilder AddJwksManager(this IServiceCollection services, Action<JwksOptions> action = null)
        {
            if (action != null)
                services.Configure(action);

            services.AddDataProtection();
            services.AddScoped<IJsonWebKeyService, JwkService>();
            services.AddScoped<IJsonWebKeySetService, JwksService>();
            services.AddSingleton<IJsonWebKeyStore, DataProtectionStore>();

            return new JwksBuilder(services);
        }

        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IJwksBuilder PersistKeysInMemory(this IJwksBuilder builder)
        {
            builder.Services.AddSingleton<IJsonWebKeyStore, InMemoryStore>();

            return builder;
        }
    }
}
