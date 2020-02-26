using Jwks.Manager;
using Jwks.Manager.Interfaces;
using Jwks.Manager.Jwk;
using Jwks.Manager.Jwks;
using System;

namespace Microsoft.Extensions.DependencyInjection
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

            services.AddScoped<IJsonWebKeyService, JwkService>();
            services.AddScoped<IJsonWebKeySetService, JwksService>();

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
