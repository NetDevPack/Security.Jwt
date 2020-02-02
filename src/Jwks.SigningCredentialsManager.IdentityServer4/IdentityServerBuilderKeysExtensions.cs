using IdentityServer4.Stores;
using Jwks.SigningCredentialsManager;
using Jwks.SigningCredentialsManager.IdentityServer4;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering crypto services
    /// </summary>
    public static class IdentityServerBuilderKeysExtensions
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IServiceCollection AddAutoSigningCredential(this IServiceCollection services, Action<JwksOptions> action = null)
        {
            if (action != null)
                services.Configure(action);


            services.AddScoped<IKeyService, KeyService>();
            services.AddScoped<ISigningCredentialStore, IdentityServer4KeyStore>();
            services.AddScoped<IValidationKeysStore, IdentityServer4KeyStore>();

            return services;
        }
    }
}