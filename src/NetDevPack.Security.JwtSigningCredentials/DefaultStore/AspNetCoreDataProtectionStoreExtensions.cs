using NetDevPack.Security.JwtSigningCredentials.DefaultStore;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering crypto services
    /// </summary>
    public static class AspNetCoreDataProtectionStoreExtensions
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IJwksBuilder PersistKeysToDataProtection(this IJwksBuilder builder)
        {
            builder.Services.AddDataProtection();

            builder.Services.AddScoped<IJsonWebKeyStore, DataProtectionStore>();

            return builder;
        }
    }
}