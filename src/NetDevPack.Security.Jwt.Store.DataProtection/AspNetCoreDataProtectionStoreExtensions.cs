using NetDevPack.Security.Jwt.Store.DataProtection;
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

            builder.Services.AddScoped<IJsonWebKeyStore, AspNetCoreDataProtection>();

            return builder;
        }
    }
}