using Microsoft.AspNetCore.DataProtection.Repositories;
using NetDevPack.Security.Jwt.Store.DataProtection;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using System.Linq;

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
            if (builder.Services.All(x => x.ServiceType != typeof(IXmlRepository)))
                builder.Services.AddDataProtection();
            builder.Services.AddScoped<IJsonWebKeyStore, AspNetCoreDataProtection>();

            return builder;
        }
    }
}