using Jwks.SigningCredentialsManager;
using Jwks.SigningCredentialsManager.Store;
using Jwks.SigningCredentialsManager.Store.FileSystem;
using Microsoft.Extensions.Options;
using System.IO;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Builder extension methods for registering crypto services
    /// </summary>
    public static class FileSystemStoreSigningCredentialsExtensions
    {
        /// <summary>
        /// Sets the signing credential.
        /// </summary>
        /// <returns></returns>
        public static IServiceCollection UseFileSystemStore(this IServiceCollection services, DirectoryInfo directory)
        {
            services.AddScoped<IKeyStore, FileSystemStore>(provider => new FileSystemStore(directory, provider.GetService<IOptions<JwksOptions>>()));

            return services;
        }
    }
}