using Microsoft.EntityFrameworkCore;

namespace Jwks.SigningCredentialsManager.Store.EntityFrameworkCore
{
    public interface ISecurityKeyContext
    {
        /// <summary>
        /// A collection of <see cref="T:Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey" />
        /// </summary>
        DbSet<SecurityKeyWithPrivate> SecurityKeys { get; }
    }
}
