using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Store.EntityFrameworkCore;

namespace NetDevPack.Security.Jwt.Tests
{
    public class AspNetGeneralContext : DbContext, IDataProtectionKeyContext, ISecurityKeyContext
    {
#pragma warning disable CS8618
        public AspNetGeneralContext(DbContextOptions<AspNetGeneralContext> options)
#pragma warning restore CS8618
            : base(options) { }

        public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
        public DbSet<KeyMaterial> SecurityKeys { get; set; }
    }
}
