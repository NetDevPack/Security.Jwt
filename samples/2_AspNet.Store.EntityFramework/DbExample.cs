using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Store.EntityFrameworkCore;

namespace AspNet.Store.EntityFramework
{
    public class DbExample : IdentityDbContext, ISecurityKeyContext
    {
        public DbExample(DbContextOptions<DbExample> options) : base(options) { }
        public DbSet<KeyMaterial> SecurityKeys { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfiguration(new KeyMaterialMap());
            base.OnModelCreating(modelBuilder);
        }
    }
}
