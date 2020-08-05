using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Api.Identity.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Api.Identity
{
    public class Program
    {
        public static void Main(string[] args)
        {

            var host = CreateHostBuilder(args).Build();

            Task.WaitAll(DbMigrationHelpers.EnsureSeedData(host.Services.CreateScope()));

            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }

    public static class DbMigrationHelpers
    {
       
        public static async Task EnsureSeedData(IServiceScope serviceScope)
        {
            var serviceProvider = serviceScope.ServiceProvider;
            using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();
            var appContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            appContext.Database.EnsureCreated();
        }
    }
}
