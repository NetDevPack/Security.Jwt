using System;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Interfaces;

namespace NetDevPack.Security.Jwt
{
    public class JwksBuilder : IJwksBuilder
    {

        public JwksBuilder(IServiceCollection services)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
        }

        public IServiceCollection Services { get; }
    }
}