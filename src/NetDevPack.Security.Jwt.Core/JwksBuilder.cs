using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core.Interfaces;

namespace NetDevPack.Security.Jwt.Core;

public class JwksBuilder : IJwksBuilder
{

    public JwksBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    public IServiceCollection Services { get; }
}