using Microsoft.Extensions.DependencyInjection;

namespace NetDevPack.Security.Jwt.Interfaces
{
    public interface IJwksBuilder
    {
        IServiceCollection Services { get; }
    }
}