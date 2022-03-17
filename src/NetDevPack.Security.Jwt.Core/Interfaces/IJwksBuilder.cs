using Microsoft.Extensions.DependencyInjection;

namespace NetDevPack.Security.Jwt.Core.Interfaces;

public interface IJwksBuilder
{
    IServiceCollection Services { get; }
}