namespace Microsoft.Extensions.DependencyInjection
{
    public interface IJwksBuilder
    {
        IServiceCollection Services { get; }
    }
}