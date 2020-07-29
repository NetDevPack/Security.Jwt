using System;

namespace Microsoft.Extensions.DependencyInjection
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