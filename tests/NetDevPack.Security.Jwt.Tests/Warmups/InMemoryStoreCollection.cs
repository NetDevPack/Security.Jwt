using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Warmups;

[CollectionDefinition(Name)]
public class InMemoryStoreCollection
{
    public const string Name = "InMemory Store";
}
