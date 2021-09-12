using Microsoft.IdentityModel.Tokens;

namespace NetDevPack.Security.Jwt.Interfaces
{
    public interface IJsonWebKeyService
    {
        JsonWebKey Generate(Algorithm algorithm);
    }
}
