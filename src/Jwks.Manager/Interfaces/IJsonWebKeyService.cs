using Microsoft.IdentityModel.Tokens;

namespace Jwks.Manager.Interfaces
{
    public interface IJsonWebKeyService
    {
        JsonWebKey Generate(Algorithm algorithm);
    }
}
