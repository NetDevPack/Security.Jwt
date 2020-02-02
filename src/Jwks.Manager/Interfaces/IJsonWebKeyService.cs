using Microsoft.IdentityModel.Tokens;

namespace Jwks.Manager.Interfaces
{
    public interface IJsonWebKeyService
    {
        SecurityKey Generate(Algorithm algorithm);
    }
}
