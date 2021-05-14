using Microsoft.IdentityModel.Tokens;

namespace NetDevPack.Security.JwtSigningCredentials.Interfaces
{
    public interface IJsonWebKeyService
    {
        JsonWebKey Generate(Algorithm jwsAlgorithm);
    }
}
