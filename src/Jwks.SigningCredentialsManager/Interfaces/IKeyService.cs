using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace Jwks.SigningCredentialsManager
{
    public interface IKeyService
    {
        SigningCredentials Generate();
        SecurityKey GetSecurityKey(SecurityKeyWithPrivate securityFile);

        SigningCredentials GetCurrent();
        IReadOnlyCollection<SecurityKeyWithPrivate> GetLastKeysCredentials(int qty);
    }
}