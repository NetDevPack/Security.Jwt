using System.Collections.Generic;

namespace Jwks.SigningCredentialsManager.Store
{
    public interface IKeyStore
    {
        void Save(SecurityKeyWithPrivate securityParamteres);
        SecurityKeyWithPrivate GetCurrentKey();
        IReadOnlyCollection<SecurityKeyWithPrivate> Get(int quantity = 5);
        void Clear();
        bool NeedsUpdate();
    }
}