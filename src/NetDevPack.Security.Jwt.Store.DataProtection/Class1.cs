using System;
using System.Collections.Generic;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        public AspNetCoreDataProtection(IXmlRepository )
        {

        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            
        }

        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<SecurityKeyWithPrivate> Get(JsonWebKeyType jwkType, int quantity = 5)
        {
            throw new NotImplementedException();
        }

        public void Clear()
        {
            throw new NotImplementedException();
        }

        public bool NeedsUpdate(JsonWebKeyType jsonWebKeyType)
        {
            throw new NotImplementedException();
        }

        public void Update(SecurityKeyWithPrivate securityKeyWithPrivate)
        {
            throw new NotImplementedException();
        }
    }
}
