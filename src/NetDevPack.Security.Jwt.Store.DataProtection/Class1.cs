using Microsoft.AspNetCore.DataProtection.Repositories;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        private readonly IXmlRepository _xmlRepository;
        private const string Name = "NetDevPack.Security.Jwt";
        public AspNetCoreDataProtection(IXmlRepository xmlRepository)
        {
            _xmlRepository = xmlRepository;
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            using var memoryStream = new MemoryStream();
            using TextWriter streamWriter = new StreamWriter(memoryStream);

            var xmlSerializer = new XmlSerializer(typeof(SecurityKeyWithPrivate));
            xmlSerializer.Serialize(streamWriter, securityParamteres);
            _xmlRepository.StoreElement(XElement.Parse(Encoding.ASCII.GetString(memoryStream.ToArray())), Name);
        }

        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            var allElements = _xmlRepository.GetAllElements();
            var keys = new Dictionary<string, SecurityKeyWithPrivate>();
            foreach (var element in allElements)
            {
                if (element.Name == Name)
                {
                    var key = new SecurityKeyWithPrivate()
                    {
                        JwkType = (JsonWebKeyType)int.Parse(element.Attribute("JwkType")!.Value),
                    };
                }
            }
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
