using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        private readonly IOptions<KeyManagementOptions> _keyManagementOptions;
        private readonly ILoggerFactory _loggerFactory;
        private readonly IConfigureOptions<KeyManagementOptions> _options;
        private readonly IInternalXmlKeyManager _internalXmlKeyManager;
        private readonly IXmlRepository _xmlRepository;
        private const string Name = "NetDevPack.Security.Jwt";
        public AspNetCoreDataProtection(IOptions<KeyManagementOptions> keyManagementOptions,
            ILoggerFactory loggerFactory)
        {
            _keyManagementOptions = keyManagementOptions;
            _loggerFactory = loggerFactory;
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            using var memoryStream = new MemoryStream();
            using TextWriter streamWriter = new StreamWriter(memoryStream);

            var xmlSerializer = new XmlSerializer(typeof(SecurityKeyWithPrivate));
            xmlSerializer.Serialize(streamWriter, securityParamteres);
            _keyManagementOptions.Value.XmlRepository.StoreElement(XElement.Parse(Encoding.ASCII.GetString(memoryStream.ToArray())), Name);
        }

        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            return GetKeys().FirstOrDefault(f => f.JwkType == jwkType);
        }

        private IOrderedEnumerable<SecurityKeyWithPrivate> GetKeys()
        {

            var allElements = _keyManagementOptions.Value.XmlRepository.GetAllElements();
            var keys = new List<SecurityKeyWithPrivate>();
            foreach (var element in allElements)
            {
                if (element.Name == Name)
                {
                    var key = FromXElement<SecurityKeyWithPrivate>(element);
                    keys.Add(key);
                }
            }

            return keys.OrderByDescending(o => o.CreationDate);
        }

        private static T FromXElement<T>(XElement xElement)
        {
            var xmlSerializer = new XmlSerializer(typeof(T));
            return (T)xmlSerializer.Deserialize(xElement.CreateReader());
        }

        public IEnumerable<SecurityKeyWithPrivate> Get(JsonWebKeyType jwkType, int quantity = 5)
        {
            return GetKeys().Where(w => w.JwkType == jwkType).Take(quantity);
        }

        public void Clear()
        {

        }

        public bool NeedsUpdate(JsonWebKeyType jsonWebKeyType)
        {
            return true;
        }

        public void Update(SecurityKeyWithPrivate securityKeyWithPrivate)
        {
            throw new NotImplementedException();
        }








        internal KeyValuePair<IXmlRepository, IXmlEncryptor> GetFallbackKeyRepositoryEncryptorPair()
        {
            IXmlEncryptor xmlEncryptor = (IXmlEncryptor)null;
            DirectoryInfo forAzureWebSites = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectoryForAzureWebSites();
            IXmlRepository key;
            if (forAzureWebSites != null)
            {
                key = (IXmlRepository)new FileSystemXmlRepository(forAzureWebSites, this._loggerFactory);
            }
            else
            {
                DirectoryInfo storageDirectory = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectory();
                if (storageDirectory != null)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        xmlEncryptor = (IXmlEncryptor)new DpapiXmlEncryptor(true, this._loggerFactory);
                    key = (IXmlRepository)new FileSystemXmlRepository(storageDirectory, this._loggerFactory);
                }
                else
                {
                    RegistryKey registryKey = (RegistryKey)null;
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        registryKey = RegistryXmlRepository.DefaultRegistryKey;
                    if (registryKey != null)
                    {
                        RegistryKey defaultRegistryKey = RegistryXmlRepository.DefaultRegistryKey;
                        xmlEncryptor = (IXmlEncryptor)new DpapiXmlEncryptor(true, this._loggerFactory);
                        key = (IXmlRepository)new RegistryXmlRepository(defaultRegistryKey, this._loggerFactory);
                    }
                    else
                    {
                        throw new Exception(
                            "Is not possible to determine which folder are the protection keys. NetDevPack.Security.JwtSigningCredentials.Store.FileSystem or NetDevPack.Security.JwtSigningCredentials.Store.EntityFrameworkCore");
                    }
                }
            }
            return new KeyValuePair<IXmlRepository, IXmlEncryptor>(key, xmlEncryptor);
        }


    }
}
