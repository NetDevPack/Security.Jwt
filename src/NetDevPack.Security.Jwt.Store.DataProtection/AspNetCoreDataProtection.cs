using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        private readonly ILoggerFactory _loggerFactory;
        private IXmlRepository KeyRepository { get; set; }
        private IXmlEncryptor KeyEncryptor { get; set; }
        private IKeyEscrowSink KeyEscrowSink { get; set; }

        private const string Name = "NetDevPack.Security.Jwt";
        public AspNetCoreDataProtection(ILoggerFactory loggerFactory)
        {

            _loggerFactory = loggerFactory;
            Check();
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            var ser = new XmlSerializer(typeof(SecurityKeyWithPrivate));
            var doc = new XDocument();
            using (var xw = doc.CreateWriter())
            {
                ser.Serialize(xw, securityParamteres);
                xw.Close();
            }


            var possiblyEncryptedKeyElement = KeyEncryptor?.Encrypt(doc.Root) != null ? KeyEncryptor.Encrypt(doc.Root).EncryptedElement : doc?.Root;

            // Persist it to the underlying repository and trigger the cancellation token.
            var friendlyName = string.Format(CultureInfo.InvariantCulture, "key-{0}-{1:D}", securityParamteres.JwkType.ToString(), securityParamteres.KeyId);
            KeyRepository.StoreElement(possiblyEncryptedKeyElement, friendlyName);

        }

        private void Check()
        {
            if (KeyRepository == null)
            {
                var keyval = GetFallbackKeyRepositoryEncryptorPair();
                KeyRepository = keyval.Key;
                KeyEncryptor = keyval.Value;

            }
        }


        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            return GetKeys().FirstOrDefault(f => f.JwkType == jwkType);
        }

        private IOrderedEnumerable<SecurityKeyWithPrivate> GetKeys()
        {

            var allElements = KeyRepository.GetAllElements();
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
