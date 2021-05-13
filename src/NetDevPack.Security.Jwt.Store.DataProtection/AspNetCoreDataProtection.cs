using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml.Linq;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        // Used for serializing elements to persistent storage
        internal static readonly XName IdAttributeName = "id";
        internal static readonly XName VersionAttributeName = "version";
        internal static readonly XName CreationDateElementName = "creationDate";
        internal static readonly XName ActivationDateElementName = "activationDate";
        internal static readonly XName ExpirationDateElementName = "expirationDate";
        internal static readonly XName DescriptorElementName = "descriptor";
        internal static readonly XName DeserializerTypeAttributeName = "deserializerType";

        private readonly ILoggerFactory _loggerFactory;
        private readonly IOptions<JwksOptions> _options;
        private readonly IOptions<KeyManagementOptions> _keyManagementOptions;
        private readonly IDataProtector _dataProtector;
        private IXmlRepository KeyRepository { get; set; }

        private const string Name = "NetDevPackSecurityJwt";
        public AspNetCoreDataProtection(ILoggerFactory loggerFactory, IOptions<JwksOptions> options, IDataProtectionProvider provider, IOptions<KeyManagementOptions> keyManagementOptions)
        {
            _loggerFactory = loggerFactory;
            _options = options;
            _keyManagementOptions = keyManagementOptions;
            _dataProtector = provider.CreateProtector(typeof(SecurityKeyWithPrivate).AssemblyQualifiedName); ;
            Check();
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            var possiblyEncryptedKeyElement = _dataProtector.Protect(System.Text.Json.JsonSerializer.Serialize(securityParamteres));

            // build the <key> element
            var keyElement = new XElement(Name,
                new XAttribute(IdAttributeName, securityParamteres.Id),
                new XAttribute(VersionAttributeName, 1),
                new XElement(CreationDateElementName, DateTimeOffset.Now),
                new XElement(ActivationDateElementName, DateTimeOffset.Now),
                new XElement(ExpirationDateElementName, DateTimeOffset.Now.AddDays(_options.Value.DaysUntilExpire)),
                new XElement(DescriptorElementName,
                    new XAttribute(DeserializerTypeAttributeName, typeof(SecurityKeyWithPrivate).AssemblyQualifiedName!),
                    possiblyEncryptedKeyElement));

            // Persist it to the underlying repository and trigger the cancellation token.
            var friendlyName = string.Format(CultureInfo.InvariantCulture, "key-{0}-{1:D}", securityParamteres.JwkType.ToString(), securityParamteres.KeyId);
            KeyRepository.StoreElement(keyElement, friendlyName);

        }

        private void Check()
        {
            KeyRepository = _keyManagementOptions.Value.XmlRepository;
            if (KeyRepository == null)
            {
                KeyRepository = GetFallbackKeyRepositoryEncryptorPair();
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
                    var descriptorElement = element.Element(DescriptorElementName);
                    // Decrypt the descriptor element and pass it to the descriptor for consumption
                    var unencryptedInputToDeserializer = _dataProtector.Unprotect(descriptorElement.Value);
                    var key = JsonSerializer.Deserialize<SecurityKeyWithPrivate>(unencryptedInputToDeserializer);
                    // IXmlRepository doesn't allow us to update. So remove from Get to prevent errors
                    if (key.IsExpired(_options.Value.DaysUntilExpire))
                        key.SetParameters();

                    keys.Add(key);
                }
            }

            return keys.OrderByDescending(o => o.CreationDate);
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
            var current = GetCurrentKey(jsonWebKeyType);
            if (current == null)
                return true;

            return current.CreationDate.AddDays(_options.Value.DaysUntilExpire) < DateTime.UtcNow.Date;
        }

        public void Update(SecurityKeyWithPrivate securityKeyWithPrivate)
        {

        }

        /// <summary>
        /// https://github.com/dotnet/aspnetcore/blob/d8906c8523f071371ce95d4e2d2fdfa89858047e/src/DataProtection/DataProtection/src/KeyManagement/XmlKeyManager.cs#L105
        /// </summary>
        /// <returns></returns>
        internal IXmlRepository GetFallbackKeyRepositoryEncryptorPair()
        {
            IXmlRepository key;
            var forAzureWebSites = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectoryForAzureWebSites();
            if (forAzureWebSites != null)
            {
                key = new FileSystemXmlRepository(forAzureWebSites, this._loggerFactory);
            }
            else
            {
                var storageDirectory = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectory();
                if (storageDirectory != null)
                {
                    key = new FileSystemXmlRepository(storageDirectory, this._loggerFactory);
                }
                else
                {
                    RegistryKey registryKey = null;
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        registryKey = RegistryXmlRepository.DefaultRegistryKey;

                    if (registryKey != null)
                    {
                        var defaultRegistryKey = RegistryXmlRepository.DefaultRegistryKey;
                        key = new RegistryXmlRepository(defaultRegistryKey, this._loggerFactory);
                    }
                    else
                    {
                        throw new Exception(
                            "Is not possible to determine which folder are the protection keys. NetDevPack.Security.JwtSigningCredentials.Store.FileSystem or NetDevPack.Security.JwtSigningCredentials.Store.EntityFrameworkCore");
                    }
                }
            }
            return key;
        }


    }


}
