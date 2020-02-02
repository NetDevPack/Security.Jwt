using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Jwks.SigningCredentialsManager.Store.FileSystem
{
    public class FileSystemStore : IKeyStore
    {
        private readonly IOptions<JwksOptions> _options;
        private readonly string _current;
        public DirectoryInfo KeysPath { get; }

        public FileSystemStore(DirectoryInfo keysPath, IOptions<JwksOptions> options)
        {
            _options = options;
            KeysPath = keysPath;
            _current = Path.Combine(KeysPath.FullName, "current.key");
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            if (!KeysPath.Exists)
                KeysPath.Create();

            // Datetime it's just to be easy searchable.
            if (File.Exists(_current))
                File.Copy(_current, Path.Combine(Path.GetDirectoryName(_current), $"old-{DateTime.Now:yyyy-MM-dd}-{Guid.NewGuid()}.key"));

            File.WriteAllText(_current, JsonConvert.SerializeObject(securityParamteres));
        }

        public bool NeedsUpdate()
        {
            return File.Exists(_current) && File.GetCreationTimeUtc(_current).AddDays(_options.Value.DaysUntilExpire) < DateTime.UtcNow.Date;
        }

        public SecurityKeyWithPrivate GetCurrentKey()
        {
            return GetKey(_current);
        }

        private SecurityKeyWithPrivate GetKey(string file)
        {
            if (!File.Exists(file)) throw new FileNotFoundException("Check configuration - cannot find auth key file: " + file);
            var keyParams = JsonConvert.DeserializeObject<SecurityKeyWithPrivate>(File.ReadAllText(file));
            return keyParams;

        }

        public IReadOnlyCollection<SecurityKeyWithPrivate> Get(int quantity = 5)
        {
            return
                KeysPath.GetFiles("*.key")
                    .OrderByDescending(s => s.CreationTime)
                    .Take(quantity)
                    .Select(s => s.FullName)
                    .Select(GetKey).ToList().AsReadOnly();
        }

        public void Clear()
        {
            if (KeysPath.Exists)
                foreach (var fileInfo in KeysPath.GetFiles("*.key"))
                {
                    fileInfo.Delete();
                }
        }
    }
}
