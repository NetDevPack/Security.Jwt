using System;
using System.IO;
using System.Runtime.InteropServices;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    internal sealed class DefaultKeyStorageDirectories
    {
        private static readonly Lazy<DirectoryInfo> _defaultDirectoryLazy = new Lazy<DirectoryInfo>(new Func<DirectoryInfo>(DefaultKeyStorageDirectories.GetKeyStorageDirectoryImpl));
        private const string DataProtectionKeysFolderName = "DataProtection-Keys";

        private DefaultKeyStorageDirectories()
        {
        }

        public static DefaultKeyStorageDirectories Instance { get; } = new DefaultKeyStorageDirectories();

        public DirectoryInfo GetKeyStorageDirectory() => DefaultKeyStorageDirectories._defaultDirectoryLazy.Value;

        private static DirectoryInfo GetKeyStorageDirectoryImpl()
        {
            string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string environmentVariable1 = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            string environmentVariable2 = Environment.GetEnvironmentVariable("USERPROFILE");
            string environmentVariable3 = Environment.GetEnvironmentVariable("HOME");
            DirectoryInfo directoryInfo;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !string.IsNullOrEmpty(folderPath))
                directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(folderPath);
            else if (environmentVariable1 != null)
                directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(environmentVariable1);
            else if (environmentVariable2 != null)
                directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(Path.Combine(environmentVariable2, "AppData", "Local"));
            else if (environmentVariable3 != null)
            {
                directoryInfo = new DirectoryInfo(Path.Combine(environmentVariable3, ".aspnet", "DataProtection-Keys"));
            }
            else
            {
                if (string.IsNullOrEmpty(folderPath))
                    return (DirectoryInfo)null;
                directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(folderPath);
            }
            try
            {
                directoryInfo.Create();
                return directoryInfo;
            }
            catch
            {
                return (DirectoryInfo)null;
            }
        }

        public DirectoryInfo GetKeyStorageDirectoryForAzureWebSites()
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")))
            {
                string environmentVariable = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(environmentVariable))
                    return DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(environmentVariable);
            }
            return (DirectoryInfo)null;
        }

        private static DirectoryInfo GetKeyStorageDirectoryFromBaseAppDataPath(
          string basePath)
        {
            return new DirectoryInfo(Path.Combine(basePath, "ASP.NET", "DataProtection-Keys"));
        }
    }
}
