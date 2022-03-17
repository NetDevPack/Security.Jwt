using System.Runtime.InteropServices;

namespace NetDevPack.Security.Jwt.Core.DefaultStore;

/// <summary>
/// https://github.com/dotnet/aspnetcore/blob/d8906c8523f071371ce95d4e2d2fdfa89858047e/src/DataProtection/DataProtection/src/KeyManagement/XmlKeyManager.cs#L105
/// </summary>
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
        var folderPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
        var home = Environment.GetEnvironmentVariable("HOME");
        DirectoryInfo directoryInfo;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !string.IsNullOrEmpty(folderPath))
            directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(folderPath);
        else if (localAppData != null)
            directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(localAppData);
        else if (userProfile != null)
            directoryInfo = DefaultKeyStorageDirectories.GetKeyStorageDirectoryFromBaseAppDataPath(Path.Combine(userProfile, "AppData", "Local"));
        else if (home != null)
        {
            directoryInfo = new DirectoryInfo(Path.Combine(home, ".aspnet", "DataProtection-Keys"));
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