using NetDevPack.Security.Jwt.Core.Jwa;

namespace NetDevPack.Security.Jwt.Core;

public class JwtOptions
{
    public Algorithm Jws { get; set; } = Algorithm.Create(AlgorithmType.RSA, JwtType.Jws);
    public Algorithm Jwe { get; set; } = Algorithm.Create(AlgorithmType.RSA, JwtType.Jwe);
    public int DaysUntilExpire { get; set; } = 90;
    public string KeyPrefix { get; set; } = $"{Environment.MachineName}_";
    public int AlgorithmsToKeep { get; set; } = 2;
    public TimeSpan CacheTime { get; set; } = TimeSpan.FromMinutes(15);
}