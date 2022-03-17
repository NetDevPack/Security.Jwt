namespace NetDevPack.Security.Jwt.Core.Jwa;

/// <summary>
/// Jws will use Digital Signatures algorithms
/// Jwe will use Encryption algorithms
/// </summary>
public enum JwtType
{
    Jws = 1,
    Jwe = 2,
    Both = 3
}