namespace NetDevPack.Security.Jwt.Core.Jwa;

public enum AlgorithmType
{
    /// <summary>
    /// RSA is one of the first public-key cryptosystems and is widely used for secure data transmission.
    /// The acronym RSA is the initial letters of the surnames of Ron Rivest, Adi Shamir, and Leonard Adleman,
    /// who publicly described the algorithm in 1977.
    /// </summary>
    RSA = 1,

    /// <summary>
    /// The Elliptic Curve Digital Signature Algorithm (ECDSA) [DSS] provides
    /// for the use of Elliptic Curve Cryptography, which is able to provide
    /// equivalent security to RSA cryptography but using shorter key sizes
    /// and with greater processing speed for many operations.  This means
    /// that ECDSA digital signatures will be substantially smaller in terms
    /// of length than equivalently strong RSA digital signatures.
    /// </summary>
    ECDsa = 2,

    /// <summary>
    /// Hash-based Message Authentication Codes (HMACs) enable one to use a
    /// secret plus a cryptographic hash function to generate a MAC.  This
    /// can be used to demonstrate that whoever generated the MAC was in
    /// possession of the MAC key.  The algorithm for implementing and
    /// validating HMACs is provided in RFC 2104 [RFC2104],
    /// </summary>
    HMAC = 3,
    AES = 4
}