namespace Umbrace.Totp;

/// <summary>
/// Hash algorithm used for HMAC computation as specified in RFC 6238 Section 1.
/// </summary>
public enum OtpAlgorithm
{
    /// <summary>HMAC-SHA-1 (20-byte output). Default per RFC 4226.</summary>
    Sha1 = 0,

    /// <summary>HMAC-SHA-256 (32-byte output). Optional per RFC 6238.</summary>
    Sha256 = 1,

    /// <summary>HMAC-SHA-512 (64-byte output). Optional per RFC 6238.</summary>
    Sha512 = 2,
}