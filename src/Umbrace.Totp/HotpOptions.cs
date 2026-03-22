namespace Umbrace.Totp;

/// <summary>
/// Immutable configuration for HOTP generation and validation.
/// Defaults match the recommendations in RFC 4226 Section 4.
/// </summary>
public sealed record HotpOptions
{
    /// <summary>
    /// Hash algorithm used for HMAC computation. Default: <see cref="OtpAlgorithm.Sha1"/>.
    /// RFC 4226 specifies SHA-1; SHA-256 and SHA-512 are also supported.
    /// </summary>
    public OtpAlgorithm Algorithm { get; init; } = OtpAlgorithm.Sha1;

    /// <summary>
    /// Number of digits in the generated OTP. Must be 6, 7, or 8 per RFC 4226 Section 5.3.
    /// Default: 6.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a value other than 6, 7, or 8.</exception>
    public int Digits
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 6, nameof(Digits));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 8, nameof(Digits));
            field = value;
        }
    } = 6;

    /// <summary>Default options: SHA-1, 6 digits.</summary>
    public static HotpOptions Default { get; } = new();
}