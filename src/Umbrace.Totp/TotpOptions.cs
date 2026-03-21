namespace Umbrace.Totp;

/// <summary>
/// Immutable configuration for TOTP generation and validation.
/// Defaults match the recommendations in RFC 6238 Section 4.
/// </summary>
public sealed record TotpOptions
{
    /// <summary>
    /// Time step duration in seconds (X in RFC 6238 Section 4). Default: 30.
    /// Must be greater than zero.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to zero or a negative value.</exception>
    public int TimeStep
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, 0, nameof(TimeStep));
            field = value;
        }
    } = 30;

    /// <summary>
    /// Unix timestamp of the initial reference time T0 (default: 0 = Unix epoch).
    /// RFC 6238 Section 4 defines this as the Unix epoch (January 1, 1970 00:00:00 UTC).
    /// </summary>
    public long T0 { get; init; }

    /// <summary>
    /// Hash algorithm used for HMAC computation. Default: <see cref="OtpAlgorithm.Sha1"/>.
    /// RFC 6238 Section 1 additionally defines SHA-256 and SHA-512 as optional algorithms.
    /// </summary>
    public OtpAlgorithm Algorithm { get; init; } = OtpAlgorithm.Sha1;

    /// <summary>
    /// Number of digits in the generated OTP. Must be 6, 7, or 8 per RFC 6238 Section 5.3.
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

    /// <summary>Default options: 30-second step, Unix epoch (T0=0), SHA-1, 6 digits.</summary>
    public static TotpOptions Default { get; } = new();
}