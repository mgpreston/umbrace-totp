using System.Diagnostics.CodeAnalysis;
using System.Text;

using Umbrace.Totp.Internal;

namespace Umbrace.Totp;

/// <summary>
/// Represents an otpauth URI for provisioning HOTP credentials into authenticator apps.
/// </summary>
/// <remarks>
/// The URI format is defined by the
/// <see href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">Key Uri Format</see>
/// specification used by Google Authenticator and compatible apps.
/// </remarks>
public sealed class HotpUri
{
    private const string OtpAuthScheme = "otpauth";
    private const string HotpType = "hotp";

    private readonly byte[] _secret;

    /// <summary>The account name (e.g. <c>alice@example.com</c>).</summary>
    public string AccountName { get; }

    /// <summary>
    /// The issuer name (e.g. <c>"Example Corp"</c>), or <see langword="null"/> when absent.
    /// </summary>
    public string? Issuer { get; }

    /// <summary>The raw shared secret bytes.</summary>
    public ReadOnlyMemory<byte> Secret => _secret;

    /// <summary>The HMAC algorithm. Default: <see cref="OtpAlgorithm.Sha1"/>.</summary>
    public OtpAlgorithm Algorithm { get; }

    /// <summary>Number of OTP digits (6, 7, or 8). Default: 6.</summary>
    public int Digits { get; }

    /// <summary>
    /// The initial HOTP counter value. Default: 0.
    /// Per the Key Uri Format specification, the <c>counter</c> parameter is required for HOTP
    /// URIs and is always included in the serialised form, even when zero.
    /// </summary>
    public long Counter { get; }

    /// <summary>Creates a new <see cref="HotpUri"/>.</summary>
    /// <param name="accountName">Account name (e.g. <c>alice@example.com</c>). Must not be empty.</param>
    /// <param name="secret">Raw shared secret bytes. Must not be empty.</param>
    /// <param name="counter">The initial HOTP counter value. Default: 0.</param>
    /// <param name="issuer">Optional issuer name (e.g. <c>"Example Corp"</c>).</param>
    /// <param name="algorithm">HMAC algorithm. Default: <see cref="OtpAlgorithm.Sha1"/>.</param>
    /// <param name="digits">OTP digit count (6, 7, or 8). Default: 6.</param>
    public HotpUri(
        string accountName,
        ReadOnlySpan<byte> secret,
        long counter = 0,
        string? issuer = null,
        OtpAlgorithm algorithm = OtpAlgorithm.Sha1,
        int digits = 6)
    {
        ArgumentException.ThrowIfNullOrEmpty(accountName);
        if (secret.IsEmpty)
            throw new ArgumentException("Secret must not be empty.", nameof(secret));
        ArgumentOutOfRangeException.ThrowIfLessThan(digits, 6);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digits, 8);

        AccountName = accountName;
        _secret = secret.ToArray();
        Counter = counter;
        Issuer = issuer;
        Algorithm = algorithm;
        Digits = digits;
    }

    /// <summary>Returns the URI as a <see cref="Uri"/> instance.</summary>
    public Uri ToUri() => new(BuildString(), UriKind.Absolute);

    /// <summary>Returns the URI string.</summary>
    public override string ToString() => BuildString();

    /// <summary>
    /// Returns an <see cref="HotpOptions"/> populated from this URI's algorithm and digits.
    /// </summary>
    public HotpOptions ToHotpOptions() => new() { Algorithm = Algorithm, Digits = Digits };

    /// <summary>Parses an otpauth URI string.</summary>
    /// <exception cref="FormatException">Thrown when the string is not a valid otpauth HOTP URI.</exception>
    public static HotpUri Parse(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return TryParse(uri, out HotpUri? result, out string? error)
            ? result
            : throw new FormatException(error);
    }

    /// <summary>
    /// Tries to parse an otpauth URI string.
    /// Returns <see langword="false"/> when the string is not a valid otpauth HOTP URI.
    /// </summary>
    public static bool TryParse(string uri, [NotNullWhen(true)] out HotpUri? result)
        => TryParse(uri, out result, out _);

    // ── Private helpers ───────────────────────────────────────────────────────

    private string BuildString()
    {
        // Encode once; reused in both the label and the issuer query parameter.
        string escapedAccount = Uri.EscapeDataString(AccountName);
        string? escapedIssuer = Issuer is not null ? Uri.EscapeDataString(Issuer) : null;

        var sb = new StringBuilder("otpauth://hotp/", 128);

        // Label: "issuer:account" or "account".
        if (escapedIssuer is not null)
            sb.Append(escapedIssuer).Append(':');
        sb.Append(escapedAccount);

        sb.Append("?secret=").Append(Base32.Encode(_secret));

        // Per the spec, issuer appears in both the label and the query string.
        if (escapedIssuer is not null)
            sb.Append("&issuer=").Append(escapedIssuer);

        // Omit parameters that equal their defaults to keep URIs short, except for
        // counter which the spec requires to always be present, even when zero.
        if (Algorithm != OtpAlgorithm.Sha1)
            sb.Append("&algorithm=").Append(FormatAlgorithm(Algorithm));
        if (Digits != 6)
            sb.Append("&digits=").Append(Digits);
        sb.Append("&counter=").Append(Counter);

        return sb.ToString();
    }

    private static bool TryParse(
        string uriString,
        [NotNullWhen(true)] out HotpUri? result,
        out string? error)
    {
        result = null;

        if (!Uri.TryCreate(uriString, UriKind.Absolute, out Uri? uri))
        {
            error = "Not a valid absolute URI.";
            return false;
        }

        if (!uri.Scheme.Equals(OtpAuthScheme, StringComparison.OrdinalIgnoreCase))
        {
            error = $"URI scheme must be '{OtpAuthScheme}', not '{uri.Scheme}'.";
            return false;
        }

        if (!uri.Host.Equals(HotpType, StringComparison.OrdinalIgnoreCase))
        {
            error = $"OTP type must be '{HotpType}', not '{uri.Host}'.";
            return false;
        }

        // AbsolutePath starts with '/'. Split on ':' before unescaping so that a
        // percent-encoded colon (%3A) in the issuer is not mistaken for a separator.
        ReadOnlySpan<char> rawLabel = uri.AbsolutePath.AsSpan().TrimStart('/');
        int colon = rawLabel.IndexOf(':');

        string? issuer;
        string accountName;
        if (colon >= 0)
        {
            issuer = Uri.UnescapeDataString(rawLabel[..colon].ToString());
            accountName = Uri.UnescapeDataString(rawLabel[(colon + 1)..].ToString());
        }
        else
        {
            issuer = null;
            accountName = Uri.UnescapeDataString(rawLabel.ToString());
        }

        if (string.IsNullOrEmpty(accountName))
        {
            error = "Label must contain a non-empty account name.";
            return false;
        }

        // Parse query parameters inline using spans for keys to avoid Dictionary and key-string allocations.
        // Only values for the five known parameters are ever converted to strings; unknown parameters are skipped.
        // Base32, algorithm, digits, and counter are ASCII-only; only issuer may need percent-decoding.
        string? secretStr = null, algorithmStr = null, digitsStr = null, counterStr = null, issuerParam = null;
        ReadOnlySpan<char> querySpan = uri.Query.AsSpan().TrimStart('?');
        while (!querySpan.IsEmpty)
        {
            int amp = querySpan.IndexOf('&');
            ReadOnlySpan<char> pair = amp >= 0 ? querySpan[..amp] : querySpan;
            querySpan = amp >= 0 ? querySpan[(amp + 1)..] : [];

            int eq = pair.IndexOf('=');
            if (eq < 0) continue;

            ReadOnlySpan<char> key = pair[..eq];
            ReadOnlySpan<char> rawValue = pair[(eq + 1)..];

            if (key.Equals("secret", StringComparison.OrdinalIgnoreCase) && secretStr is null)
                secretStr = rawValue.ToString();
            else if (key.Equals("algorithm", StringComparison.OrdinalIgnoreCase) && algorithmStr is null)
                algorithmStr = rawValue.ToString();
            else if (key.Equals("digits", StringComparison.OrdinalIgnoreCase) && digitsStr is null)
                digitsStr = rawValue.ToString();
            else if (key.Equals("counter", StringComparison.OrdinalIgnoreCase) && counterStr is null)
                counterStr = rawValue.ToString();
            else if (key.Equals("issuer", StringComparison.OrdinalIgnoreCase) && issuerParam is null)
                issuerParam = Uri.UnescapeDataString(rawValue.ToString());
        }

        // secret (required)
        if (string.IsNullOrEmpty(secretStr))
        {
            error = "Missing required 'secret' parameter.";
            return false;
        }

        int maxSecretLength = secretStr.Length * 5 / 8;
        Span<byte> secretBuf = maxSecretLength <= 128 ? stackalloc byte[maxSecretLength] : new byte[maxSecretLength];
        if (!Base32.TryDecode(secretStr, secretBuf, out int secretLength))
        {
            error = "Invalid Base32 in 'secret' parameter.";
            return false;
        }

        if (secretLength == 0)
        {
            error = "Secret must not be empty.";
            return false;
        }

        ReadOnlySpan<byte> secret = secretBuf[..secretLength];

        // algorithm (optional, default SHA1)
        var algorithm = OtpAlgorithm.Sha1;
        if (algorithmStr is not null && !TryParseAlgorithm(algorithmStr, out algorithm))
        {
            error = $"Unknown algorithm '{algorithmStr}'; expected SHA1, SHA256, or SHA512.";
            return false;
        }

        // digits (optional, default 6)
        int digits = 6;
        if (digitsStr is not null && (!int.TryParse(digitsStr, out digits) || digits is < 6 or > 8))
        {
            error = $"Invalid digits '{digitsStr}'; must be 6, 7, or 8.";
            return false;
        }

        // counter (optional per parse, defaults to 0; always emitted on serialisation)
        long counter = 0;
        if (counterStr is not null && !long.TryParse(counterStr, out counter))
        {
            error = $"Invalid counter '{counterStr}'; must be an integer.";
            return false;
        }

        // issuer query parameter overrides label prefix when present.
        if (!string.IsNullOrEmpty(issuerParam))
            issuer = issuerParam;

        result = new HotpUri(accountName, secret, counter, issuer, algorithm, digits);
        error = null;
        return true;
    }

    private static string FormatAlgorithm(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.Sha256 => "SHA256",
        OtpAlgorithm.Sha512 => "SHA512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    private static bool TryParseAlgorithm(string value, out OtpAlgorithm algorithm)
    {
        if (value.Equals("SHA1", StringComparison.OrdinalIgnoreCase))
        {
            algorithm = OtpAlgorithm.Sha1;
            return true;
        }

        if (value.Equals("SHA256", StringComparison.OrdinalIgnoreCase))
        {
            algorithm = OtpAlgorithm.Sha256;
            return true;
        }

        if (value.Equals("SHA512", StringComparison.OrdinalIgnoreCase))
        {
            algorithm = OtpAlgorithm.Sha512;
            return true;
        }

        algorithm = default;
        return false;
    }
}