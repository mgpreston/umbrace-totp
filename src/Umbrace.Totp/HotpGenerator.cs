using Umbrace.Totp.Internal;

namespace Umbrace.Totp;

/// <summary>
/// Generates and validates RFC 4226 HMAC-based One-Time Passwords (HOTP).
/// </summary>
/// <remarks>
/// <para>
/// This class is thread-safe. All configuration is immutable after construction.
/// The secret must be the raw key bytes; Base32 decoding (as used by authenticator apps)
/// is the caller's responsibility.
/// </para>
/// <para>
/// HOTP uses a monotonically increasing counter, unlike TOTP which derives the counter
/// from the current time. The caller is responsible for persisting the counter and advancing
/// it after each successful validation — see <see cref="HotpValidationResult.NextCounter"/>.
/// </para>
/// </remarks>
public sealed class HotpGenerator
{
    // Precomputed powers of 10 for digit-count modulus (indices 0-8).
    private static readonly int[] Pow10 = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];

    // Precomputed "D6"/"D7"/"D8" format strings for zero-padded integer formatting.
    private static readonly string[] StringFormats = ["", "", "", "", "", "", "D6", "D7", "D8"];

    /// <summary>
    /// The RFC 4226 Section 7.4 recommended lookahead window size to accommodate
    /// counter desynchronisation between client and server.
    /// </summary>
    public const int DefaultLookahead = 5;

    private readonly HotpOptions _options;

    /// <summary>Creates a generator with default RFC 4226 options.</summary>
    public HotpGenerator() : this(HotpOptions.Default) { }

    /// <summary>Creates a generator with the specified options.</summary>
    /// <param name="options">HOTP configuration.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    public HotpGenerator(HotpOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <summary>
    /// Generates an HOTP code for the given counter value.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <param name="counter">The HOTP counter value.</param>
    /// <returns>A zero-padded numeric string of length <see cref="HotpOptions.Digits"/>.</returns>
    public string GenerateCode(ReadOnlySpan<byte> secret, long counter) =>
        ComputeCode(secret, counter);

    /// <summary>
    /// Writes an HOTP code for the given counter value into a caller-provided
    /// <see cref="char"/> buffer, avoiding any heap allocation.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <param name="counter">The HOTP counter value.</param>
    /// <param name="destination">
    /// The buffer to write into. Must be at least <see cref="HotpOptions.Digits"/> characters wide.
    /// </param>
    /// <param name="charsWritten">
    /// When this method returns <see langword="true"/>, the number of characters written.
    /// When this method returns <see langword="false"/>, set to zero.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the destination was large enough and the code was written;
    /// <see langword="false"/> if the destination is too small.
    /// </returns>
    public bool TryGenerateCode(
        ReadOnlySpan<byte> secret,
        long counter,
        Span<char> destination,
        out int charsWritten)
    {
        if (destination.Length < _options.Digits)
        {
            charsWritten = 0;
            return false;
        }

        int code = HotpComputer.Compute(secret, counter, _options.Algorithm) % Pow10[_options.Digits];
        return code.TryFormat(destination, out charsWritten, StringFormats[_options.Digits]);
    }

    /// <summary>
    /// Writes an HOTP code for the given counter value into a caller-provided UTF-8
    /// <see cref="byte"/> buffer, avoiding any heap allocation.
    /// Suitable for writing directly to an HTTP response body or pipe.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <param name="counter">The HOTP counter value.</param>
    /// <param name="destination">
    /// The buffer to write into. Must be at least <see cref="HotpOptions.Digits"/> bytes wide.
    /// </param>
    /// <param name="bytesWritten">
    /// When this method returns <see langword="true"/>, the number of bytes written.
    /// When this method returns <see langword="false"/>, set to zero.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the destination was large enough and the code was written;
    /// <see langword="false"/> if the destination is too small.
    /// </returns>
    public bool TryGenerateCodeUtf8(
        ReadOnlySpan<byte> secret,
        long counter,
        Span<byte> destination,
        out int bytesWritten)
    {
        int digits = _options.Digits;
        if (destination.Length < digits)
        {
            bytesWritten = 0;
            return false;
        }

        int code = HotpComputer.Compute(secret, counter, _options.Algorithm) % Pow10[digits];

        // ASCII digits (0x30–0x39) have the same byte value as their char equivalents,
        // so we can write UTF-8 directly by decomposing the integer right-to-left.
        for (int i = digits - 1; i >= 0; i--)
        {
            destination[i] = (byte)('0' + code % 10);
            code /= 10;
        }

        bytesWritten = digits;
        return true;
    }

    /// <summary>
    /// Validates an HOTP code against a range of counter values starting at
    /// <paramref name="expectedCounter"/>.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes.</param>
    /// <param name="code">
    /// The code to validate. Must be numeric and have length equal to <see cref="HotpOptions.Digits"/>.
    /// </param>
    /// <param name="expectedCounter">
    /// The lowest counter value to check. This is typically the next unused counter value
    /// stored server-side.
    /// </param>
    /// <param name="lookahead">
    /// The number of additional counter steps to check beyond <paramref name="expectedCounter"/>,
    /// to accommodate counter desynchronisation. Must be non-negative.
    /// The code is checked for counter values
    /// <c>[expectedCounter, expectedCounter + lookahead]</c> (inclusive).
    /// RFC 4226 Section 7.4 recommends a value of <see cref="DefaultLookahead"/> (5).
    /// </param>
    /// <returns>
    /// An <see cref="HotpValidationResult"/> that implicitly converts to <see langword="bool"/>
    /// for simple pass/fail checks. When valid, <see cref="HotpValidationResult.NextCounter"/>
    /// must be persisted as the new <paramref name="expectedCounter"/> for the next call.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="lookahead"/> is negative.
    /// </exception>
    public HotpValidationResult ValidateCode(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<char> code,
        long expectedCounter,
        int lookahead = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(lookahead);

        if (code.Length != _options.Digits || !int.TryParse(code, out int codeValue))
            return default;

        int modulus = Pow10[_options.Digits];

        // Iterate the full window without early exit so timing does not reveal which counter matched.
        // Use bitwise & (not &&) to avoid short-circuit evaluation when recording the first match.
        bool matched = false;
        long matchedCounter = 0;
        for (int delta = 0; delta <= lookahead; delta++)
        {
            long candidateCounter = expectedCounter + delta;
            int candidate = HotpComputer.Compute(secret, candidateCounter, _options.Algorithm) % modulus;
            bool isMatch = (candidate == codeValue);
            if (isMatch & !matched) matchedCounter = candidateCounter;
            matched |= isMatch;
        }

        return matched ? HotpValidationResult.Success(matchedCounter) : default;
    }

    private string ComputeCode(ReadOnlySpan<byte> secret, long counter)
    {
        int raw = HotpComputer.Compute(secret, counter, _options.Algorithm);
        int code = raw % Pow10[_options.Digits];
        // ToString("D6"/"D7"/"D8") zero-pads in a single allocation.
        return code.ToString(StringFormats[_options.Digits]);
    }
}