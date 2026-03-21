using Umbrace.Totp.Internal;

namespace Umbrace.Totp;

/// <summary>
/// Generates and validates RFC 6238 Time-based One-Time Passwords (TOTP).
/// </summary>
/// <remarks>
/// This class is thread-safe. All configuration is immutable after construction.
/// The secret must be the raw key bytes; Base32 decoding (as used by authenticator apps)
/// is the caller's responsibility.
/// </remarks>
public sealed class TotpGenerator
{
    // Precomputed powers of 10 for digit-count modulus (indices 0-8).
    private static readonly int[] Pow10 = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];

    // Precomputed "D6"/"D7"/"D8" format strings for zero-padded integer formatting.
    private static readonly string[] StringFormats = ["", "", "", "", "", "", "D6", "D7", "D8"];

    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a generator with default RFC 6238 options using the system clock.</summary>
    public TotpGenerator() : this(TotpOptions.Default, TimeProvider.System) { }

    /// <summary>Creates a generator with the specified options using the system clock.</summary>
    public TotpGenerator(TotpOptions options) : this(options, TimeProvider.System) { }

    /// <summary>
    /// Creates a generator with the specified options and time provider.
    /// </summary>
    /// <param name="options">TOTP configuration.</param>
    /// <param name="timeProvider">Time provider used to determine the current time step.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="options"/> or <paramref name="timeProvider"/> is <see langword="null"/>.
    /// </exception>
    public TotpGenerator(TotpOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _options = options;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Generates a TOTP code for the current time.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <returns>
    /// A <see cref="GenerationResult"/> containing the code and step timing information.
    /// Implicitly converts to <see cref="string"/> for simple use.
    /// </returns>
    public GenerationResult GenerateCode(ReadOnlySpan<byte> secret)
    {
        long t = ComputeTimeStep(_timeProvider.GetUtcNow().ToUnixTimeSeconds());
        string code = ComputeCode(secret, t);
        DateTimeOffset startedAt = DateTimeOffset.FromUnixTimeSeconds(t * _options.TimeStep + _options.T0);
        return new GenerationResult
        {
            Code = code,
            StepStartedAt = startedAt,
            ExpiresAt = startedAt.AddSeconds(_options.TimeStep),
        };
    }

    /// <summary>
    /// Generates a TOTP code for a specific Unix timestamp (seconds since the Unix epoch).
    /// </summary>
    /// <param name="secret">The raw shared secret bytes.</param>
    /// <param name="unixTimeSeconds">The Unix timestamp in seconds.</param>
    /// <returns>
    /// A zero-padded numeric string of length <see cref="TotpOptions.Digits"/>.
    /// </returns>
    public string GenerateCodeForUnixTime(ReadOnlySpan<byte> secret, long unixTimeSeconds)
    {
        long t = ComputeTimeStep(unixTimeSeconds);
        return ComputeCode(secret, t);
    }

    /// <summary>
    /// Generates a TOTP code for an explicit time step counter value (the HOTP layer).
    /// </summary>
    /// <param name="secret">The raw shared secret bytes.</param>
    /// <param name="timeStep">
    /// The time step counter T as defined in RFC 6238:
    /// <c>T = floor((Unix time - T0) / X)</c>.
    /// </param>
    /// <returns>
    /// A zero-padded numeric string of length <see cref="TotpOptions.Digits"/>.
    /// </returns>
    public string GenerateCodeForTimeStep(ReadOnlySpan<byte> secret, long timeStep) =>
        ComputeCode(secret, timeStep);

    /// <summary>
    /// Writes a TOTP code for the current time into a caller-provided <see cref="char"/> buffer,
    /// avoiding any heap allocation.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <param name="destination">
    /// The buffer to write into. Must be at least <see cref="TotpOptions.Digits"/> characters wide.
    /// </param>
    /// <param name="charsWritten">
    /// When this method returns <see langword="true"/>, the number of characters written.
    /// When this method returns <see langword="false"/>, set to zero.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the destination was large enough and the code was written;
    /// <see langword="false"/> if the destination is too small.
    /// </returns>
    public bool TryGenerateCode(ReadOnlySpan<byte> secret, Span<char> destination, out int charsWritten)
    {
        if (destination.Length < _options.Digits)
        {
            charsWritten = 0;
            return false;
        }

        long t = ComputeTimeStep(_timeProvider.GetUtcNow().ToUnixTimeSeconds());
        int code = HotpComputer.Compute(secret, t, _options.Algorithm) % Pow10[_options.Digits];
        return code.TryFormat(destination, out charsWritten, StringFormats[_options.Digits]);
    }

    /// <summary>
    /// Writes a TOTP code for the current time into a caller-provided UTF-8 <see cref="byte"/> buffer,
    /// avoiding any heap allocation. Suitable for writing directly to an HTTP response body or pipe.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes (not Base32-encoded).</param>
    /// <param name="destination">
    /// The buffer to write into. Must be at least <see cref="TotpOptions.Digits"/> bytes wide.
    /// </param>
    /// <param name="bytesWritten">
    /// When this method returns <see langword="true"/>, the number of bytes written.
    /// When this method returns <see langword="false"/>, set to zero.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the destination was large enough and the code was written;
    /// <see langword="false"/> if the destination is too small.
    /// </returns>
    public bool TryGenerateCodeUtf8(ReadOnlySpan<byte> secret, Span<byte> destination, out int bytesWritten)
    {
        int digits = _options.Digits;
        if (destination.Length < digits)
        {
            bytesWritten = 0;
            return false;
        }

        long t = ComputeTimeStep(_timeProvider.GetUtcNow().ToUnixTimeSeconds());
        int code = HotpComputer.Compute(secret, t, _options.Algorithm) % Pow10[digits];

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
    /// Validates a TOTP code against the current time, accepting codes within the specified window.
    /// </summary>
    /// <param name="secret">The raw shared secret bytes.</param>
    /// <param name="code">
    /// The code to validate. Must be numeric and have length equal to <see cref="TotpOptions.Digits"/>.
    /// </param>
    /// <param name="window">
    /// The validation window specifying drift tolerance.
    /// Defaults to <c>default(ValidationWindow)</c> (LookBehind=0, LookAhead=0),
    /// which accepts only the current time step.
    /// Pass <see cref="ValidationWindow.Default"/> for the RFC 6238 recommended ±1 step tolerance.
    /// </param>
    /// <returns>
    /// A <see cref="ValidationResult"/> that implicitly converts to <see langword="bool"/> for
    /// simple pass/fail checks, and exposes <see cref="ValidationResult.TimeStepMatched"/> and
    /// <see cref="ValidationResult.StepStartedAt"/> for replay-attack prevention.
    /// </returns>
    public ValidationResult ValidateCode(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<char> code,
        ValidationWindow window = default)
    {
        if (code.Length != _options.Digits || !int.TryParse(code, out int codeValue))
            return default;

        long tNow = ComputeTimeStep(_timeProvider.GetUtcNow().ToUnixTimeSeconds());
        int modulus = Pow10[_options.Digits];

        // Iterate all steps without early return so timing does not reveal which step matched.
        // Use bitwise & (not &&) to avoid short-circuit evaluation when recording the first match.
        bool matched = false;
        long matchedStep = 0;
        for (var delta = -window.LookBehind; delta <= window.LookAhead; delta++)
        {
            long step = tNow + delta;
            int candidate = HotpComputer.Compute(secret, step, _options.Algorithm) % modulus;
            bool isMatch = (candidate == codeValue);
            if (isMatch & !matched) matchedStep = step;
            matched |= isMatch;
        }

        if (!matched) return default;

        DateTimeOffset startedAt = DateTimeOffset.FromUnixTimeSeconds(
            matchedStep * _options.TimeStep + _options.T0);
        return ValidationResult.Success(matchedStep, startedAt);
    }

    /// <summary>
    /// Returns the number of seconds remaining in the current time step.
    /// </summary>
    public int GetRemainingSeconds()
    {
        long now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        // Use a sign-safe modulo so the result is correct when now < T0.
        long step = _options.TimeStep;
        long elapsed = ((now - _options.T0) % step + step) % step;
        return _options.TimeStep - (int)elapsed;
    }

    // Floor division: unlike C# integer division (which truncates toward zero),
    // this returns the mathematically correct floor for negative dividends.
    // Relevant when unixTimeSeconds < T0 (e.g. a custom future T0 is configured).
    private long ComputeTimeStep(long unixTimeSeconds)
    {
        long q = Math.DivRem(unixTimeSeconds - _options.T0, _options.TimeStep, out long r);
        return r < 0 ? q - 1 : q;
    }

    private string ComputeCode(ReadOnlySpan<byte> secret, long timeStep)
    {
        int raw = HotpComputer.Compute(secret, timeStep, _options.Algorithm);
        int code = raw % Pow10[_options.Digits];
        // ToString("D6"/"D7"/"D8") zero-pads in a single allocation.
        return code.ToString(StringFormats[_options.Digits]);
    }
}