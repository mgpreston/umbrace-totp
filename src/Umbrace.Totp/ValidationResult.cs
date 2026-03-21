namespace Umbrace.Totp;

/// <summary>
/// The result of a <see cref="TotpGenerator.ValidateCode"/> call.
/// </summary>
/// <remarks>
/// <para>
/// Implicitly converts to <see langword="bool"/>, so existing code that only needs a pass/fail
/// answer requires no changes:
/// <code>if (generator.ValidateCode(secret, code)) { … }</code>
/// </para>
/// <para>
/// When <see cref="IsValid"/> is <see langword="true"/>, <see cref="TimeStepMatched"/> and
/// <see cref="StepStartedAt"/> identify exactly which time step was accepted. Persist
/// <see cref="TimeStepMatched"/> server-side and reject any future validation that returns the
/// same value, preventing a valid code from being replayed within the acceptance window.
/// </para>
/// </remarks>
public readonly record struct ValidationResult
{
    /// <summary>
    /// <see langword="true"/> if the submitted code was valid; otherwise <see langword="false"/>.
    /// </summary>
    public bool IsValid { get; private init; }

    /// <summary>
    /// The time step counter (<c>T = floor((Unix time − T0) / X)</c>) for which the code was valid.
    /// Zero when <see cref="IsValid"/> is <see langword="false"/>.
    /// </summary>
    public long TimeStepMatched { get; private init; }

    /// <summary>
    /// The UTC instant at which the matched time step began.
    /// <c>default(DateTimeOffset)</c> when <see cref="IsValid"/> is <see langword="false"/>.
    /// </summary>
    public DateTimeOffset StepStartedAt { get; private init; }

    /// <summary>
    /// Implicitly converts to <see langword="bool"/> via <see cref="IsValid"/>,
    /// allowing use in boolean contexts without accessing the property explicitly.
    /// </summary>
    public static implicit operator bool(ValidationResult result) => result.IsValid;

    internal static ValidationResult Success(long step, DateTimeOffset startedAt) => new()
    {
        IsValid = true,
        TimeStepMatched = step,
        StepStartedAt = startedAt,
    };
}