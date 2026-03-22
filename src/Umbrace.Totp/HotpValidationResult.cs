namespace Umbrace.Totp;

/// <summary>
/// The result of a <see cref="HotpGenerator.ValidateCode"/> call.
/// </summary>
/// <remarks>
/// <para>
/// Implicitly converts to <see langword="bool"/>, so simple pass/fail checks require no extra
/// property access:
/// <code>if (generator.ValidateCode(secret, code, counter)) { … }</code>
/// </para>
/// <para>
/// When <see cref="IsValid"/> is <see langword="true"/>, you <b>must</b> advance your stored
/// counter to <see cref="NextCounter"/> before persisting it. Failing to do so allows the same
/// code to be accepted again on the next call, undermining replay protection.
/// </para>
/// </remarks>
public readonly record struct HotpValidationResult
{
    /// <summary>
    /// <see langword="true"/> if the submitted code was valid; otherwise <see langword="false"/>.
    /// </summary>
    public bool IsValid { get; private init; }

    /// <summary>
    /// The counter value for which the submitted code was valid.
    /// Zero when <see cref="IsValid"/> is <see langword="false"/>.
    /// </summary>
    public long CounterMatched { get; private init; }

    /// <summary>
    /// The counter value that must be persisted after a successful validation
    /// (<see cref="CounterMatched"/> + 1). Pass this as the <c>expectedCounter</c>
    /// argument for the next <see cref="HotpGenerator.ValidateCode"/> call.
    /// Zero when <see cref="IsValid"/> is <see langword="false"/>.
    /// </summary>
    public long NextCounter => CounterMatched + 1;

    /// <summary>
    /// Implicitly converts to <see langword="bool"/> via <see cref="IsValid"/>,
    /// allowing use in boolean contexts without accessing the property explicitly.
    /// </summary>
    public static implicit operator bool(HotpValidationResult result) => result.IsValid;

    internal static HotpValidationResult Success(long counter) => new()
    {
        IsValid = true,
        CounterMatched = counter,
    };
}