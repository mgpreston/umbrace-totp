namespace Umbrace.Totp;

/// <summary>
/// The result of a <see cref="TotpGenerator.GenerateCode"/> call, containing the generated code
/// and timing information for the current time step.
/// </summary>
/// <remarks>
/// <para>
/// The implicit conversion to <see cref="string"/> allows simple use without accessing
/// <see cref="Code"/> explicitly:
/// <code>
/// string code = generator.GenerateCode(secret);
/// </code>
/// </para>
/// <para>
/// Use <see cref="ExpiresAt"/> to drive a countdown timer, or <see cref="StepStartedAt"/>
/// for audit logging. Both are captured atomically during generation, so there is no
/// race condition between generating the code and reading the timing information.
/// </para>
/// </remarks>
public readonly record struct GenerationResult
{
    /// <summary>
    /// The generated TOTP code, zero-padded to <see cref="TotpOptions.Digits"/> digits.
    /// </summary>
    public string Code { get; init; }

    /// <summary>
    /// The UTC time at which the current time step started.
    /// </summary>
    public DateTimeOffset StepStartedAt { get; init; }

    /// <summary>
    /// The UTC time at which the current code expires (i.e. when the next time step begins).
    /// </summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Implicitly converts a <see cref="GenerationResult"/> to the generated code string,
    /// allowing direct assignment to a <see cref="string"/> variable.
    /// </summary>
    public static implicit operator string(GenerationResult result) => result.Code;
}