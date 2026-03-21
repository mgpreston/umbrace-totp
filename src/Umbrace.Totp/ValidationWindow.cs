namespace Umbrace.Totp;

/// <summary>
/// Defines how many time steps to accept either side of the current step during validation,
/// to account for network delay and clock drift between client and server.
/// </summary>
/// <remarks>
/// The default value of this struct (<c>default(ValidationWindow)</c>) accepts only the current
/// time step, which is the strictest and most secure option. Use <see cref="Default"/> for the
/// RFC 6238 recommended drift tolerance of ±1 step.
/// </remarks>
public readonly record struct ValidationWindow
{
    /// <summary>
    /// Number of time steps before the current step to accept. Default: 0.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a negative value.</exception>
    public int LookBehind
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value, nameof(LookBehind));
            field = value;
        }
    }

    /// <summary>
    /// Number of time steps after the current step to accept. Default: 0.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a negative value.</exception>
    public int LookAhead
    {
        get;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value, nameof(LookAhead));
            field = value;
        }
    }

    /// <summary>
    /// RFC 6238 Section 5.2 recommended window: one step behind and one step ahead.
    /// With the default 30-second time step this tolerates up to ±30 seconds of clock drift.
    /// </summary>
    public static ValidationWindow Default { get; } = new() { LookBehind = 1, LookAhead = 1 };
}