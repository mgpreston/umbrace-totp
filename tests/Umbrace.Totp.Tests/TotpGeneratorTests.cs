using Microsoft.Extensions.Time.Testing;

namespace Umbrace.Totp.Tests;

public class TotpGeneratorTests
{
    // SHA-1 key from RFC 6238 Appendix B — convenient for cross-referencing expected values.
    private static readonly byte[] s_secret = "12345678901234567890"u8.ToArray();

    // ── Digit count ──────────────────────────────────────────────────────────

    [Test]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    public async Task GenerateCode_ProducesCorrectDigitCount(int digits)
    {
        var generator = new TotpGenerator(new TotpOptions { Digits = digits });
        string code = generator.GenerateCode(s_secret);
        await Assert.That(code.Length).IsEqualTo(digits);
    }

    [Test]
    public async Task GenerateCode_IsZeroPadded()
    {
        // RFC 6238 vector: time=1111111109, SHA-1, 8 digits → "07081804" (leading zero)
        var generator = new TotpGenerator(new TotpOptions { Digits = 8 });
        string code = generator.GenerateCodeForUnixTime(s_secret, 1111111109L);
        await Assert.That(code).IsEqualTo("07081804");
    }

    // ── TimeProvider injection ────────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_UsesFakeTime()
    {
        // Verify the generator honours the injected clock using a known RFC 6238 vector.
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var options = new TotpOptions { Algorithm = OtpAlgorithm.Sha1, Digits = 8 };
        var generator = new TotpGenerator(options, fakeTime);

        string code = generator.GenerateCode(s_secret);

        await Assert.That(code).IsEqualTo("94287082");
    }

    // ── Validation — current step ─────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_AcceptsCurrentStep()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);
        string code = generator.GenerateCode(s_secret);

        bool result = generator.ValidateCode(s_secret, code);

        await Assert.That(result).IsTrue();
    }

    [Test]
    public async Task ValidateCode_RejectsWrongCode_ForCurrentStep()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        bool result = generator.ValidateCode(s_secret, "000000");

        await Assert.That(result).IsFalse();
    }

    // ── Validation — window ───────────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_AcceptsPreviousStep_WithLookBehind()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        // Generate at step N
        string oldCode = generator.GenerateCode(s_secret);

        // Advance to step N+1
        fakeTime.Advance(TimeSpan.FromSeconds(30));

        bool result = generator.ValidateCode(s_secret, oldCode, ValidationWindow.Default);
        await Assert.That(result).IsTrue();
    }

    [Test]
    public async Task ValidateCode_RejectsPreviousStep_WithDefaultWindow()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        string oldCode = generator.GenerateCode(s_secret);
        fakeTime.Advance(TimeSpan.FromSeconds(30));

        // default(ValidationWindow) = current step only
        bool result = generator.ValidateCode(s_secret, oldCode);
        await Assert.That(result).IsFalse();
    }

    [Test]
    public async Task ValidateCode_AcceptsFutureStep_WithLookAhead()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        // Generate code for the next step (1030 falls in step N+1)
        string futureCode = generator.GenerateCodeForUnixTime(s_secret, 1030);

        var window = new ValidationWindow { LookAhead = 1 };
        bool result = generator.ValidateCode(s_secret, futureCode, window);

        await Assert.That(result).IsTrue();
    }

    [Test]
    public async Task ValidateCode_RejectsCodeTooFarInPast()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        // Code from step N-2 (940s → step 31, current is step 33)
        string oldCode = generator.GenerateCodeForUnixTime(s_secret, 940);

        bool result = generator.ValidateCode(s_secret, oldCode, ValidationWindow.Default);
        await Assert.That(result).IsFalse();
    }

    [Test]
    public async Task ValidateCode_AsymmetricWindow_OnlyLooksBehind()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        string previousCode = generator.GenerateCodeForUnixTime(s_secret, 970); // step N-1
        string futureCode = generator.GenerateCodeForUnixTime(s_secret, 1030); // step N+1

        var window = new ValidationWindow { LookBehind = 1, LookAhead = 0 };

        await Assert.That(generator.ValidateCode(s_secret, previousCode, window).IsValid).IsTrue();
        await Assert.That(generator.ValidateCode(s_secret, futureCode, window).IsValid).IsFalse();
    }

    // ── ValidationWindow guards ───────────────────────────────────────────────

    [Test]
    public async Task ValidationWindow_ThrowsForNegativeLookBehind()
    {
        await Assert.That(() => new ValidationWindow { LookBehind = -1 })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task ValidationWindow_ThrowsForNegativeLookAhead()
    {
        await Assert.That(() => new ValidationWindow { LookAhead = -1 })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── Validation — input guards ─────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_ReturnsFalse_ForWrongLength()
    {
        var generator = new TotpGenerator(); // 6-digit default
        await Assert.That(generator.ValidateCode(s_secret, "12345").IsValid).IsFalse();   // 5 chars
        await Assert.That(generator.ValidateCode(s_secret, "1234567").IsValid).IsFalse(); // 7 chars
    }

    [Test]
    public async Task ValidateCode_ReturnsFalse_ForNonNumeric()
    {
        var generator = new TotpGenerator();
        await Assert.That(generator.ValidateCode(s_secret, "abc123").IsValid).IsFalse();
    }

    // ── GetRemainingSeconds ───────────────────────────────────────────────────

    [Test]
    public async Task GetRemainingSeconds_ReturnsExpectedValue()
    {
        // T=1015: elapsed = 1015 % 30 = 25, remaining = 30 - 25 = 5
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1015));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        await Assert.That(generator.GetRemainingSeconds()).IsEqualTo(5);
    }

    [Test]
    public async Task GetRemainingSeconds_IsWithinTimeStepBounds()
    {
        var generator = new TotpGenerator();
        int remaining = generator.GetRemainingSeconds();
        await Assert.That(remaining).IsGreaterThan(0);
        await Assert.That(remaining).IsLessThanOrEqualTo(30);
    }

    // ── TryGenerateCode ───────────────────────────────────────────────────────

    [Test]
    public async Task TryGenerateCode_WritesCorrectCode()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var generator = new TotpGenerator(new TotpOptions { Digits = 8 }, fakeTime);
        var buffer = new char[8];

        bool result = generator.TryGenerateCode(s_secret, buffer, out int charsWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(charsWritten).IsEqualTo(8);
        await Assert.That(new string(buffer)).IsEqualTo("94287082");
    }

    [Test]
    public async Task TryGenerateCode_ReturnsFalse_WhenBufferTooSmall()
    {
        var generator = new TotpGenerator();
        var buffer = new char[5]; // needs 6

        bool result = generator.TryGenerateCode(s_secret, buffer, out int charsWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(charsWritten).IsEqualTo(0);
    }

    // ── TryGenerateCodeUtf8 ───────────────────────────────────────────────────

    [Test]
    public async Task TryGenerateCodeUtf8_WritesCorrectCode()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var generator = new TotpGenerator(new TotpOptions { Digits = 8 }, fakeTime);
        var buffer = new byte[8];

        bool result = generator.TryGenerateCodeUtf8(s_secret, buffer, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(8);
        await Assert.That(System.Text.Encoding.UTF8.GetString(buffer)).IsEqualTo("94287082");
    }

    [Test]
    public async Task TryGenerateCodeUtf8_ReturnsFalse_WhenBufferTooSmall()
    {
        var generator = new TotpGenerator();
        var buffer = new byte[5]; // needs 6

        bool result = generator.TryGenerateCodeUtf8(s_secret, buffer, out int bytesWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryGenerateCodeUtf8_MatchesGenerateCode()
    {
        // Verify TryGenerateCodeUtf8 produces the same digits as GenerateCode across all algorithms.
        // Use a plain array rather than stackalloc — Span<T> cannot live across await boundaries.
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var buffer = new byte[6];

        foreach (OtpAlgorithm algorithm in Enum.GetValues<OtpAlgorithm>())
        {
            var generator = new TotpGenerator(new TotpOptions { Digits = 6, Algorithm = algorithm }, fakeTime);

            string expected = generator.GenerateCode(s_secret).Code;
            generator.TryGenerateCodeUtf8(s_secret, buffer, out _);

            await Assert.That(System.Text.Encoding.UTF8.GetString(buffer)).IsEqualTo(expected);
        }
    }

    // ── GenerationResult ──────────────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_Result_ReturnsStepStartedAt()
    {
        // t=1000 → step = floor(1000/30) = 33, step start = 33*30 = 990
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        GenerationResult result = generator.GenerateCode(s_secret);

        await Assert.That(result.StepStartedAt).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(990));
    }

    [Test]
    public async Task GenerateCode_Result_ReturnsExpiresAt()
    {
        // t=1000 → step start=990, expires at 990+30=1020
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        GenerationResult result = generator.GenerateCode(s_secret);

        await Assert.That(result.ExpiresAt).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1020));
    }

    [Test]
    public async Task GenerateCode_Result_ImplicitStringConversion()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(59));
        var options = new TotpOptions { Algorithm = OtpAlgorithm.Sha1, Digits = 8 };
        var generator = new TotpGenerator(options, fakeTime);

        // Implicit operator string allows direct assignment without accessing .Code.
        string code = generator.GenerateCode(s_secret);

        await Assert.That(code).IsEqualTo("94287082");
    }

    // ── Invalid algorithm ─────────────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_ThrowsForInvalidAlgorithm()
    {
        var generator = new TotpGenerator(new TotpOptions { Algorithm = (OtpAlgorithm)99 });
        await Assert.That(() => generator.GenerateCode(s_secret))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── TotpOptions validation ────────────────────────────────────────────────

    [Test]
    public async Task TotpOptions_ThrowsForZeroTimeStep()
    {
        await Assert.That(() => new TotpOptions { TimeStep = 0 })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task TotpOptions_ThrowsForNegativeTimeStep()
    {
        await Assert.That(() => new TotpOptions { TimeStep = -1 })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(5)]
    [Arguments(9)]
    public async Task TotpOptions_ThrowsForInvalidDigits(int digits)
    {
        await Assert.That(() => new TotpOptions { Digits = digits })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── GenerateCodeForTimeStep ───────────────────────────────────────────────

    [Test]
    public async Task GenerateCodeForTimeStep_MatchesDirectCounterValue()
    {
        // At unixTime=59, T = floor(59/30) = 1; SHA-1 8-digit RFC vector = "94287082"
        var generator = new TotpGenerator(new TotpOptions { Digits = 8 });
        string code = generator.GenerateCodeForTimeStep(s_secret, 1L);
        await Assert.That(code).IsEqualTo("94287082");
    }

    // ── Custom T0 and TimeStep ────────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_BeforeT0_UsesFloorDivision()
    {
        // When unixTime < T0, C# integer division truncates toward zero, but TOTP
        // requires floor division. T0=100, unixTime=50: dividend = -50.
        // Math.DivRem(-50, 30) → q=-1, r=-20; floor = q-1 = -2.
        // This exercises the r < 0 branch in ComputeTimeStep.
        var gen = new TotpGenerator(new TotpOptions { T0 = 100 });
        string codeViaUnixTime = gen.GenerateCodeForUnixTime(s_secret, 50);
        string codeViaTimeStep = gen.GenerateCodeForTimeStep(s_secret, -2L);
        await Assert.That(codeViaUnixTime).IsEqualTo(codeViaTimeStep);
    }

    [Test]
    public async Task GenerateCode_RespectsCustomT0()
    {
        // With T0=30, unixTime=59: T = floor((59-30)/30) = floor(0.96) = 0
        // With T0=0,  unixTime=59: T = floor(59/30) = 1
        // The codes should differ.
        byte[] secret = s_secret;

        var defaultGen = new TotpGenerator(new TotpOptions { Digits = 8 });
        var customGen = new TotpGenerator(new TotpOptions { Digits = 8, T0 = 30 });

        string defaultCode = defaultGen.GenerateCodeForUnixTime(secret, 59);
        string customCode = customGen.GenerateCodeForUnixTime(secret, 59);

        await Assert.That(defaultCode).IsNotEqualTo(customCode);
    }

    [Test]
    public async Task GenerateCode_RespectsCustomTimeStep()
    {
        // With 60-second step, unixTime=59: T = floor(59/60) = 0
        // With 30-second step, unixTime=59: T = floor(59/30) = 1
        var gen30 = new TotpGenerator(new TotpOptions { Digits = 8, TimeStep = 30 });
        var gen60 = new TotpGenerator(new TotpOptions { Digits = 8, TimeStep = 60 });

        string code30 = gen30.GenerateCodeForUnixTime(s_secret, 59);
        string code60 = gen60.GenerateCodeForUnixTime(s_secret, 59);

        await Assert.That(code30).IsNotEqualTo(code60);
    }

    // ── ValidationResult ──────────────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_Result_ReturnsCurrentStep()
    {
        // t=1000 → step = floor(1000/30) = 33, step start = 33*30 = 990
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);
        string code = generator.GenerateCode(s_secret);

        ValidationResult result = generator.ValidateCode(s_secret, code);

        await Assert.That(result.IsValid).IsTrue();
        await Assert.That(result.TimeStepMatched).IsEqualTo(33L);
        await Assert.That(result.StepStartedAt).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(990));
    }

    [Test]
    public async Task ValidateCode_Result_ReturnsPreviousStep()
    {
        // Generate code at step 33 (t=1000), advance to step 34 (t=1030).
        // Validating the old code with LookBehind=1 should report step 33, start=990.
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);
        string oldCode = generator.GenerateCode(s_secret);

        fakeTime.Advance(TimeSpan.FromSeconds(30)); // now at t=1030, step 34

        ValidationResult result = generator.ValidateCode(s_secret, oldCode, ValidationWindow.Default);

        await Assert.That(result.IsValid).IsTrue();
        await Assert.That(result.TimeStepMatched).IsEqualTo(33L);
        await Assert.That(result.StepStartedAt).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(990));
    }

    [Test]
    public async Task ValidateCode_Result_IsDefaultOnFailure()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);

        ValidationResult result = generator.ValidateCode(s_secret, "000000");

        await Assert.That(result.IsValid).IsFalse();
        await Assert.That(result.TimeStepMatched).IsEqualTo(0L);
        await Assert.That(result.StepStartedAt).IsEqualTo(default(DateTimeOffset));
    }

    [Test]
    public async Task ValidateCode_Result_ImplicitBoolConversion()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1000));
        var generator = new TotpGenerator(TotpOptions.Default, fakeTime);
        string code = generator.GenerateCode(s_secret);

        // The implicit operator bool allows use without accessing .IsValid explicitly.
        bool valid = generator.ValidateCode(s_secret, code);
        await Assert.That(valid).IsTrue();
    }


}