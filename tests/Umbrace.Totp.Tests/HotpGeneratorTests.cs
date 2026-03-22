namespace Umbrace.Totp.Tests;

public class HotpGeneratorTests
{
    // RFC 4226 Appendix D secret key (20-byte ASCII).
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();

    // ── Digit count ───────────────────────────────────────────────────────────

    [Test]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    public async Task GenerateCode_ProducesCorrectDigitCount(int digits)
    {
        // Exact length == digits confirms that zero-padding is applied for small raw values.
        var gen = new HotpGenerator(new HotpOptions { Digits = digits });
        string code = gen.GenerateCode(Secret, 0);
        await Assert.That(code.Length).IsEqualTo(digits);
    }

    [Test]
    public async Task GenerateCode_IsZeroPadded()
    {
        // RFC 4226 vector: counter=1, SHA-1, 6 digits → "287082".
        // Request 8-digit mode: if the truncated value mod 10^8 is < 10^7,
        // the format "D8" must supply the leading zeros.
        // Verify the output is always exactly 8 digits to confirm zero-padding.
        var gen = new HotpGenerator(new HotpOptions { Digits = 8 });
        foreach (var vector in HotpRfcVectorTests.GetVectors())
        {
            string code = gen.GenerateCode(Secret, vector.Counter);
            await Assert.That(code.Length).IsEqualTo(8);
        }
    }

    // ── DefaultLookahead constant ─────────────────────────────────────────────

    [Test]
    public async Task DefaultLookahead_IsEqualTo5()
    {
        int lookahead = HotpGenerator.DefaultLookahead;
        await Assert.That(lookahead).IsEqualTo(5);
    }

    // ── Lookahead window ──────────────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_AcceptsCodeAtExactCounter()
    {
        // RFC vector counter=0: "755224"
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "755224", expectedCounter: 0);
        await Assert.That(result.IsValid).IsTrue();
    }

    [Test]
    public async Task ValidateCode_AcceptsCodeWithinLookaheadWindow()
    {
        // RFC vector counter=3: "969429"; expectedCounter=0, lookahead=5 → window [0..5]
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "969429", expectedCounter: 0, lookahead: 5);
        await Assert.That(result.IsValid).IsTrue();
    }

    [Test]
    public async Task ValidateCode_RejectsCodeBeyondLookaheadWindow()
    {
        // RFC vector counter=6: "287922"; expectedCounter=0, lookahead=5 → window [0..5], counter=6 is out
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "287922", expectedCounter: 0, lookahead: 5);
        await Assert.That(result.IsValid).IsFalse();
    }

    [Test]
    public async Task ValidateCode_RejectsCodeBelowExpectedCounter()
    {
        // HOTP is strictly forward-only — no lookbehind.
        // RFC vector counter=0: "755224"; expectedCounter=1 → counter 0 is below window.
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "755224", expectedCounter: 1, lookahead: 5);
        await Assert.That(result.IsValid).IsFalse();
    }

    [Test]
    public async Task ValidateCode_ZeroLookahead_AcceptsExactCounterOnly()
    {
        var gen = new HotpGenerator();
        // exact match
        await Assert.That(gen.ValidateCode(Secret, "755224", expectedCounter: 0, lookahead: 0).IsValid).IsTrue();
        // counter=1 code rejected when expected=0 and lookahead=0
        await Assert.That(gen.ValidateCode(Secret, "287082", expectedCounter: 0, lookahead: 0).IsValid).IsFalse();
    }

    [Test]
    public async Task ValidateCode_ThrowsForNegativeLookahead()
    {
        var gen = new HotpGenerator();
        await Assert.That(() => gen.ValidateCode(Secret, "755224", 0, lookahead: -1))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── CounterMatched and NextCounter ────────────────────────────────────────

    [Test]
    public async Task ValidateCode_CounterMatched_ReturnsActualMatchedCounter()
    {
        // Code for counter=3 submitted with expectedCounter=0, lookahead=5.
        // CounterMatched must be 3 (not 0).
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "969429", expectedCounter: 0, lookahead: 5);
        await Assert.That(result.CounterMatched).IsEqualTo(3L);
    }

    [Test]
    public async Task ValidateCode_NextCounter_IsCounterMatchedPlusOne()
    {
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "969429", expectedCounter: 0, lookahead: 5);
        await Assert.That(result.NextCounter).IsEqualTo(result.CounterMatched + 1);
        await Assert.That(result.NextCounter).IsEqualTo(4L);
    }

    [Test]
    public async Task ValidateCode_IsDefaultOnFailure()
    {
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "000000", expectedCounter: 0);
        await Assert.That(result.IsValid).IsFalse();
        await Assert.That(result.CounterMatched).IsEqualTo(0L);
        await Assert.That(result.NextCounter).IsEqualTo(1L); // CounterMatched(0) + 1; only meaningful when IsValid
    }

    [Test]
    public async Task ValidateCode_ImplicitBoolConversion()
    {
        var gen = new HotpGenerator();
        bool valid = gen.ValidateCode(Secret, "755224", expectedCounter: 0);
        await Assert.That(valid).IsTrue();
    }

    // ── Constant-time: far end of window ─────────────────────────────────────

    [Test]
    public async Task ValidateCode_ConstantTime_FindsCodeAtFarEndOfWindow()
    {
        // RFC vector counter=9: "520489". Submit with expectedCounter=4, lookahead=5 → window [4..9].
        // The code lies at delta=5 (the last iteration); constant-time iteration must still find it.
        var gen = new HotpGenerator();
        HotpValidationResult result = gen.ValidateCode(Secret, "520489", expectedCounter: 4, lookahead: 5);
        await Assert.That(result.IsValid).IsTrue();
        await Assert.That(result.CounterMatched).IsEqualTo(9L);
    }

    // ── TryGenerateCode ───────────────────────────────────────────────────────

    [Test]
    public async Task TryGenerateCode_WritesCorrectCode()
    {
        // RFC 4226 vector counter=0: "755224"
        var gen = new HotpGenerator();
        var buffer = new char[6];

        bool result = gen.TryGenerateCode(Secret, 0, buffer, out int charsWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(charsWritten).IsEqualTo(6);
        await Assert.That(new string(buffer)).IsEqualTo("755224");
    }

    [Test]
    public async Task TryGenerateCode_ReturnsFalse_WhenBufferTooSmall()
    {
        var gen = new HotpGenerator();
        var buffer = new char[5]; // needs 6

        bool result = gen.TryGenerateCode(Secret, 0, buffer, out int charsWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(charsWritten).IsEqualTo(0);
    }

    // ── TryGenerateCodeUtf8 ───────────────────────────────────────────────────

    [Test]
    public async Task TryGenerateCodeUtf8_WritesCorrectCode()
    {
        // RFC 4226 vector counter=0: "755224"
        var gen = new HotpGenerator();
        var buffer = new byte[6];

        bool result = gen.TryGenerateCodeUtf8(Secret, 0, buffer, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(6);
        await Assert.That(System.Text.Encoding.UTF8.GetString(buffer)).IsEqualTo("755224");
    }

    [Test]
    public async Task TryGenerateCodeUtf8_ReturnsFalse_WhenBufferTooSmall()
    {
        var gen = new HotpGenerator();
        var buffer = new byte[5]; // needs 6

        bool result = gen.TryGenerateCodeUtf8(Secret, 0, buffer, out int bytesWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryGenerateCodeUtf8_MatchesGenerateCode()
    {
        // Verify TryGenerateCodeUtf8 produces the same digits as GenerateCode across all algorithms.
        var buffer = new byte[6];

        foreach (OtpAlgorithm algorithm in Enum.GetValues<OtpAlgorithm>())
        {
            var gen = new HotpGenerator(new HotpOptions { Digits = 6, Algorithm = algorithm });

            string expected = gen.GenerateCode(Secret, 0);
            gen.TryGenerateCodeUtf8(Secret, 0, buffer, out _);

            await Assert.That(System.Text.Encoding.UTF8.GetString(buffer)).IsEqualTo(expected);
        }
    }

    // ── Input guards ──────────────────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_ReturnsFalse_ForWrongLength()
    {
        var gen = new HotpGenerator(); // 6-digit default
        await Assert.That(gen.ValidateCode(Secret, "12345", 0).IsValid).IsFalse();   // 5 chars
        await Assert.That(gen.ValidateCode(Secret, "1234567", 0).IsValid).IsFalse(); // 7 chars
    }

    [Test]
    public async Task ValidateCode_ReturnsFalse_ForNonNumeric()
    {
        var gen = new HotpGenerator();
        await Assert.That(gen.ValidateCode(Secret, "abc123", 0).IsValid).IsFalse();
    }

    // ── Invalid algorithm ─────────────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_ThrowsForInvalidAlgorithm()
    {
        var gen = new HotpGenerator(new HotpOptions { Algorithm = (OtpAlgorithm)99 });
        await Assert.That(() => gen.GenerateCode(Secret, 0))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── HotpOptions validation ────────────────────────────────────────────────

    [Test]
    [Arguments(5)]
    [Arguments(9)]
    public async Task HotpOptions_ThrowsForInvalidDigits(int digits)
    {
        await Assert.That(() => new HotpOptions { Digits = digits })
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── Constructor guards ────────────────────────────────────────────────────

    [Test]
    public async Task Constructor_ThrowsForNullOptions()
    {
        await Assert.That(() => new HotpGenerator(null!))
            .ThrowsExactly<ArgumentNullException>();
    }
}