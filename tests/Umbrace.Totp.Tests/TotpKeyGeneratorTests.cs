namespace Umbrace.Totp.Tests;

public class TotpKeyGeneratorTests
{
    // ── RFC-recommended lengths ───────────────────────────────────────────────

    [Test]
    [Arguments(OtpAlgorithm.Sha1, 20)]
    [Arguments(OtpAlgorithm.Sha256, 32)]
    [Arguments(OtpAlgorithm.Sha512, 64)]
    public async Task GenerateKey_Algorithm_ReturnsRfcRecommendedLength(
        OtpAlgorithm algorithm, int expectedLength)
    {
        byte[] key = TotpKeyGenerator.GenerateKey(algorithm);
        await Assert.That(key.Length).IsEqualTo(expectedLength);
    }

    [Test]
    [Arguments(OtpAlgorithm.Sha1, 20)]
    [Arguments(OtpAlgorithm.Sha256, 32)]
    [Arguments(OtpAlgorithm.Sha512, 64)]
    public async Task RecommendedKeyLength_ReturnsExpectedValue(
        OtpAlgorithm algorithm, int expectedLength)
    {
        await Assert.That(TotpKeyGenerator.RecommendedKeyLength(algorithm)).IsEqualTo(expectedLength);
    }

    [Test]
    public async Task GenerateKey_DefaultAlgorithm_ReturnsSha1Length()
    {
        byte[] key = TotpKeyGenerator.GenerateKey();
        await Assert.That(key.Length).IsEqualTo(20);
    }

    [Test]
    public async Task RecommendedKeyLength_ThrowsForInvalidAlgorithm()
    {
        await Assert.That(() => TotpKeyGenerator.RecommendedKeyLength((OtpAlgorithm)99))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── TryGenerateKey (algorithm) ────────────────────────────────────────────

    [Test]
    [Arguments(OtpAlgorithm.Sha1, 20)]
    [Arguments(OtpAlgorithm.Sha256, 32)]
    [Arguments(OtpAlgorithm.Sha512, 64)]
    public async Task TryGenerateKey_Algorithm_ReturnsTrueAndFillsBuffer(
        OtpAlgorithm algorithm, int expectedLength)
    {
        Span<byte> key = stackalloc byte[expectedLength];
        await Assert.That(TotpKeyGenerator.TryGenerateKey(key, algorithm)).IsTrue();
    }

    [Test]
    public async Task TryGenerateKey_Algorithm_ReturnsFalseWhenBufferTooSmall()
    {
        Span<byte> key = stackalloc byte[19]; // one byte short of SHA-1's 20
        await Assert.That(TotpKeyGenerator.TryGenerateKey(key, OtpAlgorithm.Sha1)).IsFalse();
    }

    [Test]
    [Arguments(OtpAlgorithm.Sha1)]
    [Arguments(OtpAlgorithm.Sha256)]
    [Arguments(OtpAlgorithm.Sha512)]
    public async Task TryGenerateKey_ProducesKeyUsableWithTotpGenerator(OtpAlgorithm algorithm)
    {
        int length = TotpKeyGenerator.RecommendedKeyLength(algorithm);
        Span<byte> key = stackalloc byte[length];
        TotpKeyGenerator.TryGenerateKey(key, algorithm);

        var generator = new TotpGenerator(new TotpOptions { Algorithm = algorithm });
        string code = generator.GenerateCode(key);
        await Assert.That(generator.ValidateCode(key, code).IsValid).IsTrue();
    }

    // ── Randomness ────────────────────────────────────────────────────────────

    [Test]
    public async Task GenerateKey_ProducesDifferentKeysOnEachCall()
    {
        byte[] key1 = TotpKeyGenerator.GenerateKey();
        byte[] key2 = TotpKeyGenerator.GenerateKey();
        await Assert.That(key1.SequenceEqual(key2)).IsFalse();
    }

    // ── Generated key works with TotpGenerator ────────────────────────────────

    [Test]
    [Arguments(OtpAlgorithm.Sha1)]
    [Arguments(OtpAlgorithm.Sha256)]
    [Arguments(OtpAlgorithm.Sha512)]
    public async Task GenerateKey_ProducesKeyUsableWithTotpGenerator(OtpAlgorithm algorithm)
    {
        byte[] key = TotpKeyGenerator.GenerateKey(algorithm);
        var generator = new TotpGenerator(new TotpOptions { Algorithm = algorithm });

        string code = generator.GenerateCode(key);
        bool valid = generator.ValidateCode(key, code);

        await Assert.That(valid).IsTrue();
    }
}