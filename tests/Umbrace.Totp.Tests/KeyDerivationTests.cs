namespace Umbrace.Totp.Tests;

public class KeyDerivationTests
{
    private static readonly byte[] MasterKey = TotpKeyGenerator.GenerateKey();

    // ── Determinism ───────────────────────────────────────────────────────────

    [Test]
    public async Task DeriveKey_SameInputs_ReturnsSameKey()
    {
        byte[] first = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);
        byte[] second = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);

        await Assert.That(first.SequenceEqual(second)).IsTrue();
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    [Test]
    public async Task DeriveKey_DifferentContexts_ReturnsDifferentKeys()
    {
        byte[] user1 = TotpKeyGenerator.DeriveKey(MasterKey, "user1"u8);
        byte[] user2 = TotpKeyGenerator.DeriveKey(MasterKey, "user2"u8);

        await Assert.That(user1.SequenceEqual(user2)).IsFalse();
    }

    [Test]
    public async Task DeriveKey_DifferentMasterKeys_ReturnsDifferentKeys()
    {
        byte[] masterA = TotpKeyGenerator.GenerateKey();
        byte[] masterB = TotpKeyGenerator.GenerateKey();

        byte[] keyA = TotpKeyGenerator.DeriveKey(masterA, "user@example.com"u8);
        byte[] keyB = TotpKeyGenerator.DeriveKey(masterB, "user@example.com"u8);

        await Assert.That(keyA.SequenceEqual(keyB)).IsFalse();
    }

    // ── Output length ─────────────────────────────────────────────────────────

    [Test]
    [Arguments(OtpAlgorithm.Sha1, 20)]
    [Arguments(OtpAlgorithm.Sha256, 32)]
    [Arguments(OtpAlgorithm.Sha512, 64)]
    public async Task DeriveKey_OutputLength_MatchesRecommendedKeyLength(OtpAlgorithm algorithm, int expectedLength)
    {
        byte[] master = TotpKeyGenerator.GenerateKey(algorithm);
        byte[] derived = TotpKeyGenerator.DeriveKey(master, "user@example.com"u8, algorithm);

        await Assert.That(derived.Length).IsEqualTo(expectedLength);
        await Assert.That(derived.Length).IsEqualTo(TotpKeyGenerator.RecommendedKeyLength(algorithm));
    }

    // ── TryDeriveKey span behaviour ───────────────────────────────────────────

    [Test]
    public async Task TryDeriveKey_DestinationTooSmall_ReturnsFalse()
    {
        Span<byte> destination = stackalloc byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha1) - 1];

        bool result = TotpKeyGenerator.TryDeriveKey(MasterKey, "user@example.com"u8, destination);

        await Assert.That(result).IsFalse();
    }

    [Test]
    public async Task TryDeriveKey_DestinationExactSize_ReturnsTrueAndMatchesDeriveKey()
    {
        // Use a heap-allocated array — stackalloc spans cannot be preserved across await boundaries.
        byte[] destination = new byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha1)];

        bool result = TotpKeyGenerator.TryDeriveKey(MasterKey, "user@example.com"u8, destination);
        byte[] expected = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);

        await Assert.That(result).IsTrue();
        await Assert.That(destination.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task TryDeriveKey_DestinationLargerThanNeeded_ReturnsTrueAndFillsBuffer()
    {
        // Use a heap-allocated array — stackalloc spans cannot be preserved across await boundaries.
        byte[] destination = new byte[TotpKeyGenerator.RecommendedKeyLength(OtpAlgorithm.Sha1) + 8];

        bool result = TotpKeyGenerator.TryDeriveKey(MasterKey, "user@example.com"u8, destination);
        byte[] expected = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);

        await Assert.That(result).IsTrue();
        await Assert.That(destination[..expected.Length].SequenceEqual(expected)).IsTrue();
    }

    // ── Validation / exception paths ──────────────────────────────────────────

    [Test]
    public async Task DeriveKey_EmptyMasterKey_ThrowsArgumentException()
    {
        await Assert.That(() => TotpKeyGenerator.DeriveKey([], "user@example.com"u8))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task TryDeriveKey_EmptyMasterKey_ThrowsArgumentException()
    {
        // Use a heap-allocated array — stackalloc spans cannot be captured in lambdas.
        byte[] destination = new byte[20];

        await Assert.That(() => TotpKeyGenerator.TryDeriveKey([], "user@example.com"u8, destination))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task DeriveKey_InvalidAlgorithm_ThrowsArgumentOutOfRangeException()
    {
        await Assert.That(() => TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8, (OtpAlgorithm)99))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task TryDeriveKey_InvalidAlgorithm_ThrowsArgumentOutOfRangeException()
    {
        // Use a large heap-allocated buffer so the algorithm check is reached.
        // stackalloc spans cannot be captured in lambdas.
        byte[] destination = new byte[64];

        await Assert.That(() => TotpKeyGenerator.TryDeriveKey(MasterKey, "user@example.com"u8, destination, (OtpAlgorithm)99))
            .Throws<ArgumentOutOfRangeException>();
    }

    // ── Integration ───────────────────────────────────────────────────────────

    [Test]
    public async Task DeriveKey_ResultWorksWithTotpGenerator()
    {
        byte[] secret = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);
        var generator = new TotpGenerator();

        GenerationResult generated = generator.GenerateCode(secret);
        ValidationResult validated = generator.ValidateCode(secret, generated.Code);

        await Assert.That(validated.IsValid).IsTrue();
    }

    [Test]
    public async Task DeriveKey_ResultWorksWithHotpGenerator()
    {
        byte[] secret = TotpKeyGenerator.DeriveKey(MasterKey, "user@example.com"u8);
        var generator = new HotpGenerator();

        string code = generator.GenerateCode(secret, counter: 0);
        HotpValidationResult validated = generator.ValidateCode(secret, code, expectedCounter: 0);

        await Assert.That(validated.IsValid).IsTrue();
    }
}