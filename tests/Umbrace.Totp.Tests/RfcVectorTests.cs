namespace Umbrace.Totp.Tests;

/// <summary>
/// Verifies TOTP generation against all test vectors in RFC 6238 Appendix B.
/// Each combination of (time, algorithm) becomes an independently named test case.
/// </summary>
public class RfcVectorTests
{
    // RFC 6238 Appendix B keys — ASCII bytes, length matches the hash output size.
    private static readonly byte[] Sha1Key =
        "12345678901234567890"u8.ToArray();                                              // 20 bytes
    private static readonly byte[] Sha256Key =
        "12345678901234567890123456789012"u8.ToArray();                                 // 32 bytes
    private static readonly byte[] Sha512Key =
        "1234567890123456789012345678901234567890123456789012345678901234"u8.ToArray(); // 64 bytes

    /// <summary>
    /// Concrete type for RFC 6238 Appendix B test vector rows.
    /// Using a record (not a tuple) satisfies TUnit's AOT-compatibility requirement.
    /// </summary>
    public record RfcVector(long UnixTime, OtpAlgorithm Algorithm, string Expected);

    /// <summary>
    /// Returns the 18 test vectors from RFC 6238 Appendix B
    /// (6 timestamps × 3 algorithms, all using 8-digit codes).
    /// </summary>
    public static IEnumerable<RfcVector> GetVectors()
    {
        // Time = 59 (1970-01-01 00:00:59)
        yield return new(59L, OtpAlgorithm.Sha1, "94287082");
        yield return new(59L, OtpAlgorithm.Sha256, "46119246");
        yield return new(59L, OtpAlgorithm.Sha512, "90693936");
        // Time = 1111111109 (2005-03-18 01:58:29)
        yield return new(1111111109L, OtpAlgorithm.Sha1, "07081804");
        yield return new(1111111109L, OtpAlgorithm.Sha256, "68084774");
        yield return new(1111111109L, OtpAlgorithm.Sha512, "25091201");
        // Time = 1111111111 (2005-03-18 01:58:31)
        yield return new(1111111111L, OtpAlgorithm.Sha1, "14050471");
        yield return new(1111111111L, OtpAlgorithm.Sha256, "67062674");
        yield return new(1111111111L, OtpAlgorithm.Sha512, "99943326");
        // Time = 1234567890 (2009-02-13 23:31:30)
        yield return new(1234567890L, OtpAlgorithm.Sha1, "89005924");
        yield return new(1234567890L, OtpAlgorithm.Sha256, "91819424");
        yield return new(1234567890L, OtpAlgorithm.Sha512, "93441116");
        // Time = 2000000000 (2033-05-18 03:33:20)
        yield return new(2000000000L, OtpAlgorithm.Sha1, "69279037");
        yield return new(2000000000L, OtpAlgorithm.Sha256, "90698825");
        yield return new(2000000000L, OtpAlgorithm.Sha512, "38618901");
        // Time = 20000000000 (2603-10-11 11:33:20)
        yield return new(20000000000L, OtpAlgorithm.Sha1, "65353130");
        yield return new(20000000000L, OtpAlgorithm.Sha256, "77737706");
        yield return new(20000000000L, OtpAlgorithm.Sha512, "47863826");
    }

    [Test]
    [MethodDataSource(nameof(GetVectors))]
    public async Task GenerateCode_MatchesRfcVectors(RfcVector vector)
    {
        byte[] key = vector.Algorithm switch
        {
            OtpAlgorithm.Sha1 => Sha1Key,
            OtpAlgorithm.Sha256 => Sha256Key,
            OtpAlgorithm.Sha512 => Sha512Key,
            _ => throw new InvalidOperationException(),
        };

        var options = new TotpOptions
        {
            Algorithm = vector.Algorithm,
            Digits = 8,
            TimeStep = 30,
            T0 = 0,
        };

        var generator = new TotpGenerator(options);
        string actual = generator.GenerateCodeForUnixTime(key, vector.UnixTime);

        await Assert.That(actual).IsEqualTo(vector.Expected);
    }
}