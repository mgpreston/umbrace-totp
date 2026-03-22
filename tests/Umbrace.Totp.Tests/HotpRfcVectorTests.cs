namespace Umbrace.Totp.Tests;

/// <summary>
/// Verifies HOTP generation against all ten test vectors in RFC 4226 Appendix D.
/// Each counter value becomes an independently named test case.
/// </summary>
public class HotpRfcVectorTests
{
    // RFC 4226 Appendix D secret key (20-byte ASCII).
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();
    private static readonly HotpGenerator Generator = new();

    public record RfcVector(long Counter, string Expected);

    /// <summary>Returns the ten test vectors from RFC 4226 Appendix D.</summary>
    public static IEnumerable<RfcVector> GetVectors()
    {
        yield return new(0, "755224");
        yield return new(1, "287082");
        yield return new(2, "359152");
        yield return new(3, "969429");
        yield return new(4, "338314");
        yield return new(5, "254676");
        yield return new(6, "287922");
        yield return new(7, "162583");
        yield return new(8, "399871");
        yield return new(9, "520489");
    }

    [Test]
    [MethodDataSource(nameof(GetVectors))]
    public async Task GenerateCode_MatchesRfcVectors(RfcVector vector)
    {
        string actual = Generator.GenerateCode(Secret, vector.Counter);
        await Assert.That(actual).IsEqualTo(vector.Expected);
    }
}