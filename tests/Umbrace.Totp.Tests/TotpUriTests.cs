namespace Umbrace.Totp.Tests;

public class TotpUriTests
{
    // Short 10-byte secret for most tests.
    private static readonly byte[] s_secret = "12345678901234567890"u8.ToArray();

    // ── Build ─────────────────────────────────────────────────────────────────

    [Test]
    public async Task ToString_ContainsBase32EncodedSecret()
    {
        var uri = new TotpUri("alice@example.com", s_secret);
        await Assert.That(uri.ToString()).Contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    [Test]
    public async Task ToString_DefaultsOmitted()
    {
        // Algorithm (SHA1), digits (6), and period (30) should not appear when default.
        var uri = new TotpUri("alice@example.com", s_secret);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).DoesNotContain("algorithm=");
        await Assert.That(uriStr).DoesNotContain("digits=");
        await Assert.That(uriStr).DoesNotContain("period=");
    }

    [Test]
    public async Task ToString_NonDefaultsIncluded()
    {
        var uri = new TotpUri("alice@example.com", s_secret,
            algorithm: OtpAlgorithm.Sha256, digits: 8, period: 60);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).Contains("algorithm=SHA256");
        await Assert.That(uriStr).Contains("digits=8");
        await Assert.That(uriStr).Contains("period=60");
    }

    [Test]
    public async Task ToString_IssuerInLabelAndQueryString()
    {
        var uri = new TotpUri("alice@example.com", s_secret, issuer: "Example Corp");
        string uriStr = uri.ToString();
        // issuer appears as label prefix
        await Assert.That(uriStr).Contains("Example%20Corp:alice%40example.com");
        // issuer also appears as query parameter
        await Assert.That(uriStr).Contains("issuer=Example%20Corp");
    }

    [Test]
    public async Task ToString_NoIssuer_NoLabelPrefixOrQueryParam()
    {
        var uri = new TotpUri("alice@example.com", s_secret);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).DoesNotContain("issuer=");
        // Label is just the account name
        await Assert.That(uriStr).Contains("totp/alice%40example.com");
    }

    [Test]
    public async Task ToUri_ReturnsAbsoluteUri()
    {
        var uri = new TotpUri("alice@example.com", s_secret);
        Uri result = uri.ToUri();
        await Assert.That(result.IsAbsoluteUri).IsTrue();
        await Assert.That(result.Scheme).IsEqualTo("otpauth");
    }

    // ── Parse ─────────────────────────────────────────────────────────────────

    [Test]
    public async Task Parse_MinimalUri_PopulatesCorrectly()
    {
        // Minimal URI: only required secret parameter, no issuer.
        string uriStr = "otpauth://totp/alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var uri = TotpUri.Parse(uriStr);

        await Assert.That(uri.AccountName).IsEqualTo("alice@example.com");
        await Assert.That(uri.Issuer).IsNull();
        await Assert.That(uri.Algorithm).IsEqualTo(OtpAlgorithm.Sha1);
        await Assert.That(uri.Digits).IsEqualTo(6);
        await Assert.That(uri.Period).IsEqualTo(30);
        await Assert.That(uri.Secret.ToArray()).IsEquivalentTo(s_secret);
    }

    [Test]
    public async Task Parse_FullUri_PopulatesAllFields()
    {
        string uriStr =
            "otpauth://totp/Example%20Corp:alice%40example.com" +
            "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
            "&issuer=Example%20Corp" +
            "&algorithm=SHA256" +
            "&digits=8" +
            "&period=60";

        var uri = TotpUri.Parse(uriStr);

        await Assert.That(uri.AccountName).IsEqualTo("alice@example.com");
        await Assert.That(uri.Issuer).IsEqualTo("Example Corp");
        await Assert.That(uri.Algorithm).IsEqualTo(OtpAlgorithm.Sha256);
        await Assert.That(uri.Digits).IsEqualTo(8);
        await Assert.That(uri.Period).IsEqualTo(60);
    }

    [Test]
    public async Task Parse_IssuerFromLabelPrefix_WhenNoQueryParam()
    {
        string uriStr = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var uri = TotpUri.Parse(uriStr);

        await Assert.That(uri.Issuer).IsEqualTo("Example");
        await Assert.That(uri.AccountName).IsEqualTo("alice");
    }

    [Test]
    public async Task Parse_IssuerQueryParamOverridesLabelPrefix()
    {
        // Spec says the issuer parameter is authoritative.
        string uriStr =
            "otpauth://totp/Old:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=New";
        var uri = TotpUri.Parse(uriStr);

        await Assert.That(uri.Issuer).IsEqualTo("New");
    }

    [Test]
    [Arguments("SHA1", OtpAlgorithm.Sha1)]
    [Arguments("sha1", OtpAlgorithm.Sha1)]
    [Arguments("SHA256", OtpAlgorithm.Sha256)]
    [Arguments("SHA512", OtpAlgorithm.Sha512)]
    [Arguments("sha512", OtpAlgorithm.Sha512)]
    public async Task Parse_CaseInsensitiveAlgorithm(string algorithmParam, OtpAlgorithm expected)
    {
        string uriStr =
            $"otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm={algorithmParam}";
        var uri = TotpUri.Parse(uriStr);

        await Assert.That(uri.Algorithm).IsEqualTo(expected);
    }

    [Test]
    public async Task Parse_CaseInsensitiveSecret_LowercaseBase32()
    {
        // Base32 is case-insensitive; lowercase should decode the same bytes.
        string upper = "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        string lower = "otpauth://totp/alice?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq";

        var uriUpper = TotpUri.Parse(upper);
        var uriLower = TotpUri.Parse(lower);

        await Assert.That(uriUpper.Secret.ToArray()).IsEquivalentTo(uriLower.Secret.ToArray());
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Test]
    public async Task RoundTrip_WithIssuer_PreservesAllProperties()
    {
        var original = new TotpUri(
            accountName: "alice@example.com",
            secret: s_secret,
            issuer: "Example Corp",
            algorithm: OtpAlgorithm.Sha512,
            digits: 8,
            period: 60);

        var parsed = TotpUri.Parse(original.ToString());

        await Assert.That(parsed.AccountName).IsEqualTo(original.AccountName);
        await Assert.That(parsed.Issuer).IsEqualTo(original.Issuer);
        await Assert.That(parsed.Algorithm).IsEqualTo(original.Algorithm);
        await Assert.That(parsed.Digits).IsEqualTo(original.Digits);
        await Assert.That(parsed.Period).IsEqualTo(original.Period);
        await Assert.That(parsed.Secret.ToArray()).IsEquivalentTo(original.Secret.ToArray());
    }

    [Test]
    public async Task RoundTrip_WithoutIssuer_PreservesAllProperties()
    {
        var original = new TotpUri("alice@example.com", s_secret);
        var parsed = TotpUri.Parse(original.ToString());

        await Assert.That(parsed.AccountName).IsEqualTo(original.AccountName);
        await Assert.That(parsed.Issuer).IsNull();
        await Assert.That(parsed.Secret.ToArray()).IsEquivalentTo(original.Secret.ToArray());
    }

    [Test]
    public async Task RoundTrip_LargeSecret_ExceedsStackallocThreshold()
    {
        // 130-byte secret → 208 Base32 chars → maxSecretLength = 130, exceeding the 128-byte
        // stackalloc threshold in TryParse (heap allocation path).
        byte[] largeSecret = new byte[130];
        for (int i = 0; i < largeSecret.Length; i++) largeSecret[i] = (byte)(i * 7 + 13);

        var original = new TotpUri("alice@example.com", largeSecret);
        var parsed = TotpUri.Parse(original.ToString());

        await Assert.That(parsed.Secret.ToArray()).IsEquivalentTo(largeSecret);
    }

    // ── ToTotpOptions ─────────────────────────────────────────────────────────

    [Test]
    public async Task ToTotpOptions_MapsFieldsCorrectly()
    {
        var uri = new TotpUri("alice@example.com", s_secret,
            algorithm: OtpAlgorithm.Sha256, digits: 8, period: 60);

        TotpOptions opts = uri.ToTotpOptions();

        await Assert.That(opts.Algorithm).IsEqualTo(OtpAlgorithm.Sha256);
        await Assert.That(opts.Digits).IsEqualTo(8);
        await Assert.That(opts.TimeStep).IsEqualTo(60);
    }

    // ── Parse error cases ─────────────────────────────────────────────────────

    [Test]
    public async Task Parse_ThrowsForWrongScheme()
    {
        string uriStr = "https://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForWrongType()
    {
        string uriStr = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForMissingSecret()
    {
        string uriStr = "otpauth://totp/alice";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidBase32()
    {
        string uriStr = "otpauth://totp/alice?secret=!!!INVALID!!!";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForUnknownAlgorithm()
    {
        string uriStr = "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForEmptyAccountNameInLabel()
    {
        // Label "MyIssuer:" has a colon but an empty account-name segment.
        string uriStr = "otpauth://totp/MyIssuer:?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForSecretDecodingToEmptyBytes()
    {
        // A single Base32 character encodes fewer than 8 bits, so it decodes to 0 bytes.
        string uriStr = "otpauth://totp/alice?secret=A";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidDigits()
    {
        string uriStr = "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=99";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidPeriod()
    {
        string uriStr = "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0";
        await Assert.That(() => TotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task TryParse_ReturnsFalse_OnFailure()
    {
        bool ok = TotpUri.TryParse("not a uri at all", out TotpUri? result);
        await Assert.That(ok).IsFalse();
        await Assert.That(result).IsNull();
    }

    // ── Constructor guards ────────────────────────────────────────────────────

    [Test]
    public async Task ToString_ThrowsForInvalidAlgorithm()
    {
        // OtpAlgorithm has no guard in the constructor; the invalid value surfaces in BuildString.
        var uri = new TotpUri("alice", [0xFF], algorithm: (OtpAlgorithm)99);
        await Assert.That(() => uri.ToString()).ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Constructor_ThrowsForEmptyAccountName()
    {
        await Assert.That(() => new TotpUri("", s_secret)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task Constructor_ThrowsForEmptySecret()
    {
        await Assert.That(() => new TotpUri("alice", [])).ThrowsExactly<ArgumentException>();
    }

    [Test]
    [Arguments(5)]
    [Arguments(9)]
    public async Task Constructor_ThrowsForInvalidDigits(int digits)
    {
        await Assert.That(() => new TotpUri("alice", s_secret, digits: digits))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Constructor_ThrowsForNonPositivePeriod()
    {
        await Assert.That(() => new TotpUri("alice", s_secret, period: 0))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── Base32 edge cases (exercised via TotpUri) ─────────────────────────────

    [Test]
    public async Task ToString_Base32Encode_FlushesRemainingBits_ForNonMultipleOfFiveByteSecret()
    {
        // A 1-byte secret has 8 bits; after consuming the top 5 bits the remaining 3
        // must be flushed into a second character. This hits the post-loop flush path
        // in Base32.Encode that is never reached by the 20-byte RFC test secret.
        // [0xFF] → top 5 bits = 11111 = index 31 = '7'
        //          remaining 3 bits (111) left-padded to 5 = 11100 = index 28 = '4'
        var uri = new TotpUri("alice", [0xFF]);
        await Assert.That(uri.ToString()).Contains("secret=74");
    }

    [Test]
    public async Task Parse_Base32Decode_StripsEqualsSignPadding()
    {
        // "AA======" is standard RFC 4648 padded Base32 for a single 0x00 byte.
        // The six '=' characters exercise the padding-strip loop in Base32.Decode.
        string uriStr = "otpauth://totp/alice?secret=AA======";
        var uri = TotpUri.Parse(uriStr);
        await Assert.That(uri.Secret.ToArray()).IsEquivalentTo(new byte[] { 0x00 });
    }

    // ── Integration: URI → TotpGenerator ─────────────────────────────────────

    [Test]
    public async Task GenerateCode_ViaUri_MatchesDirectCall()
    {
        // RFC 6238 vector: unixTime=59, SHA-1, 8 digits → "94287082"
        var uri = new TotpUri("alice@example.com", s_secret, digits: 8);
        var generator = new TotpGenerator(uri.ToTotpOptions());
        string code = generator.GenerateCodeForUnixTime(uri.Secret.Span, 59L);

        await Assert.That(code).IsEqualTo("94287082");
    }
}