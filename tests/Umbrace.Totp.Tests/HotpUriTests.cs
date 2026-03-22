namespace Umbrace.Totp.Tests;

public class HotpUriTests
{
    // Short 20-byte secret for most tests.
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();

    // ── Build ─────────────────────────────────────────────────────────────────

    [Test]
    public async Task ToString_ContainsBase32EncodedSecret()
    {
        var uri = new HotpUri("alice@example.com", Secret);
        await Assert.That(uri.ToString()).Contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    [Test]
    public async Task ToString_CounterAlwaysEmitted_WhenZero()
    {
        // counter=0 is the default but must always appear — it is required by the spec.
        var uri = new HotpUri("alice@example.com", Secret, counter: 0);
        await Assert.That(uri.ToString()).Contains("counter=0");
    }

    [Test]
    public async Task ToString_CounterAlwaysEmitted_WhenNonZero()
    {
        var uri = new HotpUri("alice@example.com", Secret, counter: 42);
        await Assert.That(uri.ToString()).Contains("counter=42");
    }

    [Test]
    public async Task ToString_DefaultsOmitted()
    {
        // algorithm=SHA1 and digits=6 should not appear when default.
        var uri = new HotpUri("alice@example.com", Secret);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).DoesNotContain("algorithm=");
        await Assert.That(uriStr).DoesNotContain("digits=");
    }

    [Test]
    public async Task ToString_NonDefaultsIncluded()
    {
        var uri = new HotpUri("alice@example.com", Secret, algorithm: OtpAlgorithm.Sha256, digits: 8);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).Contains("algorithm=SHA256");
        await Assert.That(uriStr).Contains("digits=8");
    }

    [Test]
    public async Task ToString_IssuerInLabelAndQueryString()
    {
        var uri = new HotpUri("alice@example.com", Secret, issuer: "Example Corp");
        string uriStr = uri.ToString();
        // issuer appears as label prefix
        await Assert.That(uriStr).Contains("Example%20Corp:alice%40example.com");
        // issuer also appears as query parameter
        await Assert.That(uriStr).Contains("issuer=Example%20Corp");
    }

    [Test]
    public async Task ToString_NoIssuer_NoLabelPrefixOrQueryParam()
    {
        var uri = new HotpUri("alice@example.com", Secret);
        string uriStr = uri.ToString();
        await Assert.That(uriStr).DoesNotContain("issuer=");
        await Assert.That(uriStr).Contains("hotp/alice%40example.com");
    }

    [Test]
    public async Task ToString_ContainsHotpType()
    {
        var uri = new HotpUri("alice@example.com", Secret);
        await Assert.That(uri.ToString()).StartsWith("otpauth://hotp/");
    }

    [Test]
    public async Task ToUri_ReturnsAbsoluteUri()
    {
        var uri = new HotpUri("alice@example.com", Secret);
        Uri result = uri.ToUri();
        await Assert.That(result.IsAbsoluteUri).IsTrue();
        await Assert.That(result.Scheme).IsEqualTo("otpauth");
    }

    // ── Parse ─────────────────────────────────────────────────────────────────

    [Test]
    public async Task Parse_MinimalUri_PopulatesCorrectly()
    {
        string uriStr = "otpauth://hotp/alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0";
        var uri = HotpUri.Parse(uriStr);

        await Assert.That(uri.AccountName).IsEqualTo("alice@example.com");
        await Assert.That(uri.Issuer).IsNull();
        await Assert.That(uri.Algorithm).IsEqualTo(OtpAlgorithm.Sha1);
        await Assert.That(uri.Digits).IsEqualTo(6);
        await Assert.That(uri.Counter).IsEqualTo(0L);
        await Assert.That(uri.Secret.ToArray().SequenceEqual(Secret)).IsTrue();
    }

    [Test]
    public async Task Parse_MinimalUri_WithoutCounter_DefaultsToZero()
    {
        // counter is optional on parse; the spec marks it required for serialisation only.
        string uriStr = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var uri = HotpUri.Parse(uriStr);
        await Assert.That(uri.Counter).IsEqualTo(0L);
    }

    [Test]
    public async Task Parse_FullUri_PopulatesAllFields()
    {
        string uriStr =
            "otpauth://hotp/Example%20Corp:alice%40example.com" +
            "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
            "&issuer=Example%20Corp" +
            "&algorithm=SHA256" +
            "&digits=8" +
            "&counter=100";

        var uri = HotpUri.Parse(uriStr);

        await Assert.That(uri.AccountName).IsEqualTo("alice@example.com");
        await Assert.That(uri.Issuer).IsEqualTo("Example Corp");
        await Assert.That(uri.Algorithm).IsEqualTo(OtpAlgorithm.Sha256);
        await Assert.That(uri.Digits).IsEqualTo(8);
        await Assert.That(uri.Counter).IsEqualTo(100L);
    }

    [Test]
    public async Task Parse_IssuerFromLabelPrefix_WhenNoQueryParam()
    {
        string uriStr = "otpauth://hotp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var uri = HotpUri.Parse(uriStr);

        await Assert.That(uri.Issuer).IsEqualTo("Example");
        await Assert.That(uri.AccountName).IsEqualTo("alice");
    }

    [Test]
    public async Task Parse_IssuerQueryParamOverridesLabelPrefix()
    {
        string uriStr =
            "otpauth://hotp/Old:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=New";
        var uri = HotpUri.Parse(uriStr);
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
            $"otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm={algorithmParam}";
        var uri = HotpUri.Parse(uriStr);
        await Assert.That(uri.Algorithm).IsEqualTo(expected);
    }

    [Test]
    public async Task Parse_CaseInsensitiveSecret_LowercaseBase32()
    {
        string upper = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        string lower = "otpauth://hotp/alice?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq";

        var uriUpper = HotpUri.Parse(upper);
        var uriLower = HotpUri.Parse(lower);

        await Assert.That(uriUpper.Secret.ToArray().SequenceEqual(uriLower.Secret.ToArray())).IsTrue();
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Test]
    public async Task RoundTrip_WithIssuer_PreservesAllProperties()
    {
        var original = new HotpUri(
            accountName: "alice@example.com",
            secret: Secret,
            counter: 99,
            issuer: "Example Corp",
            algorithm: OtpAlgorithm.Sha512,
            digits: 8);

        var parsed = HotpUri.Parse(original.ToString());

        await Assert.That(parsed.AccountName).IsEqualTo(original.AccountName);
        await Assert.That(parsed.Issuer).IsEqualTo(original.Issuer);
        await Assert.That(parsed.Algorithm).IsEqualTo(original.Algorithm);
        await Assert.That(parsed.Digits).IsEqualTo(original.Digits);
        await Assert.That(parsed.Counter).IsEqualTo(original.Counter);
        await Assert.That(parsed.Secret.ToArray().SequenceEqual(original.Secret.ToArray())).IsTrue();
    }

    [Test]
    public async Task RoundTrip_WithoutIssuer_PreservesAllProperties()
    {
        var original = new HotpUri("alice@example.com", Secret, counter: 7);
        var parsed = HotpUri.Parse(original.ToString());

        await Assert.That(parsed.AccountName).IsEqualTo(original.AccountName);
        await Assert.That(parsed.Issuer).IsNull();
        await Assert.That(parsed.Counter).IsEqualTo(7L);
        await Assert.That(parsed.Secret.ToArray().SequenceEqual(original.Secret.ToArray())).IsTrue();
    }

    [Test]
    public async Task RoundTrip_LargeSecret_ExceedsStackallocThreshold()
    {
        // 130-byte secret → 208 Base32 chars → maxSecretLength = 130, exceeding the 128-byte
        // stackalloc threshold in TryParse (heap allocation path).
        byte[] largeSecret = new byte[130];
        for (int i = 0; i < largeSecret.Length; i++) largeSecret[i] = (byte)(i * 7 + 13);

        var original = new HotpUri("alice@example.com", largeSecret);
        var parsed = HotpUri.Parse(original.ToString());

        await Assert.That(parsed.Secret.ToArray().SequenceEqual(largeSecret)).IsTrue();
    }

    // ── ToHotpOptions ─────────────────────────────────────────────────────────

    [Test]
    public async Task ToHotpOptions_MapsFieldsCorrectly()
    {
        var uri = new HotpUri("alice@example.com", Secret, algorithm: OtpAlgorithm.Sha256, digits: 8);

        HotpOptions opts = uri.ToHotpOptions();

        await Assert.That(opts.Algorithm).IsEqualTo(OtpAlgorithm.Sha256);
        await Assert.That(opts.Digits).IsEqualTo(8);
    }

    // ── Parse error cases ─────────────────────────────────────────────────────

    [Test]
    public async Task Parse_ThrowsForWrongScheme()
    {
        string uriStr = "https://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForWrongType_Totp()
    {
        // type=totp must be rejected by HotpUri.Parse
        string uriStr = "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForMissingSecret()
    {
        string uriStr = "otpauth://hotp/alice";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidBase32()
    {
        string uriStr = "otpauth://hotp/alice?secret=!!!INVALID!!!";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForUnknownAlgorithm()
    {
        string uriStr = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidDigits()
    {
        string uriStr = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=99";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForInvalidCounter_NonNumeric()
    {
        string uriStr = "otpauth://hotp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=abc";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForEmptyAccountNameInLabel()
    {
        string uriStr = "otpauth://hotp/MyIssuer:?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task Parse_ThrowsForSecretDecodingToEmptyBytes()
    {
        // A single Base32 character encodes fewer than 8 bits, so it decodes to 0 bytes.
        string uriStr = "otpauth://hotp/alice?secret=A";
        await Assert.That(() => HotpUri.Parse(uriStr)).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task TryParse_ReturnsFalse_OnFailure()
    {
        bool ok = HotpUri.TryParse("not a uri at all", out HotpUri? result);
        await Assert.That(ok).IsFalse();
        await Assert.That(result).IsNull();
    }

    // ── Constructor guards ────────────────────────────────────────────────────

    [Test]
    public async Task ToString_ThrowsForInvalidAlgorithm()
    {
        var uri = new HotpUri("alice", [0xFF], algorithm: (OtpAlgorithm)99);
        await Assert.That(() => uri.ToString()).ThrowsExactly<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Constructor_ThrowsForEmptyAccountName()
    {
        await Assert.That(() => new HotpUri("", Secret)).ThrowsExactly<ArgumentException>();
    }

    [Test]
    public async Task Constructor_ThrowsForEmptySecret()
    {
        await Assert.That(() => new HotpUri("alice", [])).ThrowsExactly<ArgumentException>();
    }

    [Test]
    [Arguments(5)]
    [Arguments(9)]
    public async Task Constructor_ThrowsForInvalidDigits(int digits)
    {
        await Assert.That(() => new HotpUri("alice", Secret, digits: digits))
            .ThrowsExactly<ArgumentOutOfRangeException>();
    }

    // ── Integration: URI → HotpGenerator ─────────────────────────────────────

    [Test]
    public async Task GenerateCode_ViaUri_MatchesDirectCall()
    {
        // RFC 4226 vector: counter=0, SHA-1, 6 digits → "755224"
        var uri = new HotpUri("alice@example.com", Secret);
        var gen = new HotpGenerator(uri.ToHotpOptions());
        string code = gen.GenerateCode(uri.Secret.Span, uri.Counter);

        await Assert.That(code).IsEqualTo("755224");
    }
}