using Umbrace.Totp.Internal;

namespace Umbrace.Totp.Tests;

public class Base32Tests
{
    // ── Encode ────────────────────────────────────────────────────────────────

    [Test]
    public async Task Encode_EmptyInput_ReturnsEmptyString()
    {
        await Assert.That(Base32.Encode([])).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Encode_MultipleOfFiveBytes_NoFlush()
    {
        // 5 bytes = 40 bits = exactly 8 Base32 characters, no leftover bits.
        byte[] input = "\0\0\0\0\0"u8.ToArray();
        await Assert.That(Base32.Encode(input)).IsEqualTo("AAAAAAAA");
    }

    [Test]
    public async Task Encode_NonMultipleOfFiveBytes_FlushesRemainingBits()
    {
        // 1 byte (0xFF): top 5 bits = 11111 = 31 = '7', remaining 3 bits left-padded = 11100 = 28 = '4'.
        await Assert.That(Base32.Encode([0xFF])).IsEqualTo("74");
    }

    [Test]
    public async Task Encode_KnownRfcValue()
    {
        // The 20-byte RFC 6238 SHA-1 test key encodes to a known Base32 string.
        byte[] input = "12345678901234567890"u8.ToArray();
        await Assert.That(Base32.Encode(input)).IsEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    // ── Decode ────────────────────────────────────────────────────────────────

    [Test]
    public async Task Decode_EmptyString_ReturnsEmptyArray()
    {
        await Assert.That(Decode("").SequenceEqual(Array.Empty<byte>())).IsTrue();
    }

    [Test]
    public async Task Decode_AllPadding_ReturnsEmptyArray()
    {
        // All padding characters trim to empty, which decodes to nothing.
        await Assert.That(Decode("========").SequenceEqual(Array.Empty<byte>())).IsTrue();
    }

    [Test]
    public async Task Decode_WithPadding_StripsAndDecodes()
    {
        // "AA======" is padded Base32 for a single 0x00 byte.
        await Assert.That(Decode("AA======").SequenceEqual(new byte[] { 0x00 })).IsTrue();
    }

    [Test]
    public async Task Decode_LowercaseInput_IsCaseInsensitive()
    {
        byte[] upper = Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        byte[] lower = Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq");
        await Assert.That(upper.SequenceEqual(lower)).IsTrue();
    }

    [Test]
    public async Task Decode_InvalidCharacter_ReturnsFalse()
    {
        Span<byte> buf = stackalloc byte[3];
        await Assert.That(Base32.TryDecode("!!!", buf, out _)).IsFalse();
    }

    [Test]
    public async Task Decode_HighAsciiCharacter_ReturnsFalse()
    {
        // Characters >= 128 take a separate code path (bounds check before table lookup).
        Span<byte> buf = stackalloc byte[1];
        await Assert.That(Base32.TryDecode("\u0080", buf, out _)).IsFalse();
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Test]
    public async Task RoundTrip_LargeInput_ExceedsStackallocThreshold()
    {
        // 130 bytes → 208 Base32 chars: exceeds the 128-char threshold in Encode (heap path)
        // and the 128-byte threshold in the Decode helper (heap path).
        byte[] input = new byte[130];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 7 + 13);

        await Assert.That(Decode(Base32.Encode(input)).SequenceEqual(input)).IsTrue();
    }

    [Test]
    [Arguments(1)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(10)]
    [Arguments(20)]
    [Arguments(32)]
    [Arguments(64)]
    public async Task RoundTrip_EncodeThenDecode_ReturnsOriginalBytes(int length)
    {
        byte[] input = new byte[length];
        for (int i = 0; i < length; i++) input[i] = (byte)(i * 7 + 13);

        byte[] result = Decode(Base32.Encode(input));
        await Assert.That(result.SequenceEqual(input)).IsTrue();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] Decode(string s)
    {
        int maxLen = s.Length * 5 / 8;
        Span<byte> buf = maxLen <= 128 ? stackalloc byte[maxLen] : new byte[maxLen];
        if (!Base32.TryDecode(s, buf, out int written))
            throw new FormatException($"Invalid Base32: '{s}'");
        return buf[..written].ToArray();
    }
}