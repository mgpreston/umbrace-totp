using System.Text;

namespace Umbrace.Totp.Tests;

public class Base32Tests
{
    // ── GetEncodedLength ──────────────────────────────────────────────────────

    [Test]
    [Arguments(0, 0)]
    [Arguments(1, 2)]
    [Arguments(4, 7)]
    [Arguments(5, 8)]
    [Arguments(10, 16)]
    [Arguments(20, 32)]
    public async Task GetEncodedLength_KnownLengths_ReturnsExpected(int input, int expected)
    {
        await Assert.That(Base32.GetEncodedLength(input)).IsEqualTo(expected);
    }

    [Test]
    public async Task GetEncodedLength_NegativeInput_ThrowsArgumentOutOfRangeException()
    {
        await Assert.That(() => Base32.GetEncodedLength(-1)).Throws<ArgumentOutOfRangeException>();
    }

    // ── GetMaxDecodedLength ───────────────────────────────────────────────────

    [Test]
    [Arguments(0, 0)]
    [Arguments(2, 1)]
    [Arguments(4, 2)]
    [Arguments(8, 5)]
    [Arguments(32, 20)]
    public async Task GetMaxDecodedLength_KnownLengths_ReturnsExpected(int input, int expected)
    {
        await Assert.That(Base32.GetMaxDecodedLength(input)).IsEqualTo(expected);
    }

    [Test]
    public async Task GetMaxDecodedLength_NegativeInput_ThrowsArgumentOutOfRangeException()
    {
        await Assert.That(() => Base32.GetMaxDecodedLength(-1)).Throws<ArgumentOutOfRangeException>();
    }

    // ── EncodeToString ────────────────────────────────────────────────────────

    [Test]
    public async Task EncodeToString_EmptyInput_ReturnsEmptyString()
    {
        await Assert.That(Base32.EncodeToString([])).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task EncodeToString_MultipleOfFiveBytes_NoFlush()
    {
        // 5 bytes = 40 bits = exactly 8 Base32 characters, no leftover bits.
        byte[] input = "\0\0\0\0\0"u8.ToArray();
        await Assert.That(Base32.EncodeToString(input)).IsEqualTo("AAAAAAAA");
    }

    [Test]
    public async Task EncodeToString_NonMultipleOfFiveBytes_FlushesRemainingBits()
    {
        // 1 byte (0xFF): top 5 bits = 11111 = 31 = '7', remaining 3 bits left-padded = 11100 = 28 = '4'.
        await Assert.That(Base32.EncodeToString([0xFF])).IsEqualTo("74");
    }

    [Test]
    public async Task EncodeToString_KnownRfcValue()
    {
        // The 20-byte RFC 6238 SHA-1 test key encodes to a known Base32 string.
        byte[] input = "12345678901234567890"u8.ToArray();
        await Assert.That(Base32.EncodeToString(input)).IsEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    // ── EncodeToChars ─────────────────────────────────────────────────────────

    [Test]
    public async Task EncodeToChars_EmptyInput_ReturnsEmptyArray()
    {
        await Assert.That(Base32.EncodeToChars([])).IsEmpty();
    }

    [Test]
    public async Task EncodeToChars_KnownRfcValue_ReturnsExpectedChars()
    {
        byte[] input = "12345678901234567890"u8.ToArray();
        await Assert.That(new string(Base32.EncodeToChars(input))).IsEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    // ── TryEncodeToChars ──────────────────────────────────────────────────────

    [Test]
    public async Task TryEncodeToChars_EmptySource_ReturnsTrueWithZeroCharsWritten()
    {
        Span<char> dest = stackalloc char[4];
        bool result = Base32.TryEncodeToChars([], dest, out int charsWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(charsWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryEncodeToChars_ExactSizeDestination_Succeeds()
    {
        // 1 byte (0xFF) → "74" (2 chars)
        char[] dest = new char[2];
        bool result = Base32.TryEncodeToChars([0xFF], dest, out int charsWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(charsWritten).IsEqualTo(2);
        await Assert.That(new string(dest)).IsEqualTo("74");
    }

    [Test]
    public async Task TryEncodeToChars_OversizedDestination_Succeeds()
    {
        char[] dest = new char[10];
        bool result = Base32.TryEncodeToChars([0xFF], dest, out int charsWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(charsWritten).IsEqualTo(2);
    }

    [Test]
    public async Task TryEncodeToChars_DestinationTooSmall_ReturnsFalse()
    {
        char[] dest = new char[1];
        bool result = Base32.TryEncodeToChars([0xFF], dest, out int charsWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(charsWritten).IsEqualTo(0);
    }

    // ── TryEncodeToUtf8 ───────────────────────────────────────────────────────

    [Test]
    public async Task TryEncodeToUtf8_SuccessPath_ProducesAsciiEquivalentOfChars()
    {
        byte[] source = "12345678901234567890"u8.ToArray();
        byte[] dest = new byte[Base32.GetEncodedLength(source.Length)];

        bool result = Base32.TryEncodeToUtf8(source, dest, out int bytesWritten);

        string expected = Base32.EncodeToString(source);
        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(expected.Length);
        await Assert.That(Encoding.ASCII.GetString(dest[..bytesWritten])).IsEqualTo(expected);
    }

    [Test]
    public async Task TryEncodeToUtf8_NonMultipleOfFiveBytes_FlushesRemainingBits()
    {
        // 1 byte (0xFF) → "74" — exercises the leftover-bits flush path in EncodeCoreUtf8.
        byte[] dest = new byte[2];
        bool result = Base32.TryEncodeToUtf8([0xFF], dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(2);
        await Assert.That(Encoding.ASCII.GetString(dest)).IsEqualTo("74");
    }

    [Test]
    public async Task TryEncodeToUtf8_DestinationTooSmall_ReturnsFalse()
    {
        byte[] dest = new byte[1];
        bool result = Base32.TryEncodeToUtf8([0xFF], dest, out int bytesWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryEncodeToUtf8_LargeInput_ProducesCorrectOutput()
    {
        // 130 bytes → 208 Base32 UTF-8 bytes; verifies correctness for large inputs.
        byte[] input = new byte[130];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 7 + 13);

        byte[] dest = new byte[Base32.GetEncodedLength(input.Length)];
        bool result = Base32.TryEncodeToUtf8(input, dest, out int bytesWritten);

        string expected = Base32.EncodeToString(input);
        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(208);
        await Assert.That(Encoding.ASCII.GetString(dest[..bytesWritten])).IsEqualTo(expected);
    }

    // ── DecodeFromChars ───────────────────────────────────────────────────────

    [Test]
    public async Task DecodeFromChars_EmptyInput_ReturnsEmptyArray()
    {
        await Assert.That(Base32.DecodeFromChars([])).IsEmpty();
    }

    [Test]
    public async Task DecodeFromChars_AllPadding_ReturnsEmptyArray()
    {
        // All padding characters trim to empty, which decodes to nothing.
        await Assert.That(Base32.DecodeFromChars("========")).IsEmpty();
    }

    [Test]
    public async Task DecodeFromChars_PaddedInput_StripsAndDecodes()
    {
        // "AA======" is padded Base32 for a single 0x00 byte.
        await Assert.That(Base32.DecodeFromChars("AA======").SequenceEqual(new byte[] { 0x00 })).IsTrue();
    }

    [Test]
    public async Task DecodeFromChars_KnownRfcValue_ReturnsExpectedBytes()
    {
        byte[] expected = "12345678901234567890"u8.ToArray();
        await Assert.That(Base32.DecodeFromChars("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task DecodeFromChars_LowercaseInput_IsCaseInsensitive()
    {
        byte[] upper = Base32.DecodeFromChars("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        byte[] lower = Base32.DecodeFromChars("gezdgnbvgy3tqojqgezdgnbvgy3tqojq");
        await Assert.That(upper.SequenceEqual(lower)).IsTrue();
    }

    [Test]
    public async Task DecodeFromChars_InvalidCharacter_ThrowsFormatException()
    {
        await Assert.That(() => Base32.DecodeFromChars("!!!")).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task DecodeFromChars_HighAsciiCharacter_ThrowsFormatException()
    {
        // Characters >= 128 take a separate code path (bounds check before table lookup).
        await Assert.That(() => Base32.DecodeFromChars("\u0080")).ThrowsExactly<FormatException>();
    }

    // ── TryDecodeFromChars ────────────────────────────────────────────────────

    [Test]
    public async Task TryDecodeFromChars_EmptyInput_ReturnsTrueWithZeroBytesWritten()
    {
        Span<byte> dest = stackalloc byte[4];
        bool result = Base32.TryDecodeFromChars([], dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryDecodeFromChars_AllPadding_ReturnsTrueWithZeroBytesWritten()
    {
        Span<byte> dest = stackalloc byte[4];
        bool result = Base32.TryDecodeFromChars("========", dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryDecodeFromChars_WithPadding_StripsAndDecodes()
    {
        // "AA======" is padded Base32 for a single 0x00 byte.
        // Use a heap-allocated array — stackalloc spans cannot be preserved across await boundaries.
        byte[] dest = new byte[1];
        bool result = Base32.TryDecodeFromChars("AA======", dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(1);
        await Assert.That(dest[0]).IsEqualTo((byte)0x00);
    }

    [Test]
    public async Task TryDecodeFromChars_InvalidCharacter_ReturnsFalse()
    {
        Span<byte> buf = stackalloc byte[3];
        await Assert.That(Base32.TryDecodeFromChars("!!!", buf, out _)).IsFalse();
    }

    [Test]
    public async Task TryDecodeFromChars_HighAsciiCharacter_ReturnsFalse()
    {
        // Characters >= 128 take a separate code path (bounds check before table lookup).
        Span<byte> buf = stackalloc byte[1];
        await Assert.That(Base32.TryDecodeFromChars("\u0080", buf, out _)).IsFalse();
    }

    [Test]
    public async Task TryDecodeFromChars_DestinationTooSmall_ReturnsFalse()
    {
        // "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" decodes to 20 bytes; provide only 5.
        Span<byte> dest = stackalloc byte[5];
        bool result = Base32.TryDecodeFromChars("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", dest, out int bytesWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    // ── DecodeFromUtf8 ────────────────────────────────────────────────────────

    [Test]
    public async Task DecodeFromUtf8_EmptyInput_ReturnsEmptyArray()
    {
        await Assert.That(Base32.DecodeFromUtf8([])).IsEmpty();
    }

    [Test]
    public async Task DecodeFromUtf8_SuccessPath_MatchesDecodeFromChars()
    {
        byte[] utf8 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"u8.ToArray();
        byte[] fromChars = Base32.DecodeFromChars("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        await Assert.That(Base32.DecodeFromUtf8(utf8).SequenceEqual(fromChars)).IsTrue();
    }

    [Test]
    public async Task DecodeFromUtf8_InvalidCharacter_ThrowsFormatException()
    {
        await Assert.That(() => Base32.DecodeFromUtf8("!!!"u8.ToArray())).ThrowsExactly<FormatException>();
    }

    [Test]
    public async Task DecodeFromUtf8_LargeInput_ProducesCorrectOutput()
    {
        // 130 bytes → 208 Base32 chars (> 128 threshold) — exercises the ArrayPool path.
        byte[] input = new byte[130];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 7 + 13);

        byte[] utf8Encoded = new byte[Base32.GetEncodedLength(input.Length)];
        Base32.TryEncodeToUtf8(input, utf8Encoded, out _);

        byte[] decoded = Base32.DecodeFromUtf8(utf8Encoded);
        await Assert.That(decoded.SequenceEqual(input)).IsTrue();
    }

    // ── TryDecodeFromUtf8 ─────────────────────────────────────────────────────

    [Test]
    public async Task TryDecodeFromUtf8_EmptyInput_ReturnsTrueWithZeroBytesWritten()
    {
        byte[] dest = new byte[4];
        bool result = Base32.TryDecodeFromUtf8([], dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryDecodeFromUtf8_DestinationTooSmall_ReturnsFalse()
    {
        // "AA"u8 decodes to 1 byte; provide 0-byte destination.
        byte[] dest = [];
        bool result = Base32.TryDecodeFromUtf8("AA"u8.ToArray(), dest, out int bytesWritten);

        await Assert.That(result).IsFalse();
        await Assert.That(bytesWritten).IsEqualTo(0);
    }

    [Test]
    public async Task TryDecodeFromUtf8_SuccessPath_WritesCorrectBytes()
    {
        byte[] dest = new byte[1];
        bool result = Base32.TryDecodeFromUtf8("AA"u8.ToArray(), dest, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(bytesWritten).IsEqualTo(1);
        await Assert.That(dest[0]).IsEqualTo((byte)0x00);
    }

    [Test]
    public async Task TryDecodeFromUtf8_InvalidByte_ReturnsFalse()
    {
        // '!' is 0x21, not in the Base32 alphabet.
        byte[] dest = new byte[1];
        await Assert.That(Base32.TryDecodeFromUtf8("!!"u8.ToArray(), dest, out _)).IsFalse();
    }

    [Test]
    public async Task TryDecodeFromUtf8_HighAsciiByte_ReturnsFalse()
    {
        // Byte value >= 128 takes the c >= 128 code path in TryDecodeCore.
        byte[] dest = new byte[1];
        await Assert.That(Base32.TryDecodeFromUtf8([0x80, 0x41], dest, out _)).IsFalse();
    }

    [Test]
    public async Task TryDecodeFromUtf8_LargeInput_ProducesCorrectOutput()
    {
        // 130 bytes → 208 Base32 UTF-8 bytes (> 128 threshold) — exercises the ArrayPool path.
        byte[] input = new byte[130];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 7 + 13);

        byte[] utf8Encoded = new byte[Base32.GetEncodedLength(input.Length)];
        Base32.TryEncodeToUtf8(input, utf8Encoded, out _);

        byte[] decoded = new byte[Base32.GetMaxDecodedLength(utf8Encoded.Length)];
        bool result = Base32.TryDecodeFromUtf8(utf8Encoded, decoded, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(decoded[..bytesWritten].SequenceEqual(input)).IsTrue();
    }

    // ── Round-trips through new API ───────────────────────────────────────────

    [Test]
    public async Task RoundTrip_TryEncodeToChars_ThenTryDecodeFromChars()
    {
        byte[] input = "12345678901234567890"u8.ToArray();
        Span<char> encoded = stackalloc char[Base32.GetEncodedLength(input.Length)];
        Base32.TryEncodeToChars(input, encoded, out int charsWritten);

        byte[] decoded = new byte[Base32.GetMaxDecodedLength(charsWritten)];
        bool result = Base32.TryDecodeFromChars(encoded[..charsWritten], decoded, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(decoded[..bytesWritten].SequenceEqual(input)).IsTrue();
    }

    [Test]
    public async Task RoundTrip_TryEncodeToUtf8_ThenTryDecodeFromUtf8()
    {
        byte[] input = "12345678901234567890"u8.ToArray();
        // Use heap-allocated arrays — stackalloc spans cannot be preserved across await boundaries.
        byte[] encoded = new byte[Base32.GetEncodedLength(input.Length)];
        Base32.TryEncodeToUtf8(input, encoded, out int bytesEncoded);

        byte[] decoded = new byte[Base32.GetMaxDecodedLength(bytesEncoded)];
        bool result = Base32.TryDecodeFromUtf8(encoded[..bytesEncoded], decoded, out int bytesWritten);

        await Assert.That(result).IsTrue();
        await Assert.That(decoded[..bytesWritten].SequenceEqual(input)).IsTrue();
    }

    // ── Round-trip (large inputs) ─────────────────────────────────────────────

    [Test]
    public async Task RoundTrip_LargeInput_ExceedsStackallocThreshold()
    {
        // 130 bytes → 208 Base32 chars: exceeds the 128-char threshold in EncodeToString (heap path)
        // and the 128-char threshold in the Decode helper (heap path).
        byte[] input = new byte[130];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i * 7 + 13);

        await Assert.That(Decode(Base32.EncodeToString(input)).SequenceEqual(input)).IsTrue();
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

        byte[] result = Decode(Base32.EncodeToString(input));
        await Assert.That(result.SequenceEqual(input)).IsTrue();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] Decode(string s)
    {
        int maxLen = s.Length * 5 / 8;
        Span<byte> buf = maxLen <= 128 ? stackalloc byte[maxLen] : new byte[maxLen];
        if (!Base32.TryDecodeFromChars(s, buf, out int written))
            throw new FormatException($"Invalid Base32: '{s}'");
        return buf[..written].ToArray();
    }
}