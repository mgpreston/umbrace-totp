namespace Umbrace.Totp.Internal;

/// <summary>RFC 4648 Base32 encoding and decoding (no padding).</summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // ASCII → 5-bit value; -1 = invalid character.
    private static readonly sbyte[] DecodeTable = BuildDecodeTable();

    /// <summary>Encodes <paramref name="data"/> as an unpadded Base32 string.</summary>
    /// <param name="data">The bytes to encode. An empty span returns <see cref="string.Empty"/>.</param>
    /// <returns>An uppercase Base32 string with no <c>=</c> padding.</returns>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;

        int length = (data.Length * 8 + 4) / 5; // ceil(bits / 5)
        Span<char> chars = length <= 128 ? stackalloc char[length] : new char[length];
        int bitBuffer = 0, bitsLeft = 0, charIndex = 0;

        foreach (byte b in data)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                chars[charIndex++] = Alphabet[(bitBuffer >> bitsLeft) & 0x1F];
            }
        }

        if (bitsLeft > 0)
            chars[charIndex] = Alphabet[(bitBuffer << (5 - bitsLeft)) & 0x1F];

        return new string(chars);
    }

    /// <summary>Decodes a Base32 string into <paramref name="destination"/>.</summary>
    /// <param name="encoded">The Base32 characters to decode. Optional <c>=</c> padding is stripped automatically. Case-insensitive.</param>
    /// <param name="destination">The buffer to write decoded bytes into. Must be at least <c>encoded.Length * 5 / 8</c> bytes.</param>
    /// <param name="bytesWritten">The number of bytes written to <paramref name="destination"/>.</param>
    /// <returns><see langword="false"/> when <paramref name="encoded"/> contains an invalid character.</returns>
    public static bool TryDecode(ReadOnlySpan<char> encoded, Span<byte> destination, out int bytesWritten)
    {
        encoded = encoded.TrimEnd('=');
        bytesWritten = 0;

        if (encoded.IsEmpty)
            return true;

        int bitBuffer = 0, bitsLeft = 0;

        foreach (char c in encoded)
        {
            int val = c < 128 ? DecodeTable[c] : -1;
            if (val < 0)
                return false;

            bitBuffer = (bitBuffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                destination[bytesWritten++] = (byte)(bitBuffer >> bitsLeft);
            }
        }

        return true;
    }

    private static sbyte[] BuildDecodeTable()
    {
        var table = new sbyte[128];
        Array.Fill(table, (sbyte)-1);
        for (int i = 0; i < Alphabet.Length; i++)
        {
            table[Alphabet[i]] = (sbyte)i;
            table[char.ToLowerInvariant(Alphabet[i])] = (sbyte)i;
        }
        return table;
    }
}