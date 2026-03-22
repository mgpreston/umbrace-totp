using System.Buffers;

namespace Umbrace.Totp;

/// <summary>
/// Encodes and decodes data using RFC 4648 Base32 encoding.
/// </summary>
/// <remarks>
/// <para>
/// The standard RFC 4648 alphabet is used: <c>ABCDEFGHIJKLMNOPQRSTUVWXYZ234567</c>.
/// Encoded output is always unpadded uppercase. Decoding accepts both padded (<c>=</c>)
/// and unpadded input and is case-insensitive.
/// </para>
/// </remarks>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static readonly sbyte[] DecodeTable = BuildDecodeTable();

    /// <summary>
    /// Returns the number of Base32 characters produced by encoding
    /// <paramref name="sourceLength"/> bytes.
    /// </summary>
    /// <param name="sourceLength">The number of bytes to encode. Must be non-negative.</param>
    /// <returns>The exact number of Base32 characters in the encoded output (no padding).</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="sourceLength"/> is negative.
    /// </exception>
    public static int GetEncodedLength(int sourceLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sourceLength);
        return (sourceLength * 8 + 4) / 5; // ceil(bits / 5)
    }

    /// <summary>
    /// Returns the maximum number of bytes that can be decoded from
    /// <paramref name="base32Length"/> Base32 characters.
    /// </summary>
    /// <param name="base32Length">
    /// The number of Base32 characters (excluding any <c>=</c> padding). Must be non-negative.
    /// </param>
    /// <returns>
    /// The maximum decoded byte count. The actual decoded length may be less for
    /// inputs that contain partial groups.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="base32Length"/> is negative.
    /// </exception>
    public static int GetMaxDecodedLength(int base32Length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(base32Length);
        return base32Length * 5 / 8;
    }

    /// <summary>
    /// Encodes <paramref name="source"/> as an unpadded uppercase Base32 string.
    /// </summary>
    /// <param name="source">The bytes to encode. An empty span returns <see cref="string.Empty"/>.</param>
    /// <returns>An uppercase Base32 string with no <c>=</c> padding.</returns>
    public static string EncodeToString(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty) return string.Empty;
        int length = GetEncodedLength(source.Length);
        if (length <= 128)
        {
            Span<char> chars = stackalloc char[length];
            EncodeCore(source, chars);
            return new string(chars);
        }
        char[] rented = ArrayPool<char>.Shared.Rent(length);
        try
        {
            EncodeCore(source, rented.AsSpan(0, length));
            return new string(rented, 0, length);
        }
        finally { ArrayPool<char>.Shared.Return(rented); }
    }

    /// <summary>
    /// Encodes <paramref name="source"/> as an unpadded uppercase Base32 character array.
    /// </summary>
    /// <param name="source">The bytes to encode. An empty span returns an empty array.</param>
    /// <returns>A new <see langword="char"/>[] containing the uppercase Base32 characters.</returns>
    public static char[] EncodeToChars(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty) return [];
        char[] chars = new char[GetEncodedLength(source.Length)];
        EncodeCore(source, chars);
        return chars;
    }

    /// <summary>
    /// Encodes <paramref name="source"/> into <paramref name="destination"/> as unpadded
    /// uppercase Base32 characters.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <param name="destination">The buffer to write characters into.</param>
    /// <param name="charsWritten">
    /// When this method returns <see langword="true"/>, the number of characters written to
    /// <paramref name="destination"/>; otherwise 0.
    /// </param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="destination"/> is smaller than
    /// <see cref="GetEncodedLength"/> for <paramref name="source"/>; otherwise <see langword="true"/>.
    /// </returns>
    public static bool TryEncodeToChars(ReadOnlySpan<byte> source, Span<char> destination, out int charsWritten)
    {
        int needed = GetEncodedLength(source.Length);
        if (destination.Length < needed)
        {
            charsWritten = 0;
            return false;
        }
        EncodeCore(source, destination);
        charsWritten = needed;
        return true;
    }

    /// <summary>
    /// Encodes <paramref name="source"/> into <paramref name="utf8Destination"/> as unpadded
    /// uppercase Base32 encoded as UTF-8 bytes.
    /// </summary>
    /// <remarks>
    /// Because all Base32 characters are ASCII, the UTF-8 and ASCII byte representations are identical.
    /// </remarks>
    /// <param name="source">The bytes to encode.</param>
    /// <param name="utf8Destination">The buffer to write UTF-8 bytes into.</param>
    /// <param name="bytesWritten">
    /// When this method returns <see langword="true"/>, the number of bytes written to
    /// <paramref name="utf8Destination"/>; otherwise 0.
    /// </param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="utf8Destination"/> is smaller than
    /// <see cref="GetEncodedLength"/> for <paramref name="source"/>; otherwise <see langword="true"/>.
    /// </returns>
    public static bool TryEncodeToUtf8(ReadOnlySpan<byte> source, Span<byte> utf8Destination, out int bytesWritten)
    {
        int needed = GetEncodedLength(source.Length);
        if (utf8Destination.Length < needed)
        {
            bytesWritten = 0;
            return false;
        }
        EncodeCoreUtf8(source, utf8Destination);
        bytesWritten = needed;
        return true;
    }

    /// <summary>
    /// Decodes the Base32 characters in <paramref name="source"/> and returns the decoded bytes.
    /// </summary>
    /// <param name="source">
    /// The Base32 characters to decode. Optional <c>=</c> padding is stripped automatically.
    /// Case-insensitive. An empty span (or all-padding) returns an empty array.
    /// </param>
    /// <returns>A new byte array containing the decoded data.</returns>
    /// <exception cref="FormatException">
    /// <paramref name="source"/> contains a character that is not in the Base32 alphabet.
    /// </exception>
    public static byte[] DecodeFromChars(ReadOnlySpan<char> source)
    {
        source = source.TrimEnd('=');
        if (source.IsEmpty) return [];
        byte[] result = new byte[GetMaxDecodedLength(source.Length)];
        if (!TryDecodeCore(source, result, out _))
            throw new FormatException("The input is not a valid Base32 string.");
        return result;
    }

    /// <summary>
    /// Decodes the Base32 characters in <paramref name="source"/> into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="source">
    /// The Base32 characters to decode. Optional <c>=</c> padding is stripped automatically.
    /// Case-insensitive.
    /// </param>
    /// <param name="destination">The buffer to write decoded bytes into.</param>
    /// <param name="bytesWritten">
    /// When this method returns <see langword="true"/>, the number of bytes written to
    /// <paramref name="destination"/>; otherwise 0.
    /// </param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="destination"/> is smaller than
    /// <see cref="GetMaxDecodedLength"/> for the stripped source length, or if
    /// <paramref name="source"/> contains an invalid character; otherwise <see langword="true"/>.
    /// </returns>
    public static bool TryDecodeFromChars(ReadOnlySpan<char> source, Span<byte> destination, out int bytesWritten)
    {
        source = source.TrimEnd('=');
        if (source.IsEmpty)
        {
            bytesWritten = 0;
            return true;
        }
        if (destination.Length < GetMaxDecodedLength(source.Length))
        {
            bytesWritten = 0;
            return false;
        }
        return TryDecodeCore(source, destination, out bytesWritten);
    }

    /// <summary>
    /// Decodes the UTF-8 encoded Base32 data in <paramref name="utf8Source"/> and returns the
    /// decoded bytes.
    /// </summary>
    /// <param name="utf8Source">
    /// The UTF-8 encoded Base32 bytes to decode. Optional <c>=</c> padding is stripped
    /// automatically. Case-insensitive. An empty span (or all-padding) returns an empty array.
    /// </param>
    /// <returns>A new byte array containing the decoded data.</returns>
    /// <exception cref="FormatException">
    /// <paramref name="utf8Source"/> contains a byte that is not in the Base32 alphabet.
    /// </exception>
    public static byte[] DecodeFromUtf8(ReadOnlySpan<byte> utf8Source)
    {
        utf8Source = utf8Source.TrimEnd((byte)'=');
        if (utf8Source.IsEmpty) return [];
        byte[] result = new byte[GetMaxDecodedLength(utf8Source.Length)];
        if (!TryDecodeCoreUtf8(utf8Source, result, out _))
            throw new FormatException("The input is not a valid Base32 string.");
        return result;
    }

    /// <summary>
    /// Decodes the UTF-8 encoded Base32 data in <paramref name="utf8Source"/> into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="utf8Source">
    /// The UTF-8 encoded Base32 bytes to decode. Optional <c>=</c> padding is stripped
    /// automatically. Case-insensitive.
    /// </param>
    /// <param name="destination">The buffer to write decoded bytes into.</param>
    /// <param name="bytesWritten">
    /// When this method returns <see langword="true"/>, the number of bytes written to
    /// <paramref name="destination"/>; otherwise 0.
    /// </param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="destination"/> is smaller than
    /// <see cref="GetMaxDecodedLength"/> for the stripped source length, or if
    /// <paramref name="utf8Source"/> contains an invalid byte; otherwise <see langword="true"/>.
    /// </returns>
    public static bool TryDecodeFromUtf8(ReadOnlySpan<byte> utf8Source, Span<byte> destination, out int bytesWritten)
    {
        utf8Source = utf8Source.TrimEnd((byte)'=');
        if (utf8Source.IsEmpty)
        {
            bytesWritten = 0;
            return true;
        }
        if (destination.Length < GetMaxDecodedLength(utf8Source.Length))
        {
            bytesWritten = 0;
            return false;
        }
        return TryDecodeCoreUtf8(utf8Source, destination, out bytesWritten);
    }

    private static void EncodeCore(ReadOnlySpan<byte> source, Span<char> destination)
    {
        int bitBuffer = 0, bitsLeft = 0, charIndex = 0;
        foreach (byte b in source)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                destination[charIndex++] = Alphabet[(bitBuffer >> bitsLeft) & 0x1F];
            }
        }
        if (bitsLeft > 0)
            destination[charIndex] = Alphabet[(bitBuffer << (5 - bitsLeft)) & 0x1F];
    }

    // All Base32 alphabet characters are ASCII (A-Z = 65-90, 2-7 = 50-55), so casting to
    // byte is always safe. Writing directly into the byte destination avoids any intermediate
    // char buffer entirely.
    private static void EncodeCoreUtf8(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int bitBuffer = 0, bitsLeft = 0, index = 0;
        foreach (byte b in source)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                destination[index++] = (byte)Alphabet[(bitBuffer >> bitsLeft) & 0x1F];
            }
        }
        if (bitsLeft > 0)
            destination[index] = (byte)Alphabet[(bitBuffer << (5 - bitsLeft)) & 0x1F];
    }

    private static bool TryDecodeCore(ReadOnlySpan<char> source, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int bitBuffer = 0, bitsLeft = 0;
        foreach (char c in source)
        {
            int val = c < 128 ? DecodeTable[c] : -1;
            if (val < 0) return false;
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

    // UTF-8 variant of TryDecodeCore: operates directly on the byte span, avoiding any
    // intermediate char buffer. Valid because all Base32 alphabet characters are ASCII
    // (values 0–127), so each UTF-8 byte maps to the same decode-table slot as the
    // equivalent char.
    private static bool TryDecodeCoreUtf8(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int bitBuffer = 0, bitsLeft = 0;
        foreach (byte b in source)
        {
            int val = b < 128 ? DecodeTable[b] : -1;
            if (val < 0) return false;
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