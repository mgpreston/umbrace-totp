using BenchmarkDotNet.Attributes;

namespace Umbrace.Totp.Benchmarks;

/// <summary>
/// Benchmarks for <see cref="Base32"/> encoding and decoding.
/// <see cref="EncodeToString"/>, <see cref="EncodeToChars"/>, <see cref="DecodeFromChars"/>,
/// and <see cref="DecodeFromUtf8"/> each allocate their return value.
/// All <c>Try*</c> methods are zero-allocation.
/// </summary>
[MemoryDiagnoser]
public class Base32Benchmarks
{
    // 20-byte RFC 6238 SHA-1 secret — the most common real-world input size.
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();
    private static readonly string Encoded = Base32.EncodeToString(Secret);
    private static readonly byte[] EncodedUtf8 = System.Text.Encoding.ASCII.GetBytes(Encoded);

    private readonly char[] _charBuffer = new char[Base32.GetEncodedLength(20)];
    private readonly byte[] _utf8Buffer = new byte[Base32.GetEncodedLength(20)];
    private readonly byte[] _decodeBuffer = new byte[Base32.GetMaxDecodedLength(Base32.GetEncodedLength(20))];

    // ── Allocating encode ─────────────────────────────────────────────────────

    [Benchmark]
    public string EncodeToString() => Base32.EncodeToString(Secret);

    [Benchmark]
    public char[] EncodeToChars() => Base32.EncodeToChars(Secret);

    // ── Span encode (zero-allocation) ─────────────────────────────────────────

    [Benchmark]
    public bool TryEncodeToChars() => Base32.TryEncodeToChars(Secret, _charBuffer, out _);

    [Benchmark]
    public bool TryEncodeToUtf8() => Base32.TryEncodeToUtf8(Secret, _utf8Buffer, out _);

    // ── Allocating decode ─────────────────────────────────────────────────────

    [Benchmark]
    public byte[] DecodeFromChars() => Base32.DecodeFromChars(Encoded);

    [Benchmark]
    public byte[] DecodeFromUtf8() => Base32.DecodeFromUtf8(EncodedUtf8);

    // ── Span decode (zero-allocation) ─────────────────────────────────────────

    [Benchmark]
    public bool TryDecodeFromChars() => Base32.TryDecodeFromChars(Encoded, _decodeBuffer, out _);

    [Benchmark]
    public bool TryDecodeFromUtf8() => Base32.TryDecodeFromUtf8(EncodedUtf8, _decodeBuffer, out _);
}