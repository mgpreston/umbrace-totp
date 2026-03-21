using BenchmarkDotNet.Attributes;

namespace Umbrace.Totp.Benchmarks;

/// <summary>
/// Benchmarks for <see cref="TotpUri"/> construction and parsing.
/// These operations involve string allocation and Base32 encoding/decoding.
/// </summary>
[MemoryDiagnoser]
public class TotpUriBenchmarks
{
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();

    private string _uriString = null!;

    [GlobalSetup]
    public void Setup()
    {
        _uriString = new TotpUri("alice@example.com", Secret, issuer: "Example").ToString();
    }

    [Benchmark]
    public string BuildUri() =>
        new TotpUri("alice@example.com", Secret, issuer: "Example").ToString();

    [Benchmark]
    public TotpUri ParseUri() => TotpUri.Parse(_uriString);
}