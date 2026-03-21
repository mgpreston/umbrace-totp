using BenchmarkDotNet.Attributes;

namespace Umbrace.Totp.Benchmarks;

/// <summary>
/// Benchmarks for the hot paths in <see cref="TotpGenerator"/>: code generation and validation.
/// <see cref="GenerateCode"/> allocates only the returned code string; all other methods
/// should be zero-allocation.
/// </summary>
[MemoryDiagnoser]
public class TotpGeneratorBenchmarks
{
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();

    private TotpGenerator _generator = null!;
    private string _code = null!;
    private readonly char[] _charBuffer = new char[6];
    private readonly byte[] _byteBuffer = new byte[6];

    [GlobalSetup]
    public void Setup()
    {
        _generator = new TotpGenerator();
        _code = _generator.GenerateCode(Secret).Code;
    }

    [Benchmark]
    public GenerationResult GenerateCode() => _generator.GenerateCode(Secret);

    [Benchmark]
    public bool TryGenerateCode() => _generator.TryGenerateCode(Secret, _charBuffer, out _);

    [Benchmark]
    public bool TryGenerateCodeUtf8() => _generator.TryGenerateCodeUtf8(Secret, _byteBuffer, out _);

    [Benchmark]
    public ValidationResult ValidateCode() => _generator.ValidateCode(Secret, _code);
}