namespace Umbrace.Totp.Tests;

public class AllocationTests
{
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();
    private static readonly TotpGenerator Generator = new();

    // ── Zero-allocation paths ─────────────────────────────────────────────────

    [Test]
    public async Task ValidateCode_AllocatesNothing()
    {
        // Warm up to ensure JIT compilation does not affect measurement.
        Generator.ValidateCode(Secret, "000000");

        long before = GC.GetAllocatedBytesForCurrentThread();
        Generator.ValidateCode(Secret, "000000");
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.That(allocated).IsEqualTo(0);
    }

    [Test]
    public async Task TryGenerateCode_AllocatesNothing()
    {
        Span<char> buffer = stackalloc char[6];

        Generator.TryGenerateCode(Secret, buffer, out _);

        long before = GC.GetAllocatedBytesForCurrentThread();
        Generator.TryGenerateCode(Secret, buffer, out _);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.That(allocated).IsEqualTo(0);
    }

    [Test]
    public async Task TryGenerateCodeUtf8_AllocatesNothing()
    {
        Span<byte> buffer = stackalloc byte[6];

        Generator.TryGenerateCodeUtf8(Secret, buffer, out _);

        long before = GC.GetAllocatedBytesForCurrentThread();
        Generator.TryGenerateCodeUtf8(Secret, buffer, out _);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.That(allocated).IsEqualTo(0);
    }

    [Test]
    public async Task TryGenerateKey_AllocatesNothing()
    {
        Span<byte> buffer = stackalloc byte[20];

        TotpKeyGenerator.TryGenerateKey(buffer);

        long before = GC.GetAllocatedBytesForCurrentThread();
        TotpKeyGenerator.TryGenerateKey(buffer);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.That(allocated).IsEqualTo(0);
    }

    // ── Minimal-allocation paths ──────────────────────────────────────────────

    [Test]
    public async Task GenerateCode_AllocatesOnlyCodeString()
    {
        // 6-char string: sync block (8) + method table (8) + length (4) + chars (12) + null (2) = 34, padded to 40.
        Generator.GenerateCode(Secret);

        long before = GC.GetAllocatedBytesForCurrentThread();
        Generator.GenerateCode(Secret);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        await Assert.That(allocated).IsEqualTo(40);
    }
}