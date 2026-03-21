using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Umbrace.Totp.Internal;

/// <summary>
/// Zero-allocation implementation of HOTP (RFC 4226) used as the foundation for TOTP.
/// All intermediate buffers are stack-allocated; the static <c>TryHashData</c> overloads
/// on the concrete HMAC types are used to avoid any heap allocation per call.
/// </summary>
internal static class HotpComputer
{
    // SHA-512 produces the largest output: 64 bytes.
    private const int MaxHmacLength = 64;

    /// <summary>
    /// Computes HOTP(<paramref name="secret"/>, <paramref name="counter"/>) using dynamic truncation per RFC 4226 §5.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The 8-byte big-endian counter value (the TOTP time step).</param>
    /// <param name="algorithm">The HMAC algorithm to use.</param>
    /// <returns>
    /// The raw 31-bit truncated integer. The caller is responsible for applying
    /// <c>% 10^digits</c> to extract the OTP value.
    /// </returns>
    internal static int Compute(ReadOnlySpan<byte> secret, long counter, OtpAlgorithm algorithm)
    {
        // Step 1 — 8-byte big-endian counter (RFC 4226 §5.2, Step 1)
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

        // Step 2 — HMAC into a stack buffer using zero-allocation static methods (RFC 4226 §5.2, Step 2).
        // TryHashData always succeeds when the destination is large enough (MaxHmacLength = 64 bytes),
        // so the bool return value is intentionally discarded.
        Span<byte> hmac = stackalloc byte[MaxHmacLength];
        int bytesWritten;

        _ = algorithm switch
        {
            OtpAlgorithm.Sha1 => HMACSHA1.TryHashData(secret, counterBytes, hmac, out bytesWritten),
            OtpAlgorithm.Sha256 => HMACSHA256.TryHashData(secret, counterBytes, hmac, out bytesWritten),
            OtpAlgorithm.Sha512 => HMACSHA512.TryHashData(secret, counterBytes, hmac, out bytesWritten),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        hmac = hmac[..bytesWritten];

        // Step 3 — dynamic truncation (RFC 4226 §5.3)
        // offset = low 4 bits of the last HMAC byte
        int offset = hmac[^1] & 0x0F;
        // read 4 bytes at offset as big-endian uint32, mask off the sign bit
        uint truncated = BinaryPrimitives.ReadUInt32BigEndian(hmac[offset..]) & 0x7FFF_FFFF;

        return (int)truncated;
    }
}