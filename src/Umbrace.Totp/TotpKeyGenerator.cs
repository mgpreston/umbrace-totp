using System.Security.Cryptography;

namespace Umbrace.Totp;

/// <summary>
/// Generates cryptographically random secret keys for use with TOTP.
/// </summary>
public static class TotpKeyGenerator
{
    /// <summary>
    /// Generates a cryptographically random key of the length recommended by RFC 4226
    /// for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">
    /// The algorithm the key will be used with. Determines the output length:
    /// SHA-1 → 20 bytes, SHA-256 → 32 bytes, SHA-512 → 64 bytes.
    /// </param>
    /// <returns>A new random key of the recommended length.</returns>
    public static byte[] GenerateKey(OtpAlgorithm algorithm = OtpAlgorithm.Sha1) =>
        RandomNumberGenerator.GetBytes(RecommendedKeyLength(algorithm));

    /// <summary>
    /// Fills <paramref name="destination"/> with cryptographically random bytes if it meets
    /// the length recommended by RFC 4226 for <paramref name="algorithm"/>.
    /// </summary>
    /// <param name="destination">The buffer to fill. Must be at least <see cref="RecommendedKeyLength"/> bytes for the given algorithm.</param>
    /// <param name="algorithm">The algorithm the key will be used with.</param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="destination"/> is smaller than the recommended
    /// length for <paramref name="algorithm"/>; otherwise <see langword="true"/>.
    /// </returns>
    public static bool TryGenerateKey(Span<byte> destination, OtpAlgorithm algorithm = OtpAlgorithm.Sha1)
    {
        if (destination.Length < RecommendedKeyLength(algorithm))
            return false;
        RandomNumberGenerator.Fill(destination);
        return true;
    }

    /// <summary>
    /// Returns the RFC 4226-recommended key length in bytes for the given algorithm.
    /// SHA-1: 20, SHA-256: 32, SHA-512: 64.
    /// </summary>
    public static int RecommendedKeyLength(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.Sha1 => 20,
        OtpAlgorithm.Sha256 => 32,
        OtpAlgorithm.Sha512 => 64,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}