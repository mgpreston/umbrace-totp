using System.Security.Cryptography;

namespace Umbrace.Totp;

/// <summary>
/// Generates and derives cryptographically secure secret keys for use with TOTP and HOTP.
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
    /// Derives a deterministic OTP secret from a master key and a per-user context using HKDF
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</see>).
    /// </summary>
    /// <param name="masterKey">
    /// The single secret stored server-side. Should be generated with <see cref="GenerateKey"/>
    /// or an equivalent cryptographically secure random source. The same master key is used
    /// across all users; it must be kept secret.
    /// </param>
    /// <param name="context">
    /// A per-user or per-account distinguisher that makes each derived key unique.
    /// Typically a UTF-8-encoded user identifier such as an email address or account ID
    /// (e.g. <c>"user@example.com"u8</c>). Two different contexts always produce different keys.
    /// </param>
    /// <param name="algorithm">
    /// The algorithm the derived key will be used with. Determines the output length and
    /// the HMAC hash function used internally: SHA-1 → 20 bytes, SHA-256 → 32 bytes,
    /// SHA-512 → 64 bytes.
    /// </param>
    /// <returns>
    /// A derived key of length <see cref="RecommendedKeyLength"/> for <paramref name="algorithm"/>.
    /// The same inputs always produce the same key.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method enables a server-side architecture where a single master key is stored
    /// rather than a per-user secret. The per-user TOTP or HOTP secret is re-derived on
    /// demand from the master key and the user's identifier, eliminating the need to persist
    /// individual secrets.
    /// </para>
    /// <para>
    /// Use <see cref="TryDeriveKey"/> to write the derived key directly into a caller-supplied
    /// buffer without allocating a result array.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="masterKey"/> is empty.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="algorithm"/> is not a valid <see cref="OtpAlgorithm"/> value.
    /// </exception>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> context,
        OtpAlgorithm algorithm = OtpAlgorithm.Sha1)
    {
        if (masterKey.IsEmpty)
            throw new ArgumentException("Master key must not be empty.", nameof(masterKey));

        HashAlgorithmName hashName = GetHashAlgorithmName(algorithm);
        int length = RecommendedKeyLength(algorithm);
        byte[] result = new byte[length];
        HKDF.DeriveKey(hashName, masterKey, result, salt: default, info: context);
        return result;
    }

    /// <summary>
    /// Derives a deterministic OTP secret from a master key and a per-user context into a
    /// caller-supplied buffer using HKDF
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</see>).
    /// </summary>
    /// <param name="masterKey">
    /// The single secret stored server-side. Should be generated with <see cref="GenerateKey"/>
    /// or an equivalent cryptographically secure random source. The same master key is used
    /// across all users; it must be kept secret.
    /// </param>
    /// <param name="context">
    /// A per-user or per-account distinguisher that makes each derived key unique.
    /// Typically a UTF-8-encoded user identifier such as an email address or account ID
    /// (e.g. <c>"user@example.com"u8</c>). Two different contexts always produce different keys.
    /// </param>
    /// <param name="destination">
    /// The buffer to write the derived key into. Must be at least
    /// <see cref="RecommendedKeyLength"/> bytes for <paramref name="algorithm"/>.
    /// </param>
    /// <param name="algorithm">
    /// The algorithm the derived key will be used with. Determines the required destination
    /// length and the HMAC hash function used internally: SHA-1 → 20 bytes, SHA-256 → 32 bytes,
    /// SHA-512 → 64 bytes.
    /// </param>
    /// <returns>
    /// <see langword="false"/> if <paramref name="destination"/> is smaller than
    /// <see cref="RecommendedKeyLength"/> for <paramref name="algorithm"/>;
    /// otherwise <see langword="true"/>. The same inputs always produce the same key.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method enables a server-side architecture where a single master key is stored
    /// rather than a per-user secret. The per-user TOTP or HOTP secret is re-derived on
    /// demand from the master key and the user's identifier, eliminating the need to persist
    /// individual secrets.
    /// </para>
    /// <para>
    /// This overload writes the derived key directly into <paramref name="destination"/>,
    /// avoiding a result array allocation. Use <see cref="DeriveKey"/> for the variant that
    /// returns a <see langword="byte"/>[].
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="masterKey"/> is empty.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="algorithm"/> is not a valid <see cref="OtpAlgorithm"/> value.
    /// </exception>
    public static bool TryDeriveKey(
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> context,
        Span<byte> destination,
        OtpAlgorithm algorithm = OtpAlgorithm.Sha1)
    {
        if (masterKey.IsEmpty)
            throw new ArgumentException("Master key must not be empty.", nameof(masterKey));

        HashAlgorithmName hashName = GetHashAlgorithmName(algorithm);
        if (destination.Length < RecommendedKeyLength(algorithm))
            return false;

        HKDF.DeriveKey(hashName, masterKey, destination, salt: default, info: context);
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

    private static HashAlgorithmName GetHashAlgorithmName(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.Sha1 => HashAlgorithmName.SHA1,
        OtpAlgorithm.Sha256 => HashAlgorithmName.SHA256,
        OtpAlgorithm.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}