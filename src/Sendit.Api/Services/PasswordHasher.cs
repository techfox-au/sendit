using System.Security.Cryptography;
using Sendit.Api.Configuration;

namespace Sendit.Api.Services;

/// <summary>
/// Password hashing using PBKDF2-HMAC-SHA512.
///
/// Parameters (design-locked):
/// - PRF: HMAC-SHA512
/// - Iterations: 893,241 (configurable only for tests / future rotation via stored column)
/// - Salt: 64 cryptographically random bytes, unique per password
/// - Derived key length: 64 bytes
///
/// Construction (RFC 8018):
///   salt ← CSPRNG(64)
///   dk   ← PBKDF2-HMAC-SHA512(password, salt, iterations, dkLen=64)
///   store (salt, dk, iterations)
///
/// Verification uses a constant-time comparison.
/// </summary>
public sealed class PasswordHasher
{
    public const int DefaultIterations = 893_241;
    public const int SaltSize = 64;
    public const int DerivedKeySize = 64;
    public const int MinPasswordLength = 8;
    public const int MaxPasswordLength = Util.FieldLimits.Password;

    private readonly int _iterations;

    public PasswordHasher(SenditOptions options)
    {
        _iterations = options.PasswordHashIterations > 0
            ? options.PasswordHashIterations
            : DefaultIterations;
    }

    public PasswordHashResult Hash(string password)
    {
        if (password.Length < MinPasswordLength)
            throw new ArgumentException($"Password must be at least {MinPasswordLength} characters.", nameof(password));
        if (password.Length > MaxPasswordLength)
            throw new ArgumentException($"Password must be at most {MaxPasswordLength} characters.", nameof(password));

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Pbkdf2(password, salt, _iterations);
        return new PasswordHashResult(salt, hash, _iterations);
    }

    public bool Verify(string password, byte[] salt, byte[] expectedHash, int iterations)
    {
        if (password.Length > MaxPasswordLength)
            return false;
        if (salt.Length != SaltSize || expectedHash.Length != DerivedKeySize || iterations < 1)
            return false;

        var actual = Pbkdf2(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }

    private static byte[] Pbkdf2(string password, byte[] salt, int iterations)
    {
        // Password is the HMAC key material; salt is the PBKDF2 salt (RFC 8018).
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            DerivedKeySize);
    }
}

public readonly record struct PasswordHashResult(byte[] Salt, byte[] Hash, int Iterations);
