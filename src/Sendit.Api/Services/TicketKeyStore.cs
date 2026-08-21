using System.Security.Cryptography;
using System.Text;
using Sendit.Api.Configuration;

namespace Sendit.Api.Services;

/// <summary>
/// Persistent HMAC key for auth tickets, OTP hashes, and related server MACs.
/// Prefer <c>SENDIT_TICKET_KEY</c> (high-entropy, ≥32 chars); otherwise load/create a
/// 256-bit random key file next to the DB so multi-instance shares the key with the DB volume.
/// </summary>
public static class TicketKeyStore
{
    public const string EnvName = "SENDIT_TICKET_KEY";
    public const string FileName = ".sendit-ticket-key";

    /// <summary>Minimum length of SENDIT_TICKET_KEY (characters). Short passphrases are rejected.</summary>
    public const int MinEnvKeyChars = 32;

    private static byte[]? _cached;
    private static readonly object Gate = new();

    public static byte[] GetKey(SenditOptions options)
    {
        if (_cached is not null)
            return _cached;
        lock (Gate)
        {
            if (_cached is not null)
                return _cached;

            var env = Environment.GetEnvironmentVariable(EnvName);
            if (!string.IsNullOrWhiteSpace(env))
            {
                var trimmed = env.Trim();
                if (trimmed.Length < MinEnvKeyChars)
                {
                    throw new InvalidOperationException(
                        $"{EnvName} must be at least {MinEnvKeyChars} characters of high-entropy " +
                        "random material (e.g. `openssl rand -base64 32`). Short passphrases are not allowed.");
                }
                _cached = DeriveKeyMaterial(trimmed);
                return _cached;
            }

            var path = ResolveKeyPath(options.DbPath);
            if (File.Exists(path))
            {
                var text = File.ReadAllText(path).Trim();
                if (text.Length < MinEnvKeyChars)
                {
                    throw new InvalidOperationException(
                        $"Ticket key file {path} is too short (need ≥{MinEnvKeyChars} chars). " +
                        "Delete it to regenerate, or set " + EnvName + ".");
                }
                _cached = DeriveKeyMaterial(text);
                return _cached;
            }

            // Create durable 256-bit random secret (64 hex chars) on first run.
            var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(path, secret);
            try
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // ignore
            }

            _cached = DeriveKeyMaterial(secret);
            return _cached;
        }
    }

    /// <summary>
    /// Prefer raw 32-byte key when value is 64 hex chars; otherwise SHA-256 of the secret string.
    /// </summary>
    private static byte[] DeriveKeyMaterial(string secret)
    {
        if (secret.Length == 64 && IsHex(secret))
        {
            try
            {
                return Convert.FromHexString(secret);
            }
            catch
            {
                // fall through to hash
            }
        }
        return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
        {
            var ok = c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    public static string ResolveKeyPath(string dbPath)
    {
        var full = Path.GetFullPath(string.IsNullOrWhiteSpace(dbPath) ? "sendit.db" : dbPath);
        var dir = Path.GetDirectoryName(full) ?? ".";
        return Path.Combine(dir, FileName);
    }
}
