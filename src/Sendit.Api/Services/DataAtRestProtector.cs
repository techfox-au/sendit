using System.Security.Cryptography;
using System.Text;
using Sendit.Api.Configuration;

namespace Sendit.Api.Services;

/// <summary>
/// Optional extra AES-256-GCM layer for sensitive DB columns (e.g. collect owner private-key blobs).
/// Collect private keys arrive already encrypted client-side under the user data key (UDK);
/// SENDIT_DATA_KEY adds a second server-side envelope so DB theft alone cannot use those blobs
/// even if a UDK were later obtained. When unset, the UDK-wrapped ciphertext is stored as provided.
///
/// Wire format when encrypted: 0x01 || nonce(12) || ciphertext+tag
/// Pass-through (no server layer): 0x00 || client-provided bytes
/// </summary>
public sealed class DataAtRestProtector
{
    private const byte MarkerPlain = 0x00;
    private const byte MarkerEncrypted = 0x01;
    private const int NonceSize = 12;

    private readonly byte[]? _key;
    private readonly ILogger<DataAtRestProtector> _log;

    public DataAtRestProtector(SenditOptions options, ILogger<DataAtRestProtector> log)
    {
        _log = log;
        // Prefer dedicated DATA_KEY; fall back to durable ticket key so TOTP and similar
        // secrets are never stored as raw plaintext when DATA_KEY is unset.
        _key = DeriveKey(options.DataKey) ?? TicketKeyStore.GetKey(options);
        if (string.IsNullOrWhiteSpace(options.DataKey))
        {
            _log.LogInformation(
                "SENDIT_DATA_KEY is not set. Using durable ticket-key material for at-rest " +
                "encryption of TOTP secrets and new collect-key envelopes. " +
                "Set a long random SENDIT_DATA_KEY in production for a dedicated data key.");
        }
    }

    public bool IsEnabled => _key is not null;

    public byte[] Protect(byte[] plaintext)
    {
        // Always encrypt when a key is available (DATA_KEY or ticket-key fallback).
        if (_key is null)
        {
            var raw = new byte[1 + plaintext.Length];
            raw[0] = MarkerPlain;
            Buffer.BlockCopy(plaintext, 0, raw, 1, plaintext.Length);
            return raw;
        }

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(_key, 16))
        {
            aes.Encrypt(nonce, plaintext, cipher, tag);
        }

        var packed = new byte[1 + NonceSize + cipher.Length + tag.Length];
        packed[0] = MarkerEncrypted;
        Buffer.BlockCopy(nonce, 0, packed, 1, NonceSize);
        Buffer.BlockCopy(cipher, 0, packed, 1 + NonceSize, cipher.Length);
        Buffer.BlockCopy(tag, 0, packed, 1 + NonceSize + cipher.Length, tag.Length);
        return packed;
    }

    /// <summary>Encrypt a short secret string for TEXT columns (TOTP, etc.).</summary>
    public string ProtectUtf8(string plain)
    {
        var bytes = Encoding.UTF8.GetBytes(plain);
        return Convert.ToBase64String(Protect(bytes));
    }

    /// <summary>
    /// Decrypt a value written by <see cref="ProtectUtf8"/>. No legacy plaintext support.
    /// </summary>
    public string? UnprotectUtf8(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
            return null;
        var raw = Convert.FromBase64String(stored);
        return Encoding.UTF8.GetString(Unprotect(raw));
    }

    public byte[] Unprotect(byte[] stored)
    {
        if (stored.Length < 1)
            throw new CryptographicException("Empty protected blob.");

        if (stored[0] == MarkerPlain)
        {
            var plain = new byte[stored.Length - 1];
            Buffer.BlockCopy(stored, 1, plain, 0, plain.Length);
            return plain;
        }

        if (stored[0] != MarkerEncrypted)
            throw new CryptographicException("Unknown protection marker.");

        if (_key is null)
            throw new CryptographicException(
                "Data is encrypted at rest but SENDIT_DATA_KEY is not configured.");

        if (stored.Length < 1 + NonceSize + 16)
            throw new CryptographicException("Encrypted blob too short.");

        var nonce = stored.AsSpan(1, NonceSize);
        var tag = stored.AsSpan(stored.Length - 16, 16);
        var cipher = stored.AsSpan(1 + NonceSize, stored.Length - 1 - NonceSize - 16);
        var plainOut = new byte[cipher.Length];
        using (var aes = new AesGcm(_key, 16))
        {
            aes.Decrypt(nonce, cipher, tag, plainOut);
        }
        return plainOut;
    }

    private static byte[]? DeriveKey(string? dataKey)
    {
        if (string.IsNullOrWhiteSpace(dataKey))
            return null;
        // HKDF-like expansion via SHA-256 of a fixed context + configured secret.
        return SHA256.HashData(Encoding.UTF8.GetBytes("sendit-data-at-rest-v1|" + dataKey.Trim()));
    }
}
