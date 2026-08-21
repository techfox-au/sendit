using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// HMAC-SHA256 proof-of-work for send/collect ID access, collect upload, and auth
/// (login, email-OTP, TOTP, forgot-password). Difficulty is always at least
/// <see cref="SenditOptions.MinPowDifficultyBits"/> (PoW cannot be disabled).
/// Each challenge is one-time: successful <see cref="TryConsume"/> deletes the SQLite row
/// so the same challengeId cannot be replayed. Shared DB enables multi-instance validation.
/// </summary>
public sealed class ProofOfWorkService
{
    private readonly DbConnectionFactory _db;
    private readonly int _difficultyBits;
    private readonly TimeSpan _ttl;
    private long _lastPruneMs;

    public ProofOfWorkService(SenditOptions options, DbConnectionFactory db)
    {
        _db = db;
        _difficultyBits = Math.Clamp(
            options.PowDifficultyBits,
            SenditOptions.MinPowDifficultyBits,
            28);
        _ttl = TimeSpan.FromSeconds(Math.Clamp(options.PowChallengeTtlSeconds, 30, 600));
    }

    public int DifficultyBits => _difficultyBits;

    public sealed record ChallengeIssue(
        string ChallengeId,
        string HmacKey,
        int DifficultyBits,
        string ExpiresAt);

    public ChallengeIssue Issue(string resourceKind, string resourceId)
        => Issue(resourceKind, resourceId, DateTimeOffset.UtcNow.Add(_ttl));

    public ChallengeIssue Issue(string resourceKind, string resourceId, DateTimeOffset resourceExpiresAt)
    {
        PruneIfNeeded();
        var now = DateTimeOffset.UtcNow;
        if (resourceExpiresAt <= now)
            throw new InvalidOperationException("Cannot issue PoW for an already-expired secret.");

        var id = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
        var key = RandomNumberGenerator.GetBytes(32);
        var exp = now.Add(_ttl);
        if (resourceExpiresAt < exp)
            exp = resourceExpiresAt;

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO pow_challenges (Id, ResourceKind, ResourceId, HmacKey, DifficultyBits, ExpiresAt)
            VALUES (@id, @kind, @rid, @key, @bits, @exp)
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@kind", resourceKind);
        cmd.Parameters.AddWithValue("@rid", resourceId);
        cmd.Parameters.AddWithValue("@key", key);
        cmd.Parameters.AddWithValue("@bits", _difficultyBits);
        cmd.Parameters.AddWithValue("@exp", exp.ToString("O"));
        cmd.ExecuteNonQuery();

        return new ChallengeIssue(id, Base64Url.Encode(key), _difficultyBits, exp.ToString("O"));
    }

    /// <summary>
    /// Validate PoW and consume the challenge (one-time DELETE). Returns null on success,
    /// error message on failure. Always requires a live challenge (no zero-difficulty bypass).
    /// Does not burn secrets — callers burn payload only after this returns null.
    /// </summary>
    public string? TryConsume(
        string resourceKind,
        string resourceId,
        string? challengeId,
        string? nonce,
        string? hashB64)
    {
        if (string.IsNullOrWhiteSpace(challengeId) || string.IsNullOrWhiteSpace(nonce))
            return "Proof of work is required (challengeId and nonce).";

        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();

        using var sel = conn.CreateCommand();
        sel.Transaction = tx;
        sel.CommandText = """
            SELECT ResourceKind, ResourceId, HmacKey, DifficultyBits, ExpiresAt
            FROM pow_challenges WHERE Id = @id LIMIT 1
            """;
        sel.Parameters.AddWithValue("@id", challengeId);
        using var r = sel.ExecuteReader();
        if (!r.Read())
        {
            tx.Rollback();
            return "Unknown or expired proof-of-work challenge.";
        }

        var kind = r.GetString(0);
        var rid = r.GetString(1);
        var key = (byte[])r[2];
        var bits = r.GetInt32(3);
        var exp = DateTimeOffset.Parse(r.GetString(4));
        r.Close();

        if (exp < DateTimeOffset.UtcNow)
        {
            using var delExp = conn.CreateCommand();
            delExp.Transaction = tx;
            delExp.CommandText = "DELETE FROM pow_challenges WHERE Id = @id";
            delExp.Parameters.AddWithValue("@id", challengeId);
            delExp.ExecuteNonQuery();
            tx.Commit();
            return "Proof-of-work challenge expired.";
        }

        if (!string.Equals(kind, resourceKind, StringComparison.Ordinal)
            || !string.Equals(rid, resourceId, StringComparison.Ordinal))
        {
            tx.Rollback();
            return "Proof-of-work challenge does not match this secret.";
        }

        if (nonce.Length is 0 or > 24 || !nonce.All(char.IsAsciiDigit))
        {
            tx.Rollback();
            return "Invalid proof-of-work nonce.";
        }
        if (nonce.Length > 1 && nonce[0] == '0')
        {
            tx.Rollback();
            return "Invalid proof-of-work nonce.";
        }

        var mac = ComputeHmac(key, nonce);
        if (!HasLeadingZeroBits(mac, bits))
        {
            tx.Rollback();
            return "Proof of work does not meet difficulty.";
        }

        if (!string.IsNullOrWhiteSpace(hashB64))
        {
            try
            {
                var presented = Base64Url.Decode(hashB64);
                if (!CryptographicOperations.FixedTimeEquals(mac, presented))
                {
                    tx.Rollback();
                    return "Proof-of-work hash does not match.";
                }
            }
            catch
            {
                tx.Rollback();
                return "Invalid proof-of-work hash encoding.";
            }
        }

        // One-time consume
        using var del = conn.CreateCommand();
        del.Transaction = tx;
        del.CommandText = "DELETE FROM pow_challenges WHERE Id = @id";
        del.Parameters.AddWithValue("@id", challengeId);
        if (del.ExecuteNonQuery() != 1)
        {
            tx.Rollback();
            return "Proof-of-work challenge already used.";
        }

        tx.Commit();
        return null;
    }

    public static byte[] ComputeHmac(byte[] key, string nonceAscii)
    {
        var data = Encoding.ASCII.GetBytes(nonceAscii);
        return HMACSHA256.HashData(key, data);
    }

    /// <summary>
    /// Pure bit-check helper. Production difficulty is always ≥ 1; bits ≤ 0 is only a
    /// mathematical vacuous case (any hash "satisfies" zero leading zero bits).
    /// </summary>
    public static bool HasLeadingZeroBits(ReadOnlySpan<byte> hash, int bits)
    {
        if (bits <= 0)
            return true;
        if (bits > hash.Length * 8)
            return false;

        var fullBytes = bits / 8;
        var rem = bits % 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (hash[i] != 0)
                return false;
        }
        if (rem == 0)
            return true;
        var mask = (byte)(0xFF << (8 - rem));
        return (hash[fullBytes] & mask) == 0;
    }

    private void PruneIfNeeded()
    {
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (nowMs - Interlocked.Read(ref _lastPruneMs) < 30_000)
            return;
        Interlocked.Exchange(ref _lastPruneMs, nowMs);
        try
        {
            using var conn = _db.Create();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM pow_challenges WHERE ExpiresAt < @now";
            cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        catch
        {
            // table may not exist mid-migration
        }
    }
}
