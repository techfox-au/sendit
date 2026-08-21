using System.Security.Cryptography;
using System.Text;
using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class ProofOfWorkTests : IDisposable
{
    private readonly string _dbPath;
    private readonly ProofOfWorkService _pow;

    public ProofOfWorkTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "sendit-pow-test-" + Guid.NewGuid().ToString("N") + ".db");
        var opts = new SenditOptions
        {
            DbPath = _dbPath,
            PowDifficultyBits = 8,
            PowChallengeTtlSeconds = 120
        };
        var db = new DbConnectionFactory(opts);
        using (var conn = db.Create())
            Schema.EnsureCreated(conn);
        _pow = new ProofOfWorkService(opts, db);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-wal"); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-shm"); } catch { /* ignore */ }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(12)]
    public void HasLeadingZeroBits_matches_manual_count(int bits)
    {
        var hash = new byte[32];
        if (bits < 256)
        {
            var byteIndex = bits / 8;
            var bitInByte = bits % 8;
            if (bitInByte == 0 && bits > 0)
            {
                if (byteIndex < 32)
                    hash[byteIndex] = 0x80;
            }
            else if (byteIndex < 32)
            {
                hash[byteIndex] = (byte)(1 << (7 - bitInByte));
            }
        }

        Assert.True(ProofOfWorkService.HasLeadingZeroBits(hash, bits));
        if (bits > 0)
            Assert.False(ProofOfWorkService.HasLeadingZeroBits(hash, bits + 1));
    }

    [Fact]
    public void Issue_and_consume_valid_solution()
    {
        var ch = _pow.Issue("send", "abc123");

        var key = Base64UrlDecode(ch.HmacKey);
        string? nonce = null;
        byte[]? mac = null;
        for (var n = 0; n < 1_000_000; n++)
        {
            var s = n.ToString();
            var m = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(s));
            if (ProofOfWorkService.HasLeadingZeroBits(m, ch.DifficultyBits))
            {
                nonce = s;
                mac = m;
                break;
            }
        }
        Assert.NotNull(nonce);
        Assert.NotNull(mac);

        var err = _pow.TryConsume("send", "abc123", ch.ChallengeId, nonce, Base64UrlEncode(mac!));
        Assert.Null(err);

        var err2 = _pow.TryConsume("send", "abc123", ch.ChallengeId, nonce, Base64UrlEncode(mac!));
        Assert.NotNull(err2);
    }

    [Fact]
    public void Issue_without_resource_uses_configured_ttl()
    {
        var before = DateTimeOffset.UtcNow;
        var ch = _pow.Issue("send", "missing-id-xyz");
        var chExp = DateTimeOffset.Parse(ch.ExpiresAt);
        Assert.True(chExp > before.AddSeconds(100));
        Assert.True(chExp <= before.AddSeconds(125));
    }

    [Fact]
    public void Wrong_resource_rejected()
    {
        var opts = new SenditOptions
        {
            DbPath = _dbPath,
            PowDifficultyBits = 4,
            PowChallengeTtlSeconds = 120
        };
        var pow = new ProofOfWorkService(opts, new DbConnectionFactory(opts));
        var ch = pow.Issue("send", "id-a");
        var key = Base64UrlDecode(ch.HmacKey);
        string? nonce = null;
        for (var n = 0; n < 100_000; n++)
        {
            var s = n.ToString();
            var m = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(s));
            if (ProofOfWorkService.HasLeadingZeroBits(m, ch.DifficultyBits))
            {
                nonce = s;
                break;
            }
        }
        Assert.NotNull(nonce);
        var err = pow.TryConsume("send", "id-b", ch.ChallengeId, nonce, null);
        Assert.NotNull(err);
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
