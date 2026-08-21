using Microsoft.Data.Sqlite;
using Sendit.Api.Data;

namespace Sendit.Api.Services;

/// <summary>
/// SQLite housekeeping: purge stale auth/rate-limit rows and reclaim disk space.
/// VACUUM rebuilds the database file so deleted pages are returned to the OS.
/// </summary>
public sealed class SqliteMaintenance
{
    private readonly DbConnectionFactory _db;
    private readonly ILogger<SqliteMaintenance> _log;

    public SqliteMaintenance(DbConnectionFactory db, ILogger<SqliteMaintenance> log)
    {
        _db = db;
        _log = log;
    }

    public sealed record PurgeCounts(int Sessions, int ResetTokens, int AuthTickets, int PowChallenges, int RateEvents, int ScanEvents);

    /// <summary>
    /// Delete expired sessions, used/expired reset tokens, used/expired auth tickets,
    /// expired PoW challenges, and old rate-limit / scan-event rows.
    /// Parameterized SQL only.
    /// </summary>
    public PurgeCounts PurgeAuthArtifacts()
    {
        var now = DateTimeOffset.UtcNow.ToString("O");
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        // Keep a little history past the windows used by rate/scan guards.
        var rateCutMs = nowMs - (long)TimeSpan.FromMinutes(10).TotalMilliseconds;
        var scanCutMs = nowMs - (long)TimeSpan.FromMinutes(10).TotalMilliseconds;

        int sessions;
        int tokens;
        int tickets;
        int pow;
        int rateEv;
        int scanEv;

        using var conn = _db.Create();

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM sessions WHERE ExpiresAt < @now";
            cmd.Parameters.AddWithValue("@now", now);
            sessions = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                DELETE FROM password_reset_tokens
                WHERE UsedAt IS NOT NULL OR ExpiresAt < @now
                """;
            cmd.Parameters.AddWithValue("@now", now);
            tokens = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                DELETE FROM auth_tickets
                WHERE UsedAt IS NOT NULL OR ExpiresAt < @now
                """;
            cmd.Parameters.AddWithValue("@now", now);
            tickets = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM pow_challenges WHERE ExpiresAt < @now";
            cmd.Parameters.AddWithValue("@now", now);
            pow = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM rate_limit_events WHERE AtMs < @cut";
            cmd.Parameters.AddWithValue("@cut", rateCutMs);
            rateEv = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM scan_events WHERE AtMs < @cut";
            cmd.Parameters.AddWithValue("@cut", scanCutMs);
            scanEv = cmd.ExecuteNonQuery();
        }

        return new PurgeCounts(sessions, tokens, tickets, pow, rateEv, scanEv);
    }

    /// <summary>
    /// Nightly (or on-demand) optimize: checkpoint WAL, VACUUM, PRAGMA optimize.
    /// VACUUM cannot run inside a multi-statement transaction; it needs exclusive access.
    /// </summary>
    public void OptimizeAndVacuum()
    {
        using (var conn = _db.Create())
        {
            using var checkpoint = conn.CreateCommand();
            checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            checkpoint.ExecuteNonQuery();
        }

        using (var conn = _db.Create())
        {
            using var vacuum = conn.CreateCommand();
            vacuum.CommandText = "VACUUM;";
            vacuum.CommandTimeout = 600;
            vacuum.ExecuteNonQuery();
        }

        using (var conn = _db.Create())
        {
            using var optimize = conn.CreateCommand();
            optimize.CommandText = "PRAGMA optimize;";
            optimize.ExecuteNonQuery();
        }

        _log.LogInformation("SQLite nightly maintenance completed (checkpoint, VACUUM, optimize)");
    }

    public long? TryGetFileSizeBytes(string dbPath)
    {
        try
        {
            if (File.Exists(dbPath))
                return new FileInfo(dbPath).Length;
        }
        catch
        {
            // ignore
        }
        return null;
    }
}
