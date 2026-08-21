using Sendit.Api.Configuration;
using Sendit.Api.Data;

namespace Sendit.Api.Services;

/// <summary>
/// Anti-scanning / abuse budget for send and collect public endpoints.
/// Stored in SQLite so multiple API instances sharing the DB share the same budget.
/// Failures (404 + bad PoW) count; successes do not clear the budget.
/// </summary>
public sealed class ShareScanGuard
{
    public const int MaxFailuresInWindow = 10;
    public const int MaxChallengeIssuesInWindow = 30;

    private const string KindFailure = "fail";
    private const string KindIssue = "pow_issue";

    private readonly DbConnectionFactory _db;
    private readonly double _windowSeconds;
    private long _opsSinceCleanup;

    public ShareScanGuard(SenditOptions options, DbConnectionFactory db)
    {
        _db = db;
        // Default / floor: 60s. Explicit values must be ≥ 30s; shorter values snap to 60.
        var configured = options.ScanBudgetWindowSeconds;
        _windowSeconds = configured >= 30 ? configured : 60;
    }

    public bool IsFailureBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(KindFailure, clientKey, MaxFailuresInWindow, out retryAfterSeconds);

    public void RecordFailure(string clientKey) => Record(KindFailure, clientKey);

    public bool IsChallengeIssueBudgetExceeded(string clientKey, out double retryAfterSeconds)
        => IsBudgetExceeded(KindIssue, clientKey, MaxChallengeIssuesInWindow, out retryAfterSeconds);

    public void RecordChallengeIssue(string clientKey) => Record(KindIssue, clientKey);

    public static string ClientKey(HttpContext http) =>
        Util.ClientIp.Get(http)?.ToString() ?? "unknown";

    private bool IsBudgetExceeded(string kind, string clientKey, int max, out double retryAfterSeconds)
    {
        MaybeCleanup();
        retryAfterSeconds = 0;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var cutoff = nowMs - (long)(_windowSeconds * 1000);

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT AtMs FROM scan_events
            WHERE Kind = @kind AND ClientKey = @ck AND AtMs >= @cut
            ORDER BY AtMs ASC
            """;
        cmd.Parameters.AddWithValue("@kind", kind);
        cmd.Parameters.AddWithValue("@ck", clientKey);
        cmd.Parameters.AddWithValue("@cut", cutoff);

        long? oldest = null;
        var count = 0;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            count++;
            if (oldest is null)
                oldest = r.GetInt64(0);
        }

        if (count < max)
            return false;

        if (oldest is long o)
            retryAfterSeconds = Math.Max(0.1, (o + (long)(_windowSeconds * 1000) - nowMs) / 1000.0);
        else
            retryAfterSeconds = _windowSeconds;
        return true;
    }

    private void Record(string kind, string clientKey)
    {
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO scan_events (Kind, ClientKey, AtMs) VALUES (@k, @c, @t)";
        cmd.Parameters.AddWithValue("@k", kind);
        cmd.Parameters.AddWithValue("@c", clientKey);
        cmd.Parameters.AddWithValue("@t", nowMs);
        cmd.ExecuteNonQuery();
        MaybeCleanup();
    }

    private void MaybeCleanup()
    {
        if (Interlocked.Increment(ref _opsSinceCleanup) % 256 != 0)
            return;
        var cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)(_windowSeconds * 1000);
        try
        {
            using var conn = _db.Create();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM scan_events WHERE AtMs < @cut";
            cmd.Parameters.AddWithValue("@cut", cutoff);
            cmd.ExecuteNonQuery();
        }
        catch
        {
            // ignore mid-migration
        }
    }
}
