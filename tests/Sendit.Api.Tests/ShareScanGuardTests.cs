using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class ShareScanGuardTests : IDisposable
{
    private readonly string _dbPath;
    private readonly ShareScanGuard _guard;

    public ShareScanGuardTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "sendit-scan-test-" + Guid.NewGuid().ToString("N") + ".db");
        var opts = new SenditOptions { DbPath = _dbPath, ScanBudgetWindowSeconds = 60 };
        var db = new DbConnectionFactory(opts);
        using (var conn = db.Create())
            Schema.EnsureCreated(conn);
        _guard = new ShareScanGuard(opts, db);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-wal"); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-shm"); } catch { /* ignore */ }
    }

    [Fact]
    public void Failures_exhaust_budget_without_success_reset()
    {
        const string ip = "203.0.113.10";

        Assert.False(_guard.IsFailureBudgetExceeded(ip, out _));
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++)
            _guard.RecordFailure(ip);

        Assert.True(_guard.IsFailureBudgetExceeded(ip, out var retry));
        Assert.True(retry > 0);
    }

    [Fact]
    public void Mixed_failure_kinds_share_the_same_failure_budget()
    {
        const string ip = "203.0.113.99";

        // 404s and bad PoW both call RecordFailure — ten total exhausts the budget.
        for (var i = 0; i < ShareScanGuard.MaxFailuresInWindow; i++)
            _guard.RecordFailure(ip);

        Assert.True(_guard.IsFailureBudgetExceeded(ip, out _));
    }

    [Fact]
    public void Challenge_issue_budget_is_independent()
    {
        const string ip = "198.51.100.40";

        Assert.False(_guard.IsChallengeIssueBudgetExceeded(ip, out _));
        for (var i = 0; i < ShareScanGuard.MaxChallengeIssuesInWindow; i++)
            _guard.RecordChallengeIssue(ip);

        Assert.True(_guard.IsChallengeIssueBudgetExceeded(ip, out var retry));
        Assert.True(retry > 0);
        Assert.False(_guard.IsFailureBudgetExceeded(ip, out _));
    }
}
