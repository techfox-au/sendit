using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class AuthThrottleTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuthThrottleService _a;
    private readonly AuthThrottleService _b;

    public AuthThrottleTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "sendit-throttle-" + Guid.NewGuid().ToString("N") + ".db");
        var opts = new SenditOptions { DbPath = _dbPath };
        var db = new DbConnectionFactory(opts);
        using (var conn = db.Create())
            Schema.EnsureCreated(conn);
        // Two service instances = two "API processes" sharing one DB.
        _a = new AuthThrottleService(db);
        _b = new AuthThrottleService(new DbConnectionFactory(opts));
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-wal"); } catch { /* ignore */ }
        try { File.Delete(_dbPath + "-shm"); } catch { /* ignore */ }
    }

    [Fact]
    public void Failures_and_lockout_shared_across_instances()
    {
        const string ip = "1.2.3.4";
        const string email = "user@example.com";

        for (var i = 0; i < AuthThrottleService.MaxAuthFails - 1; i++)
            Assert.False(_a.RegisterFailure(ip, email));

        // Last failure on instance B should lock out both views of the state.
        Assert.True(_b.RegisterFailure(ip, email));
        Assert.True(_a.IsLockedOut(ip, email, out var retry));
        Assert.True(retry > 0);
        Assert.True(_b.IsLockedOut(ip, email));
    }

    [Fact]
    public void Email_budget_shared_across_instances()
    {
        const string email = "shared@example.com";
        Assert.True(_a.TryAllowEmail(email, out _));
        // Immediate second send via other instance must wait.
        Assert.False(_b.TryAllowEmail(email, out var retry));
        Assert.True(retry > TimeSpan.Zero);
    }

    [Fact]
    public void Shared_ip_rate_limit_shared_across_instances()
    {
        const string ip = "9.9.9.9";
        for (var i = 0; i < AuthThrottleService.AuthIpPermitLimit; i++)
        {
            Assert.True(_a.TryConsumeRateLimit(
                AuthThrottleService.RateBucketAuth,
                ip,
                AuthThrottleService.AuthIpPermitLimit,
                AuthThrottleService.AuthIpWindow,
                out _));
        }

        Assert.False(_b.TryConsumeRateLimit(
            AuthThrottleService.RateBucketAuth,
            ip,
            AuthThrottleService.AuthIpPermitLimit,
            AuthThrottleService.AuthIpWindow,
            out var retryAfter));
        Assert.True(retryAfter > 0);
    }

    [Fact]
    public void ClearFailures_clears_for_all_instances()
    {
        const string ip = "5.5.5.5";
        const string email = "clear@example.com";
        _a.RegisterFailure(ip, email);
        _a.ClearFailures(ip, email);
        Assert.False(_b.IsLockedOut(ip, email));
        Assert.True(_b.AllowPasswordInterval(ip, email, 1.0));
    }
}
