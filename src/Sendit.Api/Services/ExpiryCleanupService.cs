using Sendit.Api.Configuration;

namespace Sendit.Api.Services;

/// <summary>
/// Background maintenance:
/// - Every 1 minute: delete expired and consumed secrets/requests, plus stale sessions/tokens
/// - Once per UTC day at the configured hour: VACUUM + PRAGMA optimize
/// Dashboard list also purges eagerly on /api/v1/me/items so UI never lags the background job.
/// </summary>
public sealed class ExpiryCleanupService : BackgroundService
{
    private readonly SecretStore _secrets;
    private readonly RequestStore _requests;
    private readonly SqliteMaintenance _maintenance;
    private readonly SenditOptions _options;
    private readonly ILogger<ExpiryCleanupService> _log;

    /// <summary>Last UTC calendar day we ran VACUUM/optimize (null = never this process).</summary>
    private DateOnly? _lastOptimizeDateUtc;

    public ExpiryCleanupService(
        SecretStore secrets,
        RequestStore requests,
        SqliteMaintenance maintenance,
        SenditOptions options,
        ILogger<ExpiryCleanupService> log)
    {
        _secrets = secrets;
        _requests = requests;
        _maintenance = maintenance;
        _options = options;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run once soon after startup so consumed/expired rows disappear without waiting a full interval.
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RunExpiryPurge();
                MaybeRunNightlyOptimize();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Database maintenance cycle failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void RunExpiryPurge()
    {
        var s = _secrets.PurgeExpired();
        var r = _requests.PurgeExpired();
        var a = _maintenance.PurgeAuthArtifacts();

        var total = s + r + a.Sessions + a.ResetTokens + a.AuthTickets + a.PowChallenges
            + a.RateEvents + a.ScanEvents;
        if (total > 0)
        {
            _log.LogInformation(
                "Purged expired/consumed rows: secrets={Secrets}, requests={Requests}, " +
                "sessions={Sessions}, resetTokens={Tokens}, authTickets={Tickets}, " +
                "pow={Pow}, rateEvents={Rate}, scanEvents={Scan}",
                s, r, a.Sessions, a.ResetTokens, a.AuthTickets, a.PowChallenges, a.RateEvents, a.ScanEvents);
        }
    }

    /// <summary>
    /// Runs once per UTC day when the current hour equals OptimizeHourUtc (default 03:00 UTC).
    /// </summary>
    private void MaybeRunNightlyOptimize()
    {
        var now = DateTime.UtcNow;
        var today = DateOnly.FromDateTime(now);
        var hour = _options.OptimizeHourUtc;

        if (now.Hour != hour)
            return;
        if (_lastOptimizeDateUtc == today)
            return;

        var before = _maintenance.TryGetFileSizeBytes(_options.DbPath);
        try
        {
            _log.LogInformation(
                "Starting nightly SQLite optimize (hour={Hour} UTC, db={Path}, sizeBefore={Size})",
                hour, _options.DbPath, before);
            _maintenance.OptimizeAndVacuum();
            _lastOptimizeDateUtc = today;
            var after = _maintenance.TryGetFileSizeBytes(_options.DbPath);
            _log.LogInformation(
                "Nightly SQLite optimize finished (sizeBefore={Before}, sizeAfter={After})",
                before, after);
        }
        catch (Exception ex)
        {
            // Do not mark as done so the next 5-minute tick in the same hour can retry.
            _log.LogError(ex, "Nightly SQLite VACUUM/optimize failed");
        }
    }
}
