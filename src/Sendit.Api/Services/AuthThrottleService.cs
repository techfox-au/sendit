using Sendit.Api.Data;

namespace Sendit.Api.Services;

/// <summary>
/// Auth throttles (lockout, progressive password interval, email send budget) and
/// fixed-window IP rate limits. State is SQLite-backed so multiple API instances
/// sharing the same DB file share the same quotas.
/// </summary>
public sealed class AuthThrottleService
{
    public const int MaxAuthFails = 10;
    public static readonly TimeSpan AuthLockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>Min gap between auth emails for the first <see cref="EmailFastLaneMaxSends"/> sends.</summary>
    public static readonly TimeSpan EmailFastInterval = TimeSpan.FromSeconds(10);

    /// <summary>Min gap after the fast lane is exhausted.</summary>
    public static readonly TimeSpan EmailSlowInterval = TimeSpan.FromMinutes(1);

    /// <summary>Number of sends that use <see cref="EmailFastInterval"/> (then <see cref="EmailSlowInterval"/>).</summary>
    public const int EmailFastLaneMaxSends = 6;

    /// <summary>
    /// Notification emails (collect ready / send opened) use a separate budget that is
    /// <b>4× more permissive</b> than OTP/reset: intervals are ¼ and the fast lane is 4× as long.
    /// </summary>
    public static readonly TimeSpan NotifyEmailFastInterval = TimeSpan.FromMilliseconds(
        EmailFastInterval.TotalMilliseconds / 4);

    public static readonly TimeSpan NotifyEmailSlowInterval = TimeSpan.FromMilliseconds(
        EmailSlowInterval.TotalMilliseconds / 4);

    public const int NotifyEmailFastLaneMaxSends = EmailFastLaneMaxSends * 4;

    /// <summary>Shared fixed-window limits (match Program.cs ASP.NET policies; SQLite-shared).</summary>
    public const int AuthIpPermitLimit = 60;
    public static readonly TimeSpan AuthIpWindow = TimeSpan.FromMinutes(1);
    public const int ForgotIpPermitLimit = 30;
    public static readonly TimeSpan ForgotIpWindow = TimeSpan.FromMinutes(1);
    public const int ApiIpPermitLimit = 600;
    public static readonly TimeSpan ApiIpWindow = TimeSpan.FromMinutes(1);

    public const string RateBucketAuth = "auth";
    public const string RateBucketForgot = "forgot";
    public const string RateBucketApi = "api";

    private readonly DbConnectionFactory _db;
    private long _opsSinceCleanup;

    public AuthThrottleService(DbConnectionFactory db)
    {
        _db = db;
    }

    public static string ClientIp(HttpContext? http) =>
        http?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static string FailKey(string ip, string identity) =>
        ip + "\n" + identity.Trim().ToLowerInvariant();

    public bool IsLockedOut(string ip, string identity)
        => IsLockedOut(ip, identity, out _);

    public bool IsLockedOut(string ip, string identity, out double retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        var key = FailKey(ip, identity);
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT FailCount, LockoutUntilMs, LastAttemptMs
            FROM auth_throttle_state
            WHERE Kind = 'fail' AND Key = @k
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@k", key);

        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return false;

        var lockoutUntil = r.IsDBNull(1) ? (long?)null : r.GetInt64(1);
        r.Close();

        if (lockoutUntil is long until && until > nowMs)
        {
            retryAfterSeconds = Math.Max(1, (until - nowMs) / 1000.0);
            return true;
        }

        if (lockoutUntil is long expired && expired <= nowMs)
        {
            // Clear expired lockout so progressive interval starts clean after the window.
            using var clear = conn.CreateCommand();
            clear.CommandText = """
                UPDATE auth_throttle_state
                SET FailCount = 0, LockoutUntilMs = NULL
                WHERE Kind = 'fail' AND Key = @k AND LockoutUntilMs IS NOT NULL AND LockoutUntilMs <= @now
                """;
            clear.Parameters.AddWithValue("@k", key);
            clear.Parameters.AddWithValue("@now", nowMs);
            clear.ExecuteNonQuery();
        }

        return false;
    }

    /// <summary>Progressive min interval between password attempts for this IP+identity (cap 60s).</summary>
    public bool AllowPasswordInterval(string ip, string identity, double baseSeconds)
        => AllowPasswordInterval(ip, identity, baseSeconds, out _);

    public bool AllowPasswordInterval(string ip, string identity, double baseSeconds, out double retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        var key = FailKey(ip, identity);
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT FailCount, LastAttemptMs
            FROM auth_throttle_state
            WHERE Kind = 'fail' AND Key = @k
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@k", key);

        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return true;

        var count = r.GetInt32(0);
        var lastAttemptMs = r.GetInt64(1);
        r.Close();

        if (lastAttemptMs <= 0)
            return true;

        var baseSec = Math.Max(1.0, baseSeconds);
        var mult = 1 << Math.Min(count, 4);
        var minIntervalMs = (long)(Math.Min(baseSec * mult, 60) * 1000);
        var elapsed = nowMs - lastAttemptMs;
        if (elapsed >= minIntervalMs)
            return true;

        retryAfterSeconds = Math.Max(1, (minIntervalMs - elapsed) / 1000.0);
        return false;
    }

    public void NotePasswordAttempt(string ip, string identity)
    {
        var key = FailKey(ip, identity);
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();
        UpsertFailRow(conn, tx, key, nowMs, incrementFail: false, out _, out _);
        tx.Commit();
    }

    /// <summary>Returns true if this failure triggered a new lockout window.</summary>
    public bool RegisterFailure(string ip, string identity)
    {
        var key = FailKey(ip, identity);
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();
        UpsertFailRow(conn, tx, key, nowMs, incrementFail: true, out var newCount, out var lockedOut);
        tx.Commit();
        return lockedOut;
    }

    public void ClearFailures(string ip, string identity)
    {
        var key = FailKey(ip, identity);
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM auth_throttle_state WHERE Kind = 'fail' AND Key = @k";
        cmd.Parameters.AddWithValue("@k", key);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Transactional auth email budget (OTP / password reset share it) per address:
    /// first <see cref="EmailFastLaneMaxSends"/> sends at most once per <see cref="EmailFastInterval"/>,
    /// then at most once per <see cref="EmailSlowInterval"/>.
    /// Returns false if the current interval has not elapsed since the last recorded send.
    /// </summary>
    public bool TryAllowEmail(string email, out TimeSpan retryAfter)
    {
        // OTP / password-reset: reserve budget immediately (send is awaited on the request).
        if (!CanSendEmailBudget(email, "email", MinEmailInterval, out retryAfter))
            return false;
        NoteEmailSent(email, "email");
        return true;
    }

    /// <summary>
    /// Notification email budget (collect ready / send opened), separate from OTP/reset.
    /// 4× more permissive: shorter intervals and a longer fast lane (see notify constants).
    /// Call <see cref="NoteNotifyEmailSent"/> only after a successful send so failed
    /// SMTP/Mailgun attempts do not burn the budget.
    /// </summary>
    public bool TryAllowNotifyEmail(string email, out TimeSpan retryAfter) =>
        CanSendEmailBudget(
            email,
            kind: "notify_email",
            MinNotifyEmailInterval,
            out retryAfter);

    /// <summary>Record a successful notification email (after transport accepts it).</summary>
    public void NoteNotifyEmailSent(string email) =>
        NoteEmailSent(email, kind: "notify_email");

    /// <summary>True if the budget allows another send now (does not record a send).</summary>
    private bool CanSendEmailBudget(
        string email,
        string kind,
        Func<int, TimeSpan> minIntervalForCount,
        out TimeSpan retryAfter)
    {
        email = email.Trim().ToLowerInvariant();
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        retryAfter = TimeSpan.Zero;

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT SendCount, LastSendMs
            FROM auth_throttle_state
            WHERE Kind = @kind AND Key = @k
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@kind", kind);
        cmd.Parameters.AddWithValue("@k", email);
        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return true;

        var sendCount = r.GetInt32(0);
        var lastSendMs = r.GetInt64(1);
        if (sendCount <= 0)
            return true;

        var minInterval = minIntervalForCount(sendCount);
        var elapsed = TimeSpan.FromMilliseconds(Math.Max(0, nowMs - lastSendMs));
        if (elapsed >= minInterval)
            return true;

        retryAfter = minInterval - elapsed;
        return false;
    }

    private void NoteEmailSent(string email, string kind)
    {
        email = email.Trim().ToLowerInvariant();
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();
        int sendCount = 0;
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT SendCount FROM auth_throttle_state
                WHERE Kind = @kind AND Key = @k LIMIT 1
                """;
            sel.Parameters.AddWithValue("@kind", kind);
            sel.Parameters.AddWithValue("@k", email);
            using var r = sel.ExecuteReader();
            if (r.Read())
                sendCount = r.GetInt32(0);
        }

        sendCount++;
        using (var up = conn.CreateCommand())
        {
            up.Transaction = tx;
            up.CommandText = """
                INSERT INTO auth_throttle_state (Kind, Key, FailCount, LockoutUntilMs, LastAttemptMs, SendCount, LastSendMs)
                VALUES (@kind, @k, 0, NULL, 0, @sc, @ls)
                ON CONFLICT(Kind, Key) DO UPDATE SET
                    SendCount = @sc,
                    LastSendMs = @ls
                """;
            up.Parameters.AddWithValue("@kind", kind);
            up.Parameters.AddWithValue("@k", email);
            up.Parameters.AddWithValue("@sc", sendCount);
            up.Parameters.AddWithValue("@ls", nowMs);
            up.ExecuteNonQuery();
        }

        tx.Commit();
    }

    /// <summary>
    /// Shared fixed-window IP rate limit (multi-instance via SQLite).
    /// Returns false when the budget is exhausted (caller should return 429).
    /// </summary>
    public bool TryConsumeRateLimit(
        string bucket,
        string clientKey,
        int permitLimit,
        TimeSpan window,
        out double retryAfterSeconds)
    {
        MaybeCleanupRateEvents(window);
        retryAfterSeconds = 0;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var windowMs = (long)Math.Max(1000, window.TotalMilliseconds);
        var cutoff = nowMs - windowMs;

        using var conn = _db.Create();
        // BEGIN IMMEDIATE so concurrent multi-instance readers cannot both pass the count check.
        using (var begin = conn.CreateCommand())
        {
            begin.CommandText = "BEGIN IMMEDIATE;";
            begin.ExecuteNonQuery();
        }

        try
        {
            long? oldest = null;
            var count = 0;
            using (var sel = conn.CreateCommand())
            {
                sel.CommandText = """
                    SELECT AtMs FROM rate_limit_events
                    WHERE Bucket = @b AND ClientKey = @c AND AtMs >= @cut
                    ORDER BY AtMs ASC
                    """;
                sel.Parameters.AddWithValue("@b", bucket);
                sel.Parameters.AddWithValue("@c", clientKey);
                sel.Parameters.AddWithValue("@cut", cutoff);
                using var r = sel.ExecuteReader();
                while (r.Read())
                {
                    count++;
                    if (oldest is null)
                        oldest = r.GetInt64(0);
                }
            }

            if (count >= permitLimit)
            {
                if (oldest is long o)
                    retryAfterSeconds = Math.Max(0.1, (o + windowMs - nowMs) / 1000.0);
                else
                    retryAfterSeconds = window.TotalSeconds;
                using var rb = conn.CreateCommand();
                rb.CommandText = "ROLLBACK;";
                rb.ExecuteNonQuery();
                return false;
            }

            using (var ins = conn.CreateCommand())
            {
                ins.CommandText =
                    "INSERT INTO rate_limit_events (Bucket, ClientKey, AtMs) VALUES (@b, @c, @t)";
                ins.Parameters.AddWithValue("@b", bucket);
                ins.Parameters.AddWithValue("@c", clientKey);
                ins.Parameters.AddWithValue("@t", nowMs);
                ins.ExecuteNonQuery();
            }

            using (var commit = conn.CreateCommand())
            {
                commit.CommandText = "COMMIT;";
                commit.ExecuteNonQuery();
            }
            return true;
        }
        catch
        {
            try
            {
                using var rb = conn.CreateCommand();
                rb.CommandText = "ROLLBACK;";
                rb.ExecuteNonQuery();
            }
            catch
            {
                /* ignore */
            }
            throw;
        }
    }

    /// <summary>
    /// Interval required before the next OTP/reset email given how many were already allowed.
    /// Sends 1–6: 10s between them; send 7+: 1 minute.
    /// </summary>
    public static TimeSpan MinEmailInterval(int sendsAlreadyAllowed)
        => sendsAlreadyAllowed < EmailFastLaneMaxSends
            ? EmailFastInterval
            : EmailSlowInterval;

    /// <summary>
    /// Notification budget: 4× more permissive than <see cref="MinEmailInterval"/>.
    /// First 24 sends: ~2.5s; thereafter 15s.
    /// </summary>
    public static TimeSpan MinNotifyEmailInterval(int sendsAlreadyAllowed)
        => sendsAlreadyAllowed < NotifyEmailFastLaneMaxSends
            ? NotifyEmailFastInterval
            : NotifyEmailSlowInterval;

    private static void UpsertFailRow(
        Microsoft.Data.Sqlite.SqliteConnection conn,
        Microsoft.Data.Sqlite.SqliteTransaction tx,
        string key,
        long nowMs,
        bool incrementFail,
        out int newCount,
        out bool lockedOut)
    {
        int count = 0;
        long? lockoutUntil = null;
        long lastAttempt = 0;

        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT FailCount, LockoutUntilMs, LastAttemptMs
                FROM auth_throttle_state
                WHERE Kind = 'fail' AND Key = @k
                LIMIT 1
                """;
            sel.Parameters.AddWithValue("@k", key);
            using var r = sel.ExecuteReader();
            if (r.Read())
            {
                count = r.GetInt32(0);
                lockoutUntil = r.IsDBNull(1) ? null : r.GetInt64(1);
                lastAttempt = r.GetInt64(2);
            }
        }

        // Expired lockout: reset count like the in-memory implementation.
        if (lockoutUntil is long lu && lu <= nowMs)
        {
            count = 0;
            lockoutUntil = null;
        }

        lastAttempt = nowMs;
        lockedOut = false;
        if (incrementFail)
        {
            count++;
            if (count >= MaxAuthFails)
            {
                lockoutUntil = nowMs + (long)AuthLockoutDuration.TotalMilliseconds;
                count = 0;
                lockedOut = true;
            }
        }

        newCount = count;
        using var up = conn.CreateCommand();
        up.Transaction = tx;
        up.CommandText = """
            INSERT INTO auth_throttle_state (Kind, Key, FailCount, LockoutUntilMs, LastAttemptMs, SendCount, LastSendMs)
            VALUES ('fail', @k, @fc, @lu, @la, 0, 0)
            ON CONFLICT(Kind, Key) DO UPDATE SET
                FailCount = @fc,
                LockoutUntilMs = @lu,
                LastAttemptMs = @la
            """;
        up.Parameters.AddWithValue("@k", key);
        up.Parameters.AddWithValue("@fc", count);
        up.Parameters.AddWithValue("@lu", (object?)lockoutUntil ?? DBNull.Value);
        up.Parameters.AddWithValue("@la", lastAttempt);
        up.ExecuteNonQuery();
    }

    private void MaybeCleanupRateEvents(TimeSpan window)
    {
        if (Interlocked.Increment(ref _opsSinceCleanup) % 128 != 0)
            return;
        var cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            - (long)Math.Max(window.TotalMilliseconds, 60_000) * 2;
        try
        {
            using var conn = _db.Create();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM rate_limit_events WHERE AtMs < @cut";
            cmd.Parameters.AddWithValue("@cut", cutoff);
            cmd.ExecuteNonQuery();

            // Drop very old fail/email rows (lockouts longer than 2h, emails idle 7d).
            var failCut = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)TimeSpan.FromHours(2).TotalMilliseconds;
            using var failCmd = conn.CreateCommand();
            failCmd.CommandText = """
                DELETE FROM auth_throttle_state
                WHERE Kind = 'fail'
                  AND (LockoutUntilMs IS NULL OR LockoutUntilMs < @now)
                  AND LastAttemptMs < @cut
                """;
            failCmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            failCmd.Parameters.AddWithValue("@cut", failCut);
            failCmd.ExecuteNonQuery();

            var emailCut = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)TimeSpan.FromDays(7).TotalMilliseconds;
            using var emailCmd = conn.CreateCommand();
            emailCmd.CommandText = """
                DELETE FROM auth_throttle_state
                WHERE Kind = 'email' AND LastSendMs < @cut
                """;
            emailCmd.Parameters.AddWithValue("@cut", emailCut);
            emailCmd.ExecuteNonQuery();
        }
        catch
        {
            // ignore mid-migration
        }
    }
}
