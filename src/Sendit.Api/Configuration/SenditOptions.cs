namespace Sendit.Api.Configuration;

/// <summary>
/// Application configuration bound from environment variables / appsettings.
/// All secrets and limits for the Sendit! API live here.
/// </summary>
public sealed class SenditOptions
{
    /// <summary>appsettings.json section name (not the product brand string).</summary>
    public const string SectionName = "Sendit";

    /// <summary>Path to the SQLite database file.</summary>
    public string DbPath { get; set; } = "sendit.db";

    /// <summary>
    /// Large request body / ciphertext limit for:
    /// authenticated <c>POST /api/v1/send</c> and <c>POST /api/v1/collect</c>,
    /// and public <c>POST /api/v1/collect/{id}/upload</c>.
    /// Default is ~200 MB + <b>5%</b> headroom so host nginx (<c>client_max_body_size 200m</c>)
    /// rejects oversized bodies first; Kestrel does not 413 after the proxy already accepted.
    /// </summary>
    public long MaxUploadBytes { get; set; } = 210_000_000; // 200_000_000 * 1.05

    /// <summary>
    /// Default max request body size for all other endpoints (auth, meta, etc.).
    /// Default is 256 KiB + <b>5%</b> headroom so host nginx (<c>client_max_body_size 256k</c>)
    /// rejects first. Enough for auth/UDK JSON; large secrets use MaxUploadBytes routes.
    /// Set via <c>SENDIT_MAX_REQUEST_BODY_BYTES</c>.
    /// </summary>
    public long MaxRequestBodyBytes { get; set; } = 275_251; // (256 * 1024) * 1.05

    /// <summary>
    /// Per-user storage quota in megabytes for owned send/collect ciphertext blobs.
    /// Default 1024 (1 GiB). Set via <c>SENDIT_USER_STORAGE_QUOTA</c> (integer MB, min 1).
    /// </summary>
    public int UserStorageQuotaMb { get; set; } = 1024;

    /// <summary>Quota in bytes derived from <see cref="UserStorageQuotaMb"/>.</summary>
    public long UserStorageQuotaBytes => (long)UserStorageQuotaMb * 1024L * 1024L;

    /// <summary>Maximum secret/request lifetime in hours (default 1080 = 45 days).</summary>
    public int MaxExpiryHours { get; set; } = 1080;

    /// <summary>Minimum secret/request lifetime in minutes (default 1).</summary>
    public int MinExpiryMinutes { get; set; } = 1;

    /// <summary>
    /// UTC hour (0–23) when nightly SQLite VACUUM + PRAGMA optimize runs.
    /// Default 3 = 03:00 UTC.
    /// </summary>
    public int OptimizeHourUtc { get; set; } = 3;

    /// <summary>
    /// Sliding-window length (seconds) for the share/collect scan budget.
    /// Default 60. Values below 30 are treated as 60 (see <see cref="Services.ShareScanGuard"/>).
    /// Set via SENDIT_SCAN_BUDGET_WINDOW_SECONDS.
    /// </summary>
    public double ScanBudgetWindowSeconds { get; set; } = 60;

    /// <summary>
    /// Optional extra server-side AES-256-GCM layer on already UDK-wrapped collect key blobs.
    /// Does not replace client UDK encryption. Set via SENDIT_DATA_KEY.
    /// </summary>
    public string? DataKey { get; set; }

    /// <summary>
    /// Domains allowed to register (lowercase, no @).
    /// Empty list or a lone entry "*" = any domain may register.
    /// Set via SENDIT_ALLOWED_EMAIL_DOMAINS=example.com,example.com.au
    /// or SENDIT_ALLOWED_EMAIL_DOMAINS=*
    /// </summary>
    public HashSet<string> AllowedEmailDomains { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Exact email addresses banned from <em>registration</em> (normalized lowercase).
    /// Empty = none banned. Existing accounts may still log in.
    /// Set via <c>SENDIT_BANNED_EMAILS=bad@example.com,spam@evil.org</c>.
    /// </summary>
    public HashSet<string> BannedEmails { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Public base URL used in password-reset emails (e.g. https://sendit.example.com).</summary>
    public string PublicBaseUrl { get; set; } = "http://localhost:8080";

    /// <summary>
    /// Default public Cloudflare Worker canary (shared; override with env if needed).
    /// </summary>
    public const string DefaultIpCheckWorkerUrl =
        "https://sendit-check-ip.domains-8c1.workers.dev";

    /// <summary>
    /// Cloudflare Worker canary URL. One-shot startup probe POSTs <see cref="PublicBaseUrl"/>
    /// to this Worker. Default: <see cref="DefaultIpCheckWorkerUrl"/>. Override or clear via
    /// <c>SENDIT_IP_CHECK_WORKER_URL</c> (empty / <c>0</c> / <c>off</c> / <c>false</c> disables).
    /// </summary>
    public string? IpCheckWorkerUrl { get; set; } = DefaultIpCheckWorkerUrl;

    /// <summary>
    /// Default Bearer for the public default Worker (<c>CALLER_SECRET</c> on that Worker).
    /// </summary>
    public const string DefaultIpCheckWorkerCallerSecret =
        "18c471779a90d164c6e47df4e67770114cdd32c6b425f718dbcdb31f9a5c97dd";

    /// <summary>
    /// Bearer token sent to the Worker when it requires <c>CALLER_SECRET</c>.
    /// Default: <see cref="DefaultIpCheckWorkerCallerSecret"/>. Override or clear via
    /// <c>SENDIT_IP_CHECK_WORKER_CALLER_SECRET</c> (empty / <c>0</c> / <c>off</c> / <c>false</c> = no auth header).
    /// Not used by the diagnostics endpoint.
    /// </summary>
    public string? IpCheckWorkerCallerSecret { get; set; } = DefaultIpCheckWorkerCallerSecret;

    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public string? SmtpUser { get; set; }
    public string? SmtpPassword { get; set; }
    public string SmtpFrom { get; set; } = "noreply@localhost";
    public bool SmtpEnableSsl { get; set; } = true;

    /// <summary>
    /// Mailgun sending domain (e.g. <c>mg.example.com</c>).
    /// Set via <c>SENDIT_MAILGUN_DOMAIN</c>. Used when SMTP is unset, or as failover if SMTP fails.
    /// </summary>
    public string? MailgunDomain { get; set; }

    /// <summary>Mailgun private API key. Set via <c>SENDIT_MAILGUN_API_KEY</c>.</summary>
    public string? MailgunApiKey { get; set; }

    /// <summary>
    /// From header for Mailgun (e.g. <c>Sendit! &lt;noreply@mg.example.com&gt;</c>).
    /// Defaults to <see cref="SmtpFrom"/> when unset. Set via <c>SENDIT_MAILGUN_FROM</c>.
    /// </summary>
    public string? MailgunFrom { get; set; }

    /// <summary>
    /// Mailgun API base (no trailing slash). Default US: <c>https://api.mailgun.net</c>.
    /// EU: <c>https://api.eu.mailgun.net</c>. Set via <c>SENDIT_MAILGUN_BASE_URL</c>.
    /// </summary>
    public string MailgunBaseUrl { get; set; } = "https://api.mailgun.net";

    /// <summary>True when SMTP host is configured.</summary>
    public bool IsSmtpConfigured => !string.IsNullOrWhiteSpace(SmtpHost);

    /// <summary>True when Mailgun domain + API key are configured.</summary>
    public bool IsMailgunConfigured =>
        !string.IsNullOrWhiteSpace(MailgunDomain) && !string.IsNullOrWhiteSpace(MailgunApiKey);

    /// <summary>True when at least one transport (SMTP or Mailgun) is configured.</summary>
    public bool IsEmailTransportConfigured => IsSmtpConfigured || IsMailgunConfigured;

    /// <summary>PBKDF2 iteration count (locked by design: 893241).</summary>
    public int PasswordHashIterations { get; set; } = 893_241;

    /// <summary>Minimum password length (locked by design: 8).</summary>
    public int MinPasswordLength { get; set; } = 8;

    /// <summary>Maximum password length (account + link passwords).</summary>
    public int MaxPasswordLength { get; set; } = Util.FieldLimits.Password;

    /// <summary>Minimum seconds between password verification attempts per account.</summary>
    public double PasswordAttemptIntervalSeconds { get; set; } = 2.0;

    /// <summary>
    /// Optional path for security/audit log file (in addition to console).
    /// Set via SENDIT_LOG_FILE=/var/log/sendit/security.log
    /// </summary>
    public string? LogFile { get; set; }

    /// <summary>
    /// Minimum log level for console and optional file logger.
    /// <c>INFO</c> (default) = Information+, <c>WARNING</c> = Warning+, <c>ERROR</c> = Error+.
    /// Set via <c>SENDIT_LOG_LEVEL</c>.
    /// </summary>
    public Microsoft.Extensions.Logging.LogLevel MinLogLevel { get; set; } =
        Microsoft.Extensions.Logging.LogLevel.Information;

    /// <summary>
    /// UI highlight / accent color as resolved #RRGGBB. Default gold <c>#c8ab37</c>.
    /// Set via SENDIT_HIGHLIGHT=#c8ab37. Use <c>#random</c> (or <c>random</c>) to pick a
    /// random accent once at process start; the resolved hex is stored here for the
    /// lifetime of the process. Invalid values fall back to the default.
    /// </summary>
    public string Highlight { get; set; } = "#c8ab37";

    /// <summary>
    /// When true, Kestrel does not emit browser security headers (CSP, HSTS-related suite,
    /// COOP, etc.). Use when TLS/static are terminated by host nginx
    /// so responses are not dual-headed. Set via SENDIT_EDGE_SECURITY_HEADERS=1|true.
    /// Default false (dev / direct Kestrel exposure still gets headers).
    /// </summary>
    public bool EdgeSecurityHeaders { get; set; }

    /// <summary>Minimum allowed PoW difficulty (never off — values below this clamp to 1).</summary>
    public const int MinPowDifficultyBits = 1;

    /// <summary>Recommended production minimum (also the default). Below this logs a startup warning.</summary>
    public const int RecommendedPowDifficultyBits = 12;

    /// <summary>
    /// HMAC-SHA256 proof-of-work difficulty in leading zero <em>bits</em> for send/collect ID access
    /// and auth login / email-OTP registration.
    /// Default 12 (~4k average HMAC tries). Always at least <see cref="MinPowDifficultyBits"/> (never off). Max 28.
    /// Set via SENDIT_POW_DIFFICULTY_BITS (values &lt; 1 are raised to 1).
    /// </summary>
    public int PowDifficultyBits { get; set; } = RecommendedPowDifficultyBits;

    /// <summary>PoW challenge lifetime in seconds (default 120). Set via SENDIT_POW_CHALLENGE_TTL_SECONDS.</summary>
    public int PowChallengeTtlSeconds { get; set; } = 120;

    /// <summary>
    /// Server-wide allow-list for <em>retrieving</em> submitted collect payloads
    /// (GET /api/v1/collect/{id}/payload). Comma-separated IPv4/IPv6 or CIDRs.
    /// Null/empty or <c>*</c> = any IP. Upload and public collect GET are not restricted.
    /// Set via SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS.
    /// </summary>
    public string? CollectionRetrieveAllowedIps { get; set; }

    public static SenditOptions FromEnvironment()
    {
        var o = new SenditOptions();
        o.DbPath = Env("SENDIT_DB_PATH", o.DbPath);
        if (long.TryParse(Environment.GetEnvironmentVariable("SENDIT_MAX_UPLOAD_BYTES"), out var maxUp))
            o.MaxUploadBytes = maxUp;
        if (long.TryParse(Environment.GetEnvironmentVariable("SENDIT_MAX_REQUEST_BODY_BYTES"), out var maxBody)
            && maxBody >= 1)
            o.MaxRequestBodyBytes = maxBody;
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_USER_STORAGE_QUOTA"), out var quotaMb)
            && quotaMb >= 1)
            o.UserStorageQuotaMb = quotaMb;
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_MAX_EXPIRY_HOURS"), out var maxExp))
            o.MaxExpiryHours = maxExp;
        o.PublicBaseUrl = Env("SENDIT_PUBLIC_BASE_URL", o.PublicBaseUrl).TrimEnd('/');
        // Worker canary URL / caller Bearer: unset env → built-in defaults; empty/off → null (disabled).
        if (TryReadOptionalEnv("SENDIT_IP_CHECK_WORKER_URL", out var workerUrl, trimEndSlash: true))
            o.IpCheckWorkerUrl = workerUrl;
        if (TryReadOptionalEnv("SENDIT_IP_CHECK_WORKER_CALLER_SECRET", out var workerCaller, trimEndSlash: false))
            o.IpCheckWorkerCallerSecret = workerCaller;
        o.SmtpHost = Environment.GetEnvironmentVariable("SENDIT_SMTP_HOST");
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_SMTP_PORT"), out var port))
            o.SmtpPort = port;
        o.SmtpUser = Environment.GetEnvironmentVariable("SENDIT_SMTP_USER");
        o.SmtpPassword = Environment.GetEnvironmentVariable("SENDIT_SMTP_PASSWORD");
        o.SmtpFrom = Env("SENDIT_SMTP_FROM", o.SmtpFrom);
        if (bool.TryParse(Environment.GetEnvironmentVariable("SENDIT_SMTP_ENABLE_SSL"), out var ssl))
            o.SmtpEnableSsl = ssl;

        o.MailgunDomain = Environment.GetEnvironmentVariable("SENDIT_MAILGUN_DOMAIN");
        o.MailgunApiKey = Environment.GetEnvironmentVariable("SENDIT_MAILGUN_API_KEY");
        o.MailgunFrom = Environment.GetEnvironmentVariable("SENDIT_MAILGUN_FROM");
        var mgBase = Environment.GetEnvironmentVariable("SENDIT_MAILGUN_BASE_URL");
        if (!string.IsNullOrWhiteSpace(mgBase))
            o.MailgunBaseUrl = mgBase.Trim().TrimEnd('/');
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_OPTIMIZE_HOUR_UTC"), out var optHour)
            && optHour is >= 0 and <= 23)
            o.OptimizeHourUtc = optHour;
        if (double.TryParse(Environment.GetEnvironmentVariable("SENDIT_SCAN_BUDGET_WINDOW_SECONDS"),
                out var windowSec) && windowSec > 0)
            o.ScanBudgetWindowSeconds = windowSec;
        o.DataKey = Environment.GetEnvironmentVariable("SENDIT_DATA_KEY");
        o.AllowedEmailDomains = ParseDomainList(
            Environment.GetEnvironmentVariable("SENDIT_ALLOWED_EMAIL_DOMAINS"));
        o.BannedEmails = ParseEmailList(
            Environment.GetEnvironmentVariable("SENDIT_BANNED_EMAILS"));
        o.LogFile = Environment.GetEnvironmentVariable("SENDIT_LOG_FILE");
        if (string.IsNullOrWhiteSpace(o.LogFile))
            o.LogFile = null;
        o.MinLogLevel = ParseLogLevel(
            Environment.GetEnvironmentVariable("SENDIT_LOG_LEVEL"),
            Microsoft.Extensions.Logging.LogLevel.Information);
        var hl = Environment.GetEnvironmentVariable("SENDIT_HIGHLIGHT");
        if (!string.IsNullOrWhiteSpace(hl))
        {
            // #random → concrete hex once per process (theme/logo stay stable until restart).
            if (Util.HighlightColor.IsRandomToken(hl))
                o.Highlight = Util.HighlightColor.RandomAccent().ToHex();
            else if (Util.HighlightColor.TryParse(hl, out var parsed))
                o.Highlight = parsed.ToHex();
            // else keep default; invalid values ignored
        }
        o.EdgeSecurityHeaders = ParseTruthy(
            Environment.GetEnvironmentVariable("SENDIT_EDGE_SECURITY_HEADERS"));
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_POW_DIFFICULTY_BITS"), out var powBits))
            o.PowDifficultyBits = powBits;
        // PoW is never off: clamp after env so 0 / negative become 1 (always issue challenges).
        o.PowDifficultyBits = Math.Clamp(o.PowDifficultyBits, MinPowDifficultyBits, 28);
        if (int.TryParse(Environment.GetEnvironmentVariable("SENDIT_POW_CHALLENGE_TTL_SECONDS"), out var powTtl)
            && powTtl is >= 30 and <= 600)
            o.PowChallengeTtlSeconds = powTtl;

        var collectIps = Environment.GetEnvironmentVariable("SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS");
        if (!Util.IpRestriction.TryNormalize(collectIps, out var collectCanon, out var collectErr))
        {
            throw new InvalidOperationException(
                "SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS is invalid: " + collectErr);
        }
        o.CollectionRetrieveAllowedIps = collectCanon;

        return o;
    }

    /// <summary>
    /// Parse "example.com, example.com.au" or "*" into a normalized domain set.
    /// "*" alone means any domain (also accepted mixed in the list as a full open).
    /// </summary>
    public static HashSet<string> ParseDomainList(string? raw)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
            return set;
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var d = part.Trim().TrimStart('@').Trim().ToLowerInvariant();
            if (d.Length == 0 || d.Contains(' ') || d.Contains('@'))
                continue;
            // Explicit "any domain" wildcard.
            if (d == "*")
            {
                set.Add("*");
                continue;
            }
            if (d.Contains('.'))
                set.Add(d);
        }
        return set;
    }

    /// <summary>
    /// True if registration is allowed for this email under the domain allow-list.
    /// Empty allow-list or "*" means all domains are permitted.
    /// Does not consult the banned-email list — use <see cref="IsRegistrationAllowed"/>.
    /// </summary>
    public bool IsEmailDomainAllowed(string email)
    {
        if (AllowedEmailDomains.Count == 0 || AllowedEmailDomains.Contains("*"))
            return true;
        var at = email.LastIndexOf('@');
        if (at < 0 || at >= email.Length - 1)
            return false;
        var domain = email[(at + 1)..].Trim().ToLowerInvariant();
        return AllowedEmailDomains.Contains(domain);
    }

    /// <summary>
    /// Parse "a@example.com, b@evil.org" into a normalized email set (trim, lower-case).
    /// Entries without <c>@</c> are ignored.
    /// </summary>
    public static HashSet<string> ParseEmailList(string? raw)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
            return set;
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var e = part.Trim().ToLowerInvariant();
            if (e.Length == 0 || e.Contains(' '))
                continue;
            var at = e.IndexOf('@');
            // Require local@domain with non-empty sides.
            if (at <= 0 || at >= e.Length - 1)
                continue;
            set.Add(e);
        }
        return set;
    }

    /// <summary>
    /// True if this exact email is on the registration ban list.
    /// </summary>
    public bool IsEmailBanned(string email)
    {
        if (BannedEmails.Count == 0)
            return false;
        if (string.IsNullOrWhiteSpace(email))
            return false;
        return BannedEmails.Contains(email.Trim().ToLowerInvariant());
    }

    /// <summary>
    /// True if a <em>new</em> account may be created for this email: not banned, and
    /// domain allow-list permits it. Existing accounts may still log in when false.
    /// </summary>
    public bool IsRegistrationAllowed(string email)
    {
        if (IsEmailBanned(email))
            return false;
        return IsEmailDomainAllowed(email);
    }

    private static string Env(string key, string fallback) =>
        Environment.GetEnvironmentVariable(key) is { Length: > 0 } v ? v : fallback;

    /// <summary>
    /// If env is unset, returns false (caller keeps property default).
    /// If set to empty / off / false / 0 / no / disabled, sets <paramref name="value"/> null (feature off).
    /// Otherwise sets the trimmed value.
    /// </summary>
    private static bool TryReadOptionalEnv(string key, out string? value, bool trimEndSlash)
    {
        value = null;
        var raw = Environment.GetEnvironmentVariable(key);
        if (raw is null)
            return false;
        var trimmed = raw.Trim();
        if (trimEndSlash)
            trimmed = trimmed.TrimEnd('/');
        if (trimmed.Length == 0
            || trimmed is "0" or "off" or "false" or "no"
            || string.Equals(trimmed, "disabled", StringComparison.OrdinalIgnoreCase))
        {
            value = null;
            return true;
        }
        value = trimmed;
        return true;
    }

    /// <summary>True for 1, true, yes, on (case-insensitive).</summary>
    public static bool ParseTruthy(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        return raw.Trim().ToUpperInvariant() is "1" or "TRUE" or "YES" or "ON";
    }

    /// <summary>
    /// Accepts INFO / WARNING / ERROR (and full names Information / Warning / Error).
    /// Unknown values fall back to <paramref name="fallback"/>.
    /// </summary>
    public static Microsoft.Extensions.Logging.LogLevel ParseLogLevel(
        string? raw,
        Microsoft.Extensions.Logging.LogLevel fallback)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return fallback;
        switch (raw.Trim().ToUpperInvariant())
        {
            case "INFO":
            case "INFORMATION":
                return Microsoft.Extensions.Logging.LogLevel.Information;
            case "WARN":
            case "WARNING":
                return Microsoft.Extensions.Logging.LogLevel.Warning;
            case "ERROR":
                return Microsoft.Extensions.Logging.LogLevel.Error;
            default:
                return fallback;
        }
    }
}
