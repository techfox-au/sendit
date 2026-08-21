using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Endpoints;
using Sendit.Api.Logging;
using Sendit.Api.Services;
using Sendit.Api.Util;
using SQLitePCL;

// Initialize SQLite native library (SQLitePCLRaw.bundle_e_sqlite3).
Batteries_V2.Init();

var builder = WebApplication.CreateBuilder(args);

var options = SenditOptions.FromEnvironment();
// appsettings.json "Sendit:DbPath" is a local-dev fallback only.
// Never let it override SENDIT_DB_PATH (Docker sets /data/sendit.db).
var cfg = builder.Configuration.GetSection(SenditOptions.SectionName);
if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SENDIT_DB_PATH"))
    && !string.IsNullOrEmpty(cfg["DbPath"]))
    options.DbPath = cfg["DbPath"]!;

// Console logging always on; optional file when SENDIT_LOG_FILE is set.
// SENDIT_LOG_LEVEL: INFO (default) | WARNING | ERROR
// Each line is prefixed with UTC [yyyy-MM-dd - HH:mm:ss] (file logger matches).
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o =>
{
    o.SingleLine = true;
    o.TimestampFormat = "[yyyy-MM-dd - HH:mm:ss] ";
    o.UseUtcTimestamp = true;
});
builder.Logging.SetMinimumLevel(options.MinLogLevel);
// Quiet framework noise when app is at WARNING/ERROR; when INFO, keep Microsoft at Information.
builder.Logging.AddFilter("Microsoft", options.MinLogLevel > LogLevel.Information
    ? options.MinLogLevel
    : LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", options.MinLogLevel);
builder.Logging.AddFilter("System", options.MinLogLevel > LogLevel.Information
    ? options.MinLogLevel
    : LogLevel.Warning);
if (!string.IsNullOrWhiteSpace(options.LogFile))
{
    builder.Logging.AddProvider(new SimpleFileLoggerProvider(options.LogFile, options.MinLogLevel));
}

builder.Services.AddSingleton(options);
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient(nameof(EmailSender), client =>
{
    // Align with EmailSender.TransportTimeout (7s) so hung Mailgun calls fail fast.
    client.Timeout = TimeSpan.FromSeconds(7);
});
builder.Services.AddHttpClient(ClientIpWorkerProbeService.HttpClientName, client =>
{
    // Worker → origin + JSON round-trip; allow enough time for cold start.
    client.Timeout = TimeSpan.FromSeconds(25);
    client.DefaultRequestHeaders.TryAddWithoutValidation(
        "User-Agent",
        "Sendit-IpCheck-Startup/1.0");
});
builder.Services.AddSingleton<DbConnectionFactory>();
builder.Services.AddSingleton<DataAtRestProtector>();
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<UserStore>();
builder.Services.AddSingleton<SecretStore>();
builder.Services.AddSingleton<RequestStore>();
builder.Services.AddSingleton<TotpService>();
builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddSingleton<NotificationEmailService>();
builder.Services.AddSingleton<ActivityAuditStore>();
builder.Services.AddSingleton<AuthThrottleService>();
builder.Services.AddSingleton<SecurityAudit>();
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<SqliteMaintenance>();
builder.Services.AddSingleton<ShareScanGuard>();
builder.Services.AddSingleton<ProofOfWorkService>();
builder.Services.AddSingleton<ClientIpProbeAuth>();
builder.Services.AddSingleton<ClientIpCapability>();
builder.Services.AddHostedService<ExpiryCleanupService>();
// One-shot after listen (not a loop): call Cloudflare Worker canary when URL is set.
builder.Services.AddHostedService<ClientIpWorkerProbeService>();

// Default body cap is small (auth, meta, etc.). Large payload routes raise the limit
// per-request in middleware (create send/collect when authed; collect upload always).
builder.Services.Configure<FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = options.MaxRequestBodyBytes;
});
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxRequestBodySize = options.MaxRequestBodyBytes;
});

builder.Services.AddRateLimiter(rl =>
{
    rl.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rl.OnRejected = async (ctx, _) =>
    {
        var audit = ctx.HttpContext.RequestServices.GetService<SecurityAudit>();
        var ip = ctx.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = ctx.HttpContext.Request.Path.Value ?? "";
        audit?.RateLimited("aspnet_rate_limiter", ip, path);
        ctx.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await ctx.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "Too many requests. Slow down and try again.",
        });
    };
    // Rate-limit API only. Static pages (/collect, /css, /js, favicon) must not burn the budget —
    // reloading a valid collect link loads many assets and would false-trigger 429s.
    rl.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var path = httpContext.Request.Path.Value ?? "";
        if (!path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
            return RateLimitPartition.GetNoLimiter("static");

        return RateLimitPartition.GetFixedWindowLimiter(
            "api:" + (httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = AuthThrottleService.ApiIpPermitLimit,
                Window = AuthThrottleService.ApiIpWindow,
                QueueLimit = 0
            });
    });

    // Tighter limits on authentication surfaces (per IP).
    // Process-local backstop; multi-instance truth is SQLite via AuthThrottleService
    // (same limits: auth 60/min, forgot 30/min — tighten further at nginx if needed).
    rl.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = AuthThrottleService.AuthIpPermitLimit,
                Window = AuthThrottleService.AuthIpWindow,
                QueueLimit = 0
            }));

    rl.AddPolicy("forgot", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = AuthThrottleService.ForgotIpPermitLimit,
                Window = AuthThrottleService.ForgotIpWindow,
                QueueLimit = 0
            }));
});

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Trust only local / docker / ULA peers (nginx on same host or same L3 fabric).
    // Do NOT clear KnownProxies entirely — that would trust XFF from any client
    // if Kestrel is ever exposed without a reverse proxy.
    o.KnownProxies.Clear();
    o.KnownIPNetworks.Clear();
    // 127.0.0.0/8 (entire loopback range, not only 127.0.0.1)
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("127.0.0.0"), 8));
    // ::1/128
    o.KnownProxies.Add(System.Net.IPAddress.IPv6Loopback);
    // Unique local addresses (fd00::/8 is the locally-assigned half of fc00::/7)
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("fd00::"), 8));
    // Typical docker / LAN bridges
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("10.0.0.0"), 8));
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("172.16.0.0"), 12));
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("192.168.0.0"), 16));
    // Netbird / CGNAT shared address space (tailnet peers often appear as 100.x).
    o.KnownIPNetworks.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("100.64.0.0"), 10));
});
var app = builder.Build();

{
    var db = app.Services.GetRequiredService<DbConnectionFactory>();
    using var conn = db.Create();
    Schema.EnsureCreated(conn);
}

if (!string.IsNullOrWhiteSpace(options.LogFile))
{
    app.Logger.LogInformation("Security/audit logs also written to {LogFile}", options.LogFile);
}

// Ensure durable ticket key material exists early (env or file next to DB).
_ = TicketKeyStore.GetKey(options);
// Keep options in sync with ProofOfWorkService clamp (env 0 / negative → 1; max 28).
options.PowDifficultyBits = Math.Clamp(
    options.PowDifficultyBits,
    SenditOptions.MinPowDifficultyBits,
    28);
app.Logger.LogInformation(
    "Proof-of-work: {Bits} leading zero bits (min {Min}), challenge TTL {Ttl}s (SQLite-backed, one-time challenges).",
    options.PowDifficultyBits,
    SenditOptions.MinPowDifficultyBits,
    options.PowChallengeTtlSeconds);
app.Logger.LogInformation("UI highlight: {Highlight}", options.Highlight);
if (options.PowDifficultyBits < SenditOptions.RecommendedPowDifficultyBits)
{
    app.Logger.LogWarning(
        "SENDIT_POW_DIFFICULTY_BITS is set low at {Bits}, recommended a value of at least {Recommended}!",
        options.PowDifficultyBits,
        SenditOptions.RecommendedPowDifficultyBits);
}

// Behind nginx: only trust X-Forwarded-* from loopback/docker bridge by default.
// If the API port is ever public, spoofed XFF would bypass IP allow-lists and rate limits.
// Prefer binding Kestrel to 127.0.0.1 and terminating TLS at nginx (see deploy/).
app.UseForwardedHeaders();

// Raise body limit for large payload routes. Default remains MaxRequestBodyBytes (~256 KiB + 5%).
// - create send/collect: only when a valid session is present
// - collect upload: public (unauthenticated) so recipients can submit large secrets
// Defaults sit ~5% above nginx client_max_body_size so the edge rejects oversized bodies first.
app.Use(async (ctx, next) =>
{
    if (HttpMethods.IsPost(ctx.Request.Method))
    {
        var path = ctx.Request.Path;
        var allowLarge = false;
        if (IsCollectUploadPath(path))
            allowLarge = true;
        else if (IsAuthenticatedCreatePath(path))
        {
            var auth = ctx.RequestServices.GetRequiredService<AuthService>();
            allowLarge = AuthEndpoints.CurrentUser(auth, ctx) is not null;
        }

        if (allowLarge)
        {
            var feature = ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
            if (feature is { IsReadOnly: false })
                feature.MaxRequestBodySize = options.MaxUploadBytes;
        }
    }

    await next();
});

// Browser security headers: either nginx (edge) or Kestrel (direct exposure), not both.
// SENDIT_EDGE_SECURITY_HEADERS=1 → edge owns headers; skip Kestrel suite (no duplicates).
if (options.EdgeSecurityHeaders)
{
    app.Logger.LogInformation(
        "SENDIT_EDGE_SECURITY_HEADERS enabled: browser security headers left to the reverse proxy.");
}
else
{
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        // Only Chromium-recognized feature names (unknown tokens log console errors).
        ctx.Response.Headers["Permissions-Policy"] =
            "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), " +
            "fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), " +
            "magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), " +
            "publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), usb=(), " +
            "web-share=(), xr-spatial-tracking=()";
        ctx.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
        ctx.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";

        // Strict CSP for API only; HTML/JS pages need script-src 'self'.
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.Headers["Content-Security-Policy"] =
                "default-src 'none'; frame-ancestors 'none'";
        }
        else
        {
            ctx.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
                "connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; " +
                "object-src 'none'";
        }

        await next();
    });
}

app.UseRateLimiter();

// Multi-instance global API rate limit (SQLite). Complements process-local ASP.NET global limiter.
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    if (path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
    {
        var throttle = ctx.RequestServices.GetRequiredService<AuthThrottleService>();
        var audit = ctx.RequestServices.GetService<SecurityAudit>();
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!throttle.TryConsumeRateLimit(
                AuthThrottleService.RateBucketApi,
                ip,
                AuthThrottleService.ApiIpPermitLimit,
                AuthThrottleService.ApiIpWindow,
                out var retryAfter))
        {
            var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter));
            ctx.Response.Headers.RetryAfter = seconds.ToString();
            audit?.RateLimited("shared_api_rate_limit", ip, path, seconds);
            ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await ctx.Response.WriteAsJsonAsync(new
            {
                error = "Too many requests. Slow down and try again.",
                retryAfterSeconds = seconds
            });
            return;
        }
    }

    await next();
});

// Serve built frontend from public/ (dev convenience). Production can still use nginx.
var staticRoot = ResolveStaticRoot(app.Environment);
if (staticRoot is not null)
{
    var files = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(staticRoot);

    // Clean URLs: /dashboard → dashboard.min.html (build emits *.min.html)
    app.Use(async (ctx, next) =>
    {
        var path = ctx.Request.Path.Value;
        if (path is not null
            && path.Length > 1
            && !path.StartsWith("/api", StringComparison.OrdinalIgnoreCase)
            && !Path.HasExtension(path))
        {
            var relative = path.TrimStart('/').TrimEnd('/') + ".min.html";
            if (files.GetFileInfo(relative).Exists)
                ctx.Request.Path = "/" + relative;
        }
        await next();
    });

    var defaultFiles = new DefaultFilesOptions { FileProvider = files };
    defaultFiles.DefaultFileNames.Clear();
    defaultFiles.DefaultFileNames.Add("login.min.html");
    app.UseDefaultFiles(defaultFiles);
    app.UseStaticFiles(new StaticFileOptions { FileProvider = files });

    // No public home page — / goes to login.
    app.MapGet("/", () => Results.Redirect("/login"));

    // Pages: /send + /send/new, /collect + /collect/new. Legacy aliases redirect.
    app.MapGet("/share", () => Results.Redirect("/send/new"));
    app.MapGet("/share/new", () => Results.Redirect("/send/new"));
    app.MapGet("/request", () => Results.Redirect("/collect/new"));
    app.MapGet("/new-collect", () => Results.Redirect("/collect/new"));
    // Old obtain URL for sends
    app.MapGet("/view", (HttpContext http) =>
    {
        var qs = http.Request.QueryString.HasValue ? http.Request.QueryString.Value : "";
        return Results.Redirect("/send" + qs);
    });

    app.Logger.LogInformation("Serving static files from {StaticRoot}", staticRoot);
}
else
{
    app.Logger.LogWarning(
        "No static root found. Set SENDIT_STATIC_ROOT or run: python3 scripts/build-frontend.py");
}

// Browsers always request /favicon.ico — themed rocket mark (SVG) from SENDIT_HIGHLIGHT.
// Logo wordmark is the same model via /api/v1/branding/logo.svg. No disk branding assets.
app.MapGet("/favicon.ico", (SenditOptions opts) =>
{
    var svg = Sendit.Api.Util.HighlightColor.ThemeRocketFaviconSvg(opts.Highlight);
    return Results.Text(svg, "image/svg+xml; charset=utf-8");
});

app.MapGet("/api/v1/health", () => Results.Ok(new { status = "ok" }));

// Secret-gated client-IP snapshot for the Cloudflare Worker canary (and manual curl).
// Auth: X-Sendit-Ip-Probe or Authorization: Bearer (see ClientIpProbeAuth).
// 200 = public client IP; 503 = private/loopback; 404 = wrong/missing secret (not a public oracle).
// Docs: docs/CONFIGURATION.md “Client-IP check”, deploy/cloudflare-worker-check-ip/.
{
    var probeAuth = app.Services.GetRequiredService<ClientIpProbeAuth>();
    if (probeAuth.IsUsingDefault)
    {
        app.Logger.LogInformation(
            "GET /api/v1/diagnostics/client-ip enabled (built-in default probe secret). " +
            "Override with SENDIT_IP_PROBE_SECRET if desired. " +
            "Cloudflare Worker canary: deploy/cloudflare-worker-check-ip.");
    }
    else
    {
        app.Logger.LogInformation(
            "GET /api/v1/diagnostics/client-ip enabled (SENDIT_IP_PROBE_SECRET override). " +
            "Use the Cloudflare Worker canary to verify public client IPs through nginx.");
    }
}

app.MapGet("/api/v1/diagnostics/client-ip", (HttpContext http, ClientIpProbeAuth probeAuth) =>
{
    if (!probeAuth.IsAuthorized(http))
        return Results.NotFound();

    var body = ClientIp.Describe(http);
    // Worker canary expects 503 when isPrivateOrLocal so upstreamStatus reflects proxy health.
    if (ClientIp.IsPrivateOrLocal(ClientIp.Get(http)))
        return Results.Json(body, statusCode: StatusCodes.Status503ServiceUnavailable);
    return Results.Ok(body);
});

app.MapBrandingEndpoints();
app.MapAuthEndpoints();
app.MapSecretEndpoints();
app.MapRequestEndpoints();

// Do not fall back unknown paths to index.min.html — that made /login look like a no-op
// when the clean-URL rewrite failed (same home page again).

app.Run();

/// <summary>Authenticated create-send / create-collect (session required to raise body limit).</summary>
static bool IsAuthenticatedCreatePath(PathString path)
{
    var p = NormalizeApiPath(path);
    return p.Equals("/api/v1/send", StringComparison.OrdinalIgnoreCase)
        || p.Equals("/api/v1/collect", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Public collect upload of encrypted payload (large body allowed without session).</summary>
static bool IsCollectUploadPath(PathString path)
{
    var p = NormalizeApiPath(path);
    // /api/v1/collect/{id}/upload
    if (!p.StartsWith("/api/v1/collect/", StringComparison.OrdinalIgnoreCase))
        return false;
    if (!p.EndsWith("/upload", StringComparison.OrdinalIgnoreCase))
        return false;
    // Exactly one segment between collect and upload (the id).
    var mid = p.AsSpan("/api/v1/collect/".Length);
    if (mid.Length <= "/upload".Length)
        return false;
    mid = mid[..^"/upload".Length];
    if (mid.Length == 0 || mid.Contains('/'))
        return false;
    return true;
}

static string NormalizeApiPath(PathString path)
{
    var p = path.Value ?? "";
    if (p.Length > 1 && p[^1] == '/')
        p = p[..^1];
    return p;
}

/// <summary>
/// Resolve the path to public/ static assets.
/// Order: SENDIT_STATIC_ROOT env → content-root relatives → cwd/public.
/// Relative env paths are resolved against ContentRootPath (not process CWD).
/// </summary>
static string? ResolveStaticRoot(IWebHostEnvironment env)
{
    static bool IsValid(string? path) =>
        !string.IsNullOrEmpty(path)
        && Directory.Exists(path)
        && File.Exists(Path.Combine(path, "index.min.html"));

    var fromEnv = Environment.GetEnvironmentVariable("SENDIT_STATIC_ROOT");
    if (!string.IsNullOrWhiteSpace(fromEnv))
    {
        var full = Path.IsPathRooted(fromEnv)
            ? Path.GetFullPath(fromEnv)
            : Path.GetFullPath(Path.Combine(env.ContentRootPath, fromEnv));
        if (IsValid(full))
            return full;
    }

    // Content root is typically src/Sendit.Api when using dotnet run.
    var candidates = new[]
    {
        Path.GetFullPath(Path.Combine(env.ContentRootPath, "public")),
        Path.GetFullPath(Path.Combine(env.ContentRootPath, "..", "..", "public")),
        Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "public")),
    };

    foreach (var c in candidates)
    {
        if (IsValid(c))
            return c;
    }

    return null;
}

public partial class Program { }
