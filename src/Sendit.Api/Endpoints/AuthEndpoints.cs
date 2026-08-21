using Microsoft.AspNetCore.RateLimiting;
using Sendit.Api.Models;
using Sendit.Api.Services;

namespace Sendit.Api.Endpoints;

public static class AuthEndpoints
{
    public const string PowKindAuth = "auth";

    public static void MapAuthEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/v1/auth");

        // PoW challenges: no shared auth rate-limit charge (avoid double-spend with the action POST).
        // Challenge-issue budget (ShareScanGuard) + process-local ASP.NET auth policy still apply.
        g.MapGet("/login/pow", (
            string? email,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (string.IsNullOrWhiteSpace(email))
                return Results.BadRequest(new { error = "email query parameter is required." });
            var rid = AuthService.PowBindId("login", email);
            return IssueAuthPow(scanGuard, audit, pow, http, rid);
        }).RequireRateLimiting("auth");

        g.MapGet("/login/email-otp/pow", (
            string? ticket,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (string.IsNullOrWhiteSpace(ticket))
                return Results.BadRequest(new { error = "ticket query parameter is required." });
            var rid = AuthService.PowBindId("email-otp", ticket);
            return IssueAuthPow(scanGuard, audit, pow, http, rid);
        }).RequireRateLimiting("auth");

        g.MapGet("/login/totp/pow", (
            string? ticket,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (string.IsNullOrWhiteSpace(ticket))
                return Results.BadRequest(new { error = "ticket query parameter is required." });
            var rid = AuthService.PowBindId("totp", ticket);
            return IssueAuthPow(scanGuard, audit, pow, http, rid);
        }).RequireRateLimiting("auth");

        g.MapGet("/forgot-password/pow", (
            string? email,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (string.IsNullOrWhiteSpace(email))
                return Results.BadRequest(new { error = "email query parameter is required." });
            var rid = AuthService.PowBindId("forgot", email);
            return IssueAuthPow(scanGuard, audit, pow, http, rid);
        }).RequireRateLimiting("forgot");

        // Unified sign-in: existing users log in; unknown allowed-domain emails auto-register + email OTP.
        g.MapPost("/login", async (
            LoginRequest body,
            AuthService auth,
            ProofOfWorkService pow,
            ShareScanGuard scanGuard,
            AuthThrottleService throttle,
            SecurityAudit audit,
            ILoggerFactory logFactory,
            HttpContext http,
            CancellationToken ct) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            if (body.Email is null || body.Password is null)
                return Results.BadRequest(new { error = "Email and password are required." });

            var rid = AuthService.PowBindId("login", body.Email);
            var denied = RequireAuthPow(
                pow, scanGuard, audit, logFactory, http,
                rid, body.PowChallengeId, body.PowNonce, body.PowHash, "login");
            if (denied is not null)
                return denied;

            var result = await auth.LoginOrRegisterAsync(
                body.Email, body.Password, body.WrappedUserDataKey, ct);
            return ToLoginResponse(http, result);
        }).RequireRateLimiting("auth");

        g.MapPost("/login/email-otp", async (
            EmailOtpLoginRequest body,
            AuthService auth,
            ProofOfWorkService pow,
            ShareScanGuard scanGuard,
            AuthThrottleService throttle,
            SecurityAudit audit,
            ILoggerFactory logFactory,
            HttpContext http,
            CancellationToken ct) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            if (body.EmailOtpTicket is null || body.Code is null)
                return Results.BadRequest(new { error = "emailOtpTicket and code are required." });

            var rid = AuthService.PowBindId("email-otp", body.EmailOtpTicket);
            var denied = RequireAuthPow(
                pow, scanGuard, audit, logFactory, http,
                rid, body.PowChallengeId, body.PowNonce, body.PowHash, "email-otp");
            if (denied is not null)
                return denied;

            var result = await auth.CompleteEmailOtpAsync(body.EmailOtpTicket, body.Code, ct);
            return ToLoginResponse(http, result);
        }).RequireRateLimiting("auth");

        g.MapPost("/login/totp", (
            TotpLoginRequest body,
            AuthService auth,
            ProofOfWorkService pow,
            ShareScanGuard scanGuard,
            AuthThrottleService throttle,
            SecurityAudit audit,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            if (body.TotpTicket is null || body.Code is null)
                return Results.BadRequest(new { error = "totpTicket and code are required." });

            var rid = AuthService.PowBindId("totp", body.TotpTicket);
            var denied = RequireAuthPow(
                pow, scanGuard, audit, logFactory, http,
                rid, body.PowChallengeId, body.PowNonce, body.PowHash, "totp");
            if (denied is not null)
                return denied;

            var result = auth.CompleteTotpLogin(body.TotpTicket, body.Code);
            return ToLoginResponse(http, result);
        }).RequireRateLimiting("auth");

        g.MapPost("/logout", (AuthService auth, HttpContext http) =>
        {
            var sid = http.Request.Cookies[AuthService.SessionCookieName];
            auth.Logout(sid);
            ClearSessionCookie(http);
            return Results.Ok(new { ok = true });
        });

        // Guest-friendly: unauthenticated callers get 200 + authenticated:false.
        // Does NOT return the password-wrapped UDK package (use GET /user-data-key for unlock).
        g.MapGet("/me", (AuthService auth, HttpContext http) =>
        {
            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Ok(new { authenticated = false });
            return Results.Ok(new
            {
                authenticated = true,
                id = user.Id,
                email = user.Email,
                totpEnabled = user.TotpEnabled,
                hasUserDataKey = !string.IsNullOrEmpty(user.WrappedUserDataKey),
                notifyCollectReady = user.NotifyCollectReady,
                notifySendOpened = user.NotifySendOpened
            });
        });

        /// <summary>
        /// Update email notification preferences (both flags required; default off).
        /// </summary>
        g.MapPatch("/notifications", (
            NotificationPrefsBody body,
            AuthService auth,
            UserStore users,
            HttpContext http) =>
        {
            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (body.NotifyCollectReady is null || body.NotifySendOpened is null)
            {
                return Results.BadRequest(new
                {
                    error = "notifyCollectReady and notifySendOpened are required booleans."
                });
            }

            if (!users.SetNotificationPrefs(
                    user.Id,
                    body.NotifyCollectReady.Value,
                    body.NotifySendOpened.Value))
                return Results.NotFound();

            var updated = users.FindById(user.Id);
            return Results.Ok(new
            {
                ok = true,
                notifyCollectReady = updated?.NotifyCollectReady ?? body.NotifyCollectReady.Value,
                notifySendOpened = updated?.NotifySendOpened ?? body.NotifySendOpened.Value
            });
        }).RequireRateLimiting("auth");

        /// <summary>
        /// Password-wrapped UDK package for browser unlock only (not on every /me poll).
        /// </summary>
        g.MapGet("/user-data-key", (
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            return Results.Ok(new
            {
                wrappedUserDataKey = user.WrappedUserDataKey,
                hasUserDataKey = !string.IsNullOrEmpty(user.WrappedUserDataKey)
            });
        }).RequireRateLimiting("auth");

        /// <summary>
        /// Set wrapped user data key only when the account has none (migration / recovery).
        /// </summary>
        g.MapPost("/user-data-key", (
            SetUserDataKeyRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (string.IsNullOrWhiteSpace(body.WrappedUserDataKey) || body.WrappedUserDataKey.Length > 16_384)
                return Results.BadRequest(new { error = "wrappedUserDataKey is required." });
            if (!string.IsNullOrEmpty(user.WrappedUserDataKey))
                return Results.Conflict(new { error = "User data key already set. Change password to rotate it." });

            auth.SetWrappedUserDataKey(user.Id, body.WrappedUserDataKey.Trim());
            return Results.Ok(new { ok = true });
        }).RequireRateLimiting("auth");

        g.MapPost("/forgot-password", async (
            ForgotRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            ProofOfWorkService pow,
            ShareScanGuard scanGuard,
            ILoggerFactory logFactory,
            HttpContext http,
            CancellationToken ct) =>
        {
            var limited = CheckSharedForgotRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            if (string.IsNullOrWhiteSpace(body.Email))
                return Results.BadRequest(new { error = "email is required." });

            var rid = AuthService.PowBindId("forgot", body.Email);
            var denied = RequireAuthPow(
                pow, scanGuard, audit, logFactory, http,
                rid, body.PowChallengeId, body.PowNonce, body.PowHash, "forgot");
            if (denied is not null)
                return denied;

            await auth.RequestPasswordResetAsync(body.Email, ct);
            // Always generic success.
            return Results.Ok(new { ok = true, message = "If an account exists, a reset email has been sent." });
        }).RequireRateLimiting("forgot");

        g.MapPost("/reset-password", (
            ResetRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            if (body.Token is null || body.Password is null || body.WrappedUserDataKey is null)
                return Results.BadRequest(new
                {
                    error = "Token, password, and wrappedUserDataKey are required."
                });
            var (ok, error, deleted) = auth.ResetPassword(
                body.Token, body.Password, body.WrappedUserDataKey, body.TotpCode);
            if (!ok)
            {
                if (IsAuthRateLimitMessage(error))
                    return AuthRateLimited(http, error!);
                if (error is not null && error.Contains("Authenticator code is required", StringComparison.Ordinal))
                    return Results.Json(new { error, totpRequired = true }, statusCode: 400);
                return Results.BadRequest(new { error });
            }
            return Results.Ok(new
            {
                ok = true,
                deletedItems = deleted,
                message = "Password reset. Previous shares and requests for this account were permanently deleted."
            });
        }).RequireRateLimiting("auth");

        g.MapPost("/change-password", (
            ChangePasswordRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (body.CurrentPassword is null || body.NewPassword is null || body.WrappedUserDataKey is null)
                return Results.BadRequest(new
                {
                    error = "currentPassword, newPassword, and wrappedUserDataKey are required."
                });

            var (ok, error, deleted) = auth.ChangePassword(
                user,
                body.CurrentPassword,
                body.NewPassword,
                body.WrappedUserDataKey,
                body.TotpCode);
            if (!ok)
            {
                if (IsAuthRateLimitMessage(error))
                    return AuthRateLimited(http, error!);
                if (error is not null
                    && error.Contains("Authenticator code is required", StringComparison.Ordinal))
                    return Results.Json(new { error, totpRequired = true }, statusCode: 400);
                return Results.BadRequest(new { error });
            }
            ClearSessionCookie(http);
            return Results.Ok(new
            {
                ok = true,
                deletedItems = deleted,
                message = "Password changed. Previous shares and requests were permanently deleted."
            });
        }).RequireRateLimiting("auth");

        g.MapPost("/totp/begin", (
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            var (ok, uri, error) = auth.BeginTotpEnroll(user);
            if (!ok)
                return Results.BadRequest(new { error });
            return Results.Ok(new { otpauthUri = uri });
        }).RequireRateLimiting("auth");

        g.MapPost("/totp/confirm", (
            TotpCodeRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (body.Code is null)
                return Results.BadRequest(new { error = "code is required." });
            var (ok, error) = auth.ConfirmTotpEnroll(user, body.Code);
            if (!ok)
                return Results.BadRequest(new { error });
            // Sessions already wiped in ConfirmTotpEnroll; drop this browser's cookie too.
            ClearSessionCookie(http);
            return Results.Ok(new
            {
                ok = true,
                totpEnabled = true,
                requiresReLogin = true,
                message = "Two-factor authentication enabled. Sign in again with your authenticator code."
            });
        }).RequireRateLimiting("auth");

        g.MapPost("/totp/disable", (
            DisableTotpRequest body,
            AuthService auth,
            AuthThrottleService throttle,
            SecurityAudit audit,
            HttpContext http) =>
        {
            var limited = CheckSharedAuthRateLimit(throttle, audit, http);
            if (limited is not null) return limited;

            var user = CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (body.Password is null || body.Code is null)
                return Results.BadRequest(new { error = "password and code are required." });
            var (ok, error) = auth.DisableTotp(user, body.Password, body.Code);
            if (!ok)
            {
                if (IsAuthRateLimitMessage(error))
                    return AuthRateLimited(http, error!);
                return Results.BadRequest(new { error });
            }
            return Results.Ok(new { ok = true, totpEnabled = false });
        }).RequireRateLimiting("auth");
    }

    private static bool IsAuthRateLimitMessage(string? error) =>
        error is not null
        && error.Contains("Too many attempts", StringComparison.OrdinalIgnoreCase);

    private static IResult AuthRateLimited(HttpContext http, string error)
    {
        const int seconds = 60;
        http.Response.Headers.RetryAfter = seconds.ToString();
        return Results.Json(
            new { error, retryAfterSeconds = seconds },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    /// <summary>
    /// SQLite-shared IP budget (multi-instance). Complements process-local ASP.NET rate limits.
    /// </summary>
    private static IResult? CheckSharedAuthRateLimit(
        AuthThrottleService throttle,
        SecurityAudit audit,
        HttpContext http)
        => CheckSharedIpRateLimit(
            throttle,
            audit,
            http,
            AuthThrottleService.RateBucketAuth,
            AuthThrottleService.AuthIpPermitLimit,
            AuthThrottleService.AuthIpWindow);

    private static IResult? CheckSharedForgotRateLimit(
        AuthThrottleService throttle,
        SecurityAudit audit,
        HttpContext http)
        => CheckSharedIpRateLimit(
            throttle,
            audit,
            http,
            AuthThrottleService.RateBucketForgot,
            AuthThrottleService.ForgotIpPermitLimit,
            AuthThrottleService.ForgotIpWindow);

    private static IResult? CheckSharedIpRateLimit(
        AuthThrottleService throttle,
        SecurityAudit audit,
        HttpContext http,
        string bucket,
        int permitLimit,
        TimeSpan window)
    {
        var ip = ShareScanGuard.ClientKey(http);
        if (throttle.TryConsumeRateLimit(bucket, ip, permitLimit, window, out var retryAfter))
            return null;

        var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter));
        http.Response.Headers.RetryAfter = seconds.ToString();
        audit.RateLimited("shared_rate_limit", ip, http.Request.Path.Value ?? "", seconds);
        return Results.Json(
            new
            {
                error = "Too many requests. Slow down and try again.",
                retryAfterSeconds = seconds
            },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    private static IResult IssueAuthPow(
        ShareScanGuard scanGuard,
        SecurityAudit audit,
        ProofOfWorkService pow,
        HttpContext http,
        string resourceId)
    {
        var client = ShareScanGuard.ClientKey(http);
        // Exhausted abuse or issue budget → 429 (no free challenge minting).
        if (scanGuard.IsFailureBudgetExceeded(client, out var retryFail))
            return SecretEndpoints.TooManyFailedLookups(http, retryFail, audit);
        if (scanGuard.IsChallengeIssueBudgetExceeded(client, out var retryIssue))
            return SecretEndpoints.TooManyFailedLookups(http, retryIssue, audit);

        var ch = pow.Issue(PowKindAuth, resourceId);
        scanGuard.RecordChallengeIssue(client);
        return Results.Ok(new
        {
            challengeId = ch.ChallengeId,
            hmacKey = ch.HmacKey,
            difficultyBits = ch.DifficultyBits,
            expiresAt = ch.ExpiresAt
        });
    }

    /// <summary>
    /// Consume one-time PoW for an auth action (always required; difficulty ≥ 1).
    /// Bad/missing PoW → 403 (counts toward scan budget → 429).
    /// </summary>
    private static IResult? RequireAuthPow(
        ProofOfWorkService pow,
        ShareScanGuard scanGuard,
        SecurityAudit audit,
        ILoggerFactory logFactory,
        HttpContext http,
        string resourceId,
        string? challengeId,
        string? nonce,
        string? hash,
        string stage)
    {
        var client = ShareScanGuard.ClientKey(http);
        if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
            return SecretEndpoints.TooManyFailedLookups(http, retryPow, audit);

        var powErr = pow.TryConsume(PowKindAuth, resourceId, challengeId, nonce, hash);
        if (powErr is not null)
        {
            var log = logFactory.CreateLogger("Sendit.AuthPow");
            return SecretEndpoints.PowDenied(scanGuard, http, log, audit, stage, resourceId, powErr);
        }

        return null;
    }

    public static UserRecord? CurrentUser(AuthService auth, HttpContext http)
    {
        var sid = http.Request.Cookies[AuthService.SessionCookieName];
        return auth.GetUserFromSession(sid);
    }

    private static IResult ToLoginResponse(HttpContext http, LoginResult result)
    {
        if (!result.Ok)
        {
            if (result.IsRateLimited)
            {
                var seconds = result.RetryAfterSeconds ?? 60;
                http.Response.Headers.RetryAfter = seconds.ToString();
                return Results.Json(
                    new { error = result.Error, retryAfterSeconds = seconds },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }
            return Results.Json(
                new { error = result.Error, code = result.ErrorCode },
                statusCode: 401);
        }

        if (result.EmailOtpRequired)
        {
            return Results.Ok(new
            {
                emailOtpRequired = true,
                emailOtpTicket = result.EmailOtpTicket,
                totpRequired = false,
                wrappedUserDataKey = result.User!.WrappedUserDataKey
            });
        }

        if (result.TotpRequired)
        {
            return Results.Ok(new
            {
                emailOtpRequired = false,
                totpRequired = true,
                totpTicket = result.TotpTicket,
                wrappedUserDataKey = result.User!.WrappedUserDataKey
            });
        }

        SetSessionCookie(http, result.SessionId!);
        return Results.Ok(new
        {
            emailOtpRequired = false,
            totpRequired = false,
            user = new
            {
                id = result.User!.Id,
                email = result.User.Email,
                totpEnabled = result.User.TotpEnabled
            },
            wrappedUserDataKey = result.User.WrappedUserDataKey
        });
    }

    private static CookieOptions SessionCookieOptions(HttpContext http) => new()
    {
        HttpOnly = true,
        Secure = http.Request.IsHttps ||
                 string.Equals(http.Request.Headers["X-Forwarded-Proto"], "https", StringComparison.OrdinalIgnoreCase),
        SameSite = SameSiteMode.Strict,
        Path = "/",
        IsEssential = true
    };

    private static void SetSessionCookie(HttpContext http, string sessionId)
    {
        var opts = SessionCookieOptions(http);
        opts.MaxAge = TimeSpan.FromHours(8);
        http.Response.Cookies.Append(AuthService.SessionCookieName, sessionId, opts);
    }

    /// <summary>
    /// Delete must use the same Path/SameSite/Secure as Set, or browsers keep the cookie.
    /// </summary>
    private static void ClearSessionCookie(HttpContext http)
    {
        var opts = SessionCookieOptions(http);
        opts.Expires = DateTimeOffset.UnixEpoch;
        opts.MaxAge = TimeSpan.Zero;
        http.Response.Cookies.Delete(AuthService.SessionCookieName, opts);
        // Also overwrite with empty value for stubborn clients.
        http.Response.Cookies.Append(AuthService.SessionCookieName, "", opts);
    }

    public record LoginRequest(
        string? Email,
        string? Password,
        string? WrappedUserDataKey,
        string? PowChallengeId = null,
        string? PowNonce = null,
        string? PowHash = null);

    public record EmailOtpLoginRequest(
        string? EmailOtpTicket,
        string? Code,
        string? PowChallengeId = null,
        string? PowNonce = null,
        string? PowHash = null);
    public record TotpLoginRequest(
        string? TotpTicket,
        string? Code,
        string? PowChallengeId = null,
        string? PowNonce = null,
        string? PowHash = null);
    public record ForgotRequest(
        string? Email,
        string? PowChallengeId = null,
        string? PowNonce = null,
        string? PowHash = null);
    public record ResetRequest(string? Token, string? Password, string? WrappedUserDataKey, string? TotpCode);
    public record ChangePasswordRequest(
        string? CurrentPassword,
        string? NewPassword,
        string? WrappedUserDataKey,
        string? TotpCode);
    public record SetUserDataKeyRequest(string? WrappedUserDataKey);
    public record TotpCodeRequest(string? Code);
    public record DisableTotpRequest(string? Password, string? Code);
    public record NotificationPrefsBody(bool? NotifyCollectReady, bool? NotifySendOpened);
}
