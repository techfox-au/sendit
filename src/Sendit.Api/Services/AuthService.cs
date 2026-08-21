using System.Security.Cryptography;
using System.Text;
using Sendit.Api.Configuration;
using Sendit.Api.Models;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Account registration, login (with password rate limit + optional TOTP),
/// password reset, and session helpers.
/// </summary>
public sealed class AuthService
{
    public const string SessionCookieName = "sendit_session";
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan ResetTokenLifetime = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan EmailOtpLifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan AuthTicketLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Failed email OTP attempts (per account) before the current code(s) are wiped.
    /// Counter resets; signing in again can issue a fresh OTP, which again allows this many
    /// wrong tries before the next wipe — repeats until a correct code is entered.
    /// </summary>
    public const int MaxEmailOtpFails = 5;

    private readonly UserStore _users;
    private readonly PasswordHasher _hasher;
    private readonly TotpService _totp;
    private readonly IEmailSender _email;
    private readonly ActivityAuditStore _activityAudit;
    private readonly SenditOptions _options;
    private readonly AuthThrottleService _throttle;
    private readonly IHttpContextAccessor _http;
    private readonly SecurityAudit _audit;
    private readonly byte[] _ticketKey;

    public AuthService(
        UserStore users,
        PasswordHasher hasher,
        TotpService totp,
        IEmailSender email,
        ActivityAuditStore activityAudit,
        SenditOptions options,
        AuthThrottleService throttle,
        IHttpContextAccessor http,
        SecurityAudit audit)
    {
        _users = users;
        _hasher = hasher;
        _totp = totp;
        _email = email;
        _activityAudit = activityAudit;
        _options = options;
        _throttle = throttle;
        _http = http;
        _audit = audit;
        // Durable across restarts / multi-instance when DB volume is shared (or SENDIT_TICKET_KEY set).
        _ticketKey = TicketKeyStore.GetKey(options);
    }

    private string ClientIp() => AuthThrottleService.ClientIp(_http.HttpContext);

    /// <summary>
    /// Site-wide audit UI row for failed password / email-OTP / TOTP attempts
    /// (security console logs still go through <see cref="SecurityAudit"/>).
    /// </summary>
    private void RecordAuthCredentialFailure(
        string kind,
        string message,
        string? userId,
        string? email,
        string ip)
    {
        _activityAudit.Append(
            kind,
            message,
            actorUserId: userId,
            actorEmail: email,
            ownerUserId: userId,
            resourceKind: "auth",
            resourceId: null,
            clientIp: ip);
    }

    /// <summary>
    /// Unified sign-in: existing users log in; unknown emails on the allow-list are registered
    /// and must verify ownership via email OTP before a session is issued.
    /// </summary>
    /// <remarks>
    /// Response shape already reveals path (e.g. email OTP for new/unconfirmed vs session/TOTP
    /// for confirmed accounts). Artificial wall-clock padding is not used.
    /// </remarks>
    public async Task<LoginResult> LoginOrRegisterAsync(
        string email,
        string password,
        string? wrappedUserDataKey,
        CancellationToken ct = default)
    {
        email = UserStore.NormalizeEmail(email);
        if (!IsValidEmail(email))
            return LoginResult.Fail("Invalid email or password.");

        var user = _users.FindByEmail(email);
        if (user is null)
        {
            // Auto-register: ban list first, then domain allow-list (empty = open).
            // Existing accounts always take the login path above and are not blocked by bans.
            if (!_options.IsRegistrationAllowed(email))
            {
                var reason = _options.IsEmailBanned(email) ? "email banned" : "domain not allowed";
                var code = _options.IsEmailBanned(email)
                    ? "register_email_banned"
                    : "register_domain_blocked";
                _audit.AuthFailure(code, ClientIp(), email, reason);
                return LoginResult.Fail("Invalid email or password.");
            }
            if (password.Length < _options.MinPasswordLength)
                return LoginResult.Fail($"Password must be at least {_options.MinPasswordLength} characters.");
            if (password.Length > _options.MaxPasswordLength)
                return LoginResult.Fail($"Password must be at most {_options.MaxPasswordLength} characters.");
            if (string.IsNullOrWhiteSpace(wrappedUserDataKey) || wrappedUserDataKey.Length > 16_384)
                return LoginResult.Fail("wrappedUserDataKey is required for new accounts.");

            var hashed = _hasher.Hash(password);
            try
            {
                user = _users.Create(
                    email,
                    hashed.Salt,
                    hashed.Hash,
                    hashed.Iterations,
                    emailConfirmed: false,
                    wrappedUserDataKey.Trim());
                _activityAudit.Append(
                    ActivityAuditStore.KindAccountRegistered,
                    $"{user.Email} registered an account",
                    user.Id,
                    user.Email,
                    user.Id,
                    "account",
                    user.Id,
                    ClientIp());
            }
            catch (Microsoft.Data.Sqlite.SqliteException)
            {
                // Concurrent register of same email — treat as existing account path.
                user = _users.FindByEmail(email);
                if (user is null)
                    return LoginResult.Fail("Invalid email or password.");
                return await ContinueLoginAfterPasswordAsync(user, password, wrappedUserDataKey, ct);
            }

            return await IssueOrReuseEmailOtpAsync(user, ct);
        }

        return await ContinueLoginAfterPasswordAsync(user, password, wrappedUserDataKey, ct);
    }

    private async Task<LoginResult> ContinueLoginAfterPasswordAsync(
        UserRecord user,
        string password,
        string? wrappedUserDataKey,
        CancellationToken ct)
    {
        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email, out var lockRetry))
        {
            _audit.AuthFailure("password_locked", ip, user.Email, "ip+email lockout active");
            return LoginResult.FailRateLimited(
                "Too many attempts from this network. Try again later.",
                lockRetry);
        }

        if (!_throttle.AllowPasswordInterval(ip, user.Email, _options.PasswordAttemptIntervalSeconds, out var intervalRetry))
        {
            _audit.AuthFailure("password_interval", ip, user.Email, "progressive delay");
            return LoginResult.FailRateLimited(
                "Too many attempts. Wait a few seconds and try again.",
                intervalRetry);
        }

        _throttle.NotePasswordAttempt(ip, user.Email);

        // Incomplete registration: email not confirmed yet — no session has ever been issued.
        // Allow restarting with the same or a new password (clients always send a fresh UDK wrap).
        if (!user.EmailConfirmed)
            return await ContinueUnconfirmedRegistrationAsync(user, password, wrappedUserDataKey, ip, ct);

        if (!_hasher.Verify(password, user.PasswordSalt, user.PasswordHash, user.PasswordHashIterations))
        {
            _audit.AuthFailure("password_invalid", ip, user.Email, "bad password");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthPasswordFailed,
                $"{user.Email} failed a password sign-in attempt",
                user.Id,
                user.Email,
                ip);
            if (_throttle.RegisterFailure(ip, user.Email))
            {
                _audit.AuthLockout(ip, user.Email, "password failures threshold");
                return LoginResult.FailRateLimited(
                    "Too many attempts from this network. Try again later.",
                    AuthThrottleService.AuthLockoutDuration.TotalSeconds);
            }
            return LoginResult.Fail("Invalid email or password.");
        }

        _throttle.ClearFailures(ip, user.Email);
        user = _users.FindById(user.Id)!;

        if (user.TotpEnabled)
        {
            var ticket = CreateAuthTicket(user.Id, user.SecurityStamp, "totp");
            return LoginResult.NeedTotp(ticket, user);
        }

        _users.ClearAuthStepFails(user.Id);
        var sessionId = _users.CreateSession(user.Id, user.SecurityStamp, SessionLifetime);
        return LoginResult.Success(sessionId, user);
    }

    /// <summary>
    /// Resume or restart sign-up for an account that never completed email OTP.
    /// Matching password re-issues/reuses OTP; a different password + wrap updates
    /// credentials so "start registration again" does not get stuck on the first password.
    /// </summary>
    private async Task<LoginResult> ContinueUnconfirmedRegistrationAsync(
        UserRecord user,
        string password,
        string? wrappedUserDataKey,
        string ip,
        CancellationToken ct)
    {
        var passwordOk = _hasher.Verify(
            password, user.PasswordSalt, user.PasswordHash, user.PasswordHashIterations);

        if (!passwordOk)
        {
            // Treat as registration restart only when the client supplies a full new-account payload.
            if (password.Length < _options.MinPasswordLength)
                return LoginResult.Fail($"Password must be at least {_options.MinPasswordLength} characters.");
            if (password.Length > _options.MaxPasswordLength)
                return LoginResult.Fail($"Password must be at most {_options.MaxPasswordLength} characters.");
            if (string.IsNullOrWhiteSpace(wrappedUserDataKey) || wrappedUserDataKey.Length > 16_384)
            {
                _audit.AuthFailure("password_invalid", ip, user.Email, "bad password on unconfirmed");
                RecordAuthCredentialFailure(
                    ActivityAuditStore.KindAuthPasswordFailed,
                    $"{user.Email} failed a password sign-in attempt (unconfirmed account)",
                    user.Id,
                    user.Email,
                    ip);
                if (_throttle.RegisterFailure(ip, user.Email))
                {
                    _audit.AuthLockout(ip, user.Email, "password failures threshold");
                    return LoginResult.FailRateLimited(
                        "Too many attempts from this network. Try again later.",
                        AuthThrottleService.AuthLockoutDuration.TotalSeconds);
                }
                return LoginResult.Fail("Invalid email or password.");
            }

            var hashed = _hasher.Hash(password);
            var newStamp = IdGenerator.NewId();
            _users.UpdatePassword(
                user.Id,
                hashed.Salt,
                hashed.Hash,
                hashed.Iterations,
                newStamp,
                wrappedUserDataKey.Trim());
            // Credential change invalidates any prior email OTP (must receive a fresh code).
            _users.SetEmailOtp(user.Id, null, null);
            user = _users.FindById(user.Id)!;
            // Do not ClearFailures: wrap-based restarts must keep progressive password interval
            // so PBKDF2/CPU cannot be hammered without delay on an unconfirmed address.
        }
        else
        {
            _throttle.ClearFailures(ip, user.Email);
            if (!string.IsNullOrWhiteSpace(wrappedUserDataKey) && wrappedUserDataKey.Length <= 16_384)
            {
                // Same password: adopt the client wrap from this attempt so the UDK the browser
                // just generated stays usable after OTP.
                _users.SetWrappedUserDataKey(user.Id, wrappedUserDataKey.Trim());
                user = _users.FindById(user.Id)!;
            }
        }

        return await IssueOrReuseEmailOtpAsync(user, ct);
    }

    /// <summary>
    /// Issue a new email OTP, or reuse a still-valid pending code when the email budget blocks a resend.
    /// </summary>
    private async Task<LoginResult> IssueOrReuseEmailOtpAsync(UserRecord user, CancellationToken ct)
    {
        // Banned addresses never get OTP email, tickets, or reuse of a pending code.
        if (_options.IsEmailBanned(user.Email))
        {
            _users.SetEmailOtp(user.Id, null, null);
            _audit.AuthFailure("register_email_banned", ClientIp(), user.Email, "otp blocked for banned email");
            return LoginResult.Fail("Invalid email or password.");
        }

        var otpIssue = await TryIssueEmailOtpAsync(user, ct);
        if (!otpIssue.Ok)
        {
            // Still allow entering an existing valid code without resending email
            // (not for send failures — those clear the pending OTP; not for bans).
            if (otpIssue.ErrorCode != "email_send_failed"
                && otpIssue.ErrorCode != "email_banned"
                && HasValidPendingOtp(user))
            {
                var reuseTicket = CreateAuthTicket(user.Id, user.SecurityStamp, "email-otp");
                return LoginResult.NeedEmailOtp(reuseTicket, user);
            }
            return LoginResult.Fail(otpIssue.Error!, otpIssue.ErrorCode);
        }

        user = _users.FindById(user.Id)!;
        var emailTicket = CreateAuthTicket(user.Id, user.SecurityStamp, "email-otp");
        return LoginResult.NeedEmailOtp(emailTicket, user);
    }

    public async Task<LoginResult> CompleteEmailOtpAsync(string emailOtpTicket, string code, CancellationToken ct = default)
    {
        if (!TryParseAuthTicket(emailOtpTicket, "email-otp", out var userId, out var stamp))
            return LoginResult.Fail("Invalid or expired verification session.");

        var user = _users.FindById(userId);
        if (user is null || !string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal))
            return LoginResult.Fail("Invalid or expired verification session.");

        // Ban list: never complete registration OTP for a banned address.
        if (_options.IsEmailBanned(user.Email))
        {
            _users.SetEmailOtp(user.Id, null, null);
            _audit.AuthFailure("register_email_banned", ClientIp(), user.Email, "otp complete blocked for banned email");
            return LoginResult.Fail("Invalid email or password.");
        }

        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email, out var lockRetry))
        {
            _audit.AuthFailure("otp_locked", ip, user.Email, "ip+email lockout active");
            return LoginResult.FailRateLimited(
                "Too many attempts from this network. Try again later.",
                lockRetry);
        }

        if (string.IsNullOrEmpty(user.EmailOtpHash) || string.IsNullOrEmpty(user.EmailOtpExpiresAt))
            return LoginResult.Fail("No verification code is pending. Sign in again.");

        if (DateTimeOffset.Parse(user.EmailOtpExpiresAt) < DateTimeOffset.UtcNow)
            return LoginResult.Fail("Verification code expired. Sign in again to get a new code.");

        // Email OTP is always 6 digits (CSPRNG); do not accept other lengths.
        var codeNorm = (code ?? "").Trim().Replace(" ", "");
        if (codeNorm.Length != 6 || !codeNorm.All(char.IsDigit))
        {
            _audit.AuthFailure("otp_invalid", ip, user.Email, "bad code format");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthOtpFailed,
                $"{user.Email} failed an email verification code attempt (invalid format)",
                user.Id,
                user.Email,
                ip);
            return LoginResult.Fail("Invalid verification code.");
        }

        var hash = HashSensitiveToken(codeNorm);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(hash),
                Encoding.UTF8.GetBytes(user.EmailOtpHash)))
        {
            var fails = user.EmailOtpFailCount + 1;
            _audit.AuthFailure("otp_invalid", ip, user.Email, $"bad code attempt={fails}/{MaxEmailOtpFails}");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthOtpFailed,
                $"{user.Email} failed an email verification code attempt",
                user.Id,
                user.Email,
                ip);
            if (_throttle.RegisterFailure(ip, user.Email))
            {
                _audit.AuthLockout(ip, user.Email, "otp failures threshold");
                return LoginResult.FailRateLimited(
                    "Too many attempts from this network. Try again later.",
                    AuthThrottleService.AuthLockoutDuration.TotalSeconds);
            }
            if (fails >= MaxEmailOtpFails)
            {
                // Wipe OTP so the stolen/guessed code space is useless. Fail counter resets to 0
                // (SetEmailOtp clears it). User can sign in again for a new code; after another
                // MaxEmailOtpFails wrong tries that code is wiped too — indefinitely until success.
                _users.SetEmailOtp(user.Id, null, null);
                _audit.AuthFailure(
                    "otp_exhausted",
                    ip,
                    user.Email,
                    $"otp invalidated after {MaxEmailOtpFails} fails; counter reset");
                return LoginResult.Fail(
                    "Too many invalid codes. That verification code is no longer valid. " +
                    "Sign in again to get a new code.");
            }
            _users.SetEmailOtpFailCount(user.Id, fails);
            return LoginResult.Fail("Invalid verification code.");
        }

        // Consume email-otp ticket only after a correct code (wrong tries keep the same ticket).
        if (!TryConsumeAuthTicket(emailOtpTicket, "email-otp", userId))
            return LoginResult.Fail("Invalid or expired verification session.");

        _users.ConfirmEmail(user.Id);
        _users.SetEmailOtpFailCount(user.Id, 0);
        _throttle.ClearFailures(ip, user.Email);
        user = _users.FindById(user.Id)!;

        if (user.TotpEnabled)
        {
            var totpTicket = CreateAuthTicket(user.Id, user.SecurityStamp, "totp");
            return LoginResult.NeedTotp(totpTicket, user);
        }

        _users.ClearAuthStepFails(user.Id);
        var sessionId = _users.CreateSession(user.Id, user.SecurityStamp, SessionLifetime);
        return LoginResult.Success(sessionId, user);
    }

    public LoginResult CompleteTotpLogin(string totpTicket, string code)
    {
        if (!TryParseAuthTicket(totpTicket, "totp", out var userId, out var stamp))
            return LoginResult.Fail("Invalid or expired login session.");

        var user = _users.FindById(userId);
        if (user is null || !string.Equals(user.SecurityStamp, stamp, StringComparison.Ordinal))
            return LoginResult.Fail("Invalid or expired login session.");

        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email, out var lockRetry))
        {
            _audit.AuthFailure("totp_locked", ip, user.Email, "ip+email lockout active");
            return LoginResult.FailRateLimited(
                "Too many attempts from this network. Try again later.",
                lockRetry);
        }
        if (!user.EmailConfirmed)
            return LoginResult.Fail("Email is not verified.");
        if (!user.TotpEnabled || user.TotpSecret is null)
            return LoginResult.Fail("Two-factor authentication is not enabled.");
        if (!_totp.Verify(user.TotpSecret, code))
        {
            _audit.AuthFailure("totp_invalid", ip, user.Email, "bad totp code");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthTotpFailed,
                $"{user.Email} failed an authenticator code attempt at sign-in",
                user.Id,
                user.Email,
                ip);
            if (_throttle.RegisterFailure(ip, user.Email))
            {
                _audit.AuthLockout(ip, user.Email, "totp failures threshold");
                return LoginResult.FailRateLimited(
                    "Too many attempts from this network. Try again later.",
                    AuthThrottleService.AuthLockoutDuration.TotalSeconds);
            }
            return LoginResult.Fail("Invalid authentication code.");
        }

        if (!TryConsumeAuthTicket(totpTicket, "totp", userId))
            return LoginResult.Fail("Invalid or expired login session.");

        _throttle.ClearFailures(ip, user.Email);
        _users.ClearAuthStepFails(user.Id);
        var sessionId = _users.CreateSession(user.Id, user.SecurityStamp, SessionLifetime);
        return LoginResult.Success(sessionId, user);
    }

    private static bool HasValidPendingOtp(UserRecord user)
    {
        if (string.IsNullOrEmpty(user.EmailOtpHash) || string.IsNullOrEmpty(user.EmailOtpExpiresAt))
            return false;
        return DateTimeOffset.TryParse(user.EmailOtpExpiresAt, out var exp) && exp > DateTimeOffset.UtcNow;
    }

    /// <summary>Send a new email OTP if the progressive email budget allows.</summary>
    private async Task<(bool Ok, string? Error, string? ErrorCode)> TryIssueEmailOtpAsync(
        UserRecord user, CancellationToken ct)
    {
        if (_options.IsEmailBanned(user.Email))
        {
            _users.SetEmailOtp(user.Id, null, null);
            _audit.AuthFailure("register_email_banned", ClientIp(), user.Email, "otp issue blocked for banned email");
            return (false, "Invalid email or password.", "email_banned");
        }

        if (!_throttle.TryAllowEmail(user.Email, out var retry))
        {
            var secs = Math.Max(1, (int)Math.Ceiling(retry.TotalSeconds));
            _audit.EmailThrottled("otp", user.Email);
            return (false, $"Please wait {secs}s before requesting another email code.", null);
        }

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var hash = HashSensitiveToken(code);
        var exp = DateTimeOffset.UtcNow.Add(EmailOtpLifetime);
        _users.SetEmailOtp(user.Id, hash, exp.ToString("O"));

        try
        {
            var plain =
                $"Your Sendit! verification code is: {code}\n\n" +
                "It expires in 15 minutes.\n\n" +
                "If you did not try to sign in, you can ignore this email.";
            var html = Util.EmailHtmlTemplate.Render(
                "Email verification",
                Util.EmailHtmlTemplate.ParagraphsFromPlain(
                    "Use this one-time code to finish signing in to Sendit!:") +
                Util.EmailHtmlTemplate.CodeBlock(code) +
                Util.EmailHtmlTemplate.ParagraphsFromPlain(
                    "It expires in 15 minutes.\n\n" +
                    "If you did not try to sign in, you can ignore this email."),
                _options,
                preheader: "Your verification code is " + code);
            await _email.SendAsync(
                user.Email,
                "Sendit! email verification",
                plain,
                ct,
                htmlBody: html);
        }
        catch (Exception)
        {
            // Do not leave a code that never reached the user (EmailSender already logged).
            _users.SetEmailOtp(user.Id, null, null);
            return (
                false,
                "Could not send verification email. Try again in a moment.",
                "email_send_failed");
        }

        return (true, null, null);
    }

    public UserRecord? GetUserFromSession(string? sessionId)
    {
        if (string.IsNullOrEmpty(sessionId) || sessionId.Length > 128)
            return null;
        return _users.GetUserForSession(sessionId);
    }

    public void Logout(string? sessionId)
    {
        if (!string.IsNullOrEmpty(sessionId))
            _users.DeleteSession(sessionId);
    }

    public void SetWrappedUserDataKey(string userId, string wrappedUserDataKey)
    {
        _users.SetWrappedUserDataKey(userId, wrappedUserDataKey);
    }

    public async Task RequestPasswordResetAsync(string email, CancellationToken ct = default)
    {
        email = UserStore.NormalizeEmail(email);
        if (!IsValidEmail(email))
            return;

        // Banned: no reset token, no link, no email (same silent client response).
        if (_options.IsEmailBanned(email))
        {
            _audit.AuthFailure("password_reset_email_banned", ClientIp(), email, "banned");
            return;
        }

        var user = _users.FindByEmail(email);
        // Always same client response; only send if a completed account exists.
        // Unconfirmed (registration OTP never finished) must not get reset links —
        // they resume via sign-in + email OTP, not password reset.
        if (user is null || !user.EmailConfirmed)
            return;

        // Progressive auth email budget (OTP or reset share it): 10s × first 6, then 1/min.
        if (!_throttle.TryAllowEmail(user.Email, out _))
        {
            _audit.EmailThrottled("password_reset", user.Email);
            return;
        }

        var rawToken = IdGenerator.NewId() + IdGenerator.NewId();
        var hash = HashSensitiveToken(rawToken);
        // Only the latest token is valid.
        _users.InvalidateResetTokensForUser(user.Id);
        _users.CreatePasswordResetToken(user.Id, hash, DateTimeOffset.UtcNow.Add(ResetTokenLifetime));

        var link = $"{_options.PublicBaseUrl.TrimEnd('/')}/reset-password?token={Uri.EscapeDataString(rawToken)}";
        try
        {
            var plain =
                $"Reset your Sendit! password using this link (expires in 30 minutes):\n\n{link}\n\n" +
                "If you did not request this, ignore this email.";
            var html = Util.EmailHtmlTemplate.Render(
                "Password reset",
                Util.EmailHtmlTemplate.ParagraphsFromPlain(
                    "We received a request to reset your Sendit! password. " +
                    "This link expires in 30 minutes.") +
                Util.EmailHtmlTemplate.CtaButton(link, "Reset password", _options.Highlight) +
                Util.EmailHtmlTemplate.ParagraphsFromPlain(
                    "If the button does not work, copy and paste this URL into your browser:\n" +
                    link + "\n\n" +
                    "If you did not request this, ignore this email."),
                _options,
                preheader: "Reset your Sendit! password");
            await _email.SendAsync(
                user.Email,
                "Sendit! password reset",
                plain,
                ct,
                htmlBody: html);
        }
        catch
        {
            // Same client-facing silence as "account not found"; EmailSender logs the failure.
        }
    }

    public (bool Ok, string? Error, int DeletedItems) ResetPassword(
        string rawToken,
        string newPassword,
        string newWrappedUserDataKey,
        string? totpCode)
    {
        if (newPassword.Length < _options.MinPasswordLength)
            return (false, $"Password must be at least {_options.MinPasswordLength} characters.", 0);
        if (newPassword.Length > _options.MaxPasswordLength)
            return (false, $"Password must be at most {_options.MaxPasswordLength} characters.", 0);
        if (string.IsNullOrWhiteSpace(newWrappedUserDataKey) || newWrappedUserDataKey.Length > 16_384)
            return (false, "wrappedUserDataKey is required (new user data key after reset).", 0);

        var hash = HashSensitiveToken(rawToken);
        var ipEarly = ClientIp();
        // Peek user for TOTP before consume so we can require 2FA without burning token on missing code.
        var peek = _users.FindResetToken(hash);
        if (peek is null)
        {
            _audit.AuthFailure("reset_token_invalid", ipEarly, null, "unknown token");
            return (false, "Invalid or expired reset token.", 0);
        }
        if (peek.Value.UsedAt is not null)
        {
            _audit.AuthFailure("reset_token_used", ipEarly, null, "already used");
            return (false, "Invalid or expired reset token.", 0);
        }
        if (DateTimeOffset.Parse(peek.Value.ExpiresAt) < DateTimeOffset.UtcNow)
        {
            _audit.AuthFailure("reset_token_expired", ipEarly, null, "expired");
            return (false, "Invalid or expired reset token.", 0);
        }

        var user = _users.FindById(peek.Value.UserId);
        if (user is null)
            return (false, "Invalid or expired reset token.", 0);

        // Incomplete registration: no password-reset path (even if a stale token exists).
        if (!user.EmailConfirmed)
        {
            _audit.AuthFailure("reset_unconfirmed", ClientIp(), user.Email, "email not verified");
            return (false, "Invalid or expired reset token.", 0);
        }

        // Banned: never accept a reset token (stale tokens issued before ban).
        if (_options.IsEmailBanned(user.Email))
        {
            _audit.AuthFailure("password_reset_email_banned", ClientIp(), user.Email, "reset complete blocked");
            return (false, "Invalid or expired reset token.", 0);
        }

        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email))
        {
            _audit.AuthFailure("reset_locked", ip, user.Email, "ip+email lockout active");
            return (false, "Too many attempts from this network. Try again later.", 0);
        }

        // Enforce TOTP when 2FA is enabled (email compromise alone is insufficient).
        if (user.TotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(totpCode))
            {
                _audit.AuthFailure("reset_totp_required", ip, user.Email, "missing totp");
                return (false, "Authenticator code is required to reset this password.", 0);
            }
            if (user.TotpSecret is null || !_totp.Verify(user.TotpSecret, totpCode))
            {
                _audit.AuthFailure("reset_totp_invalid", ip, user.Email, "bad totp on reset");
                RecordAuthCredentialFailure(
                    ActivityAuditStore.KindAuthTotpFailed,
                    $"{user.Email} failed an authenticator code attempt during password reset",
                    user.Id,
                    user.Email,
                    ip);
                if (_throttle.RegisterFailure(ip, user.Email))
                    _audit.AuthLockout(ip, user.Email, "reset totp failures threshold");
                return (false, "Invalid authenticator code.", 0);
            }
        }

        // Atomic single-use consume (wins concurrent races).
        var userId = _users.TryConsumeResetToken(hash);
        if (userId is null)
        {
            _audit.AuthFailure("reset_token_invalid", ip, user.Email, "consume failed");
            return (false, "Invalid or expired reset token.", 0);
        }

        // Old password-wrapped key is unusable; destroy data encrypted under the previous user data key.
        var deleted = _users.DeleteOwnedEncryptedData(userId);
        var hashed = _hasher.Hash(newPassword);
        var newStamp = IdGenerator.NewId();
        _users.UpdatePassword(
            userId, hashed.Salt, hashed.Hash, hashed.Iterations, newStamp, newWrappedUserDataKey.Trim());
        _users.DeleteAllSessionsForUser(userId);
        _users.ClearAuthStepFails(userId);
        _users.InvalidateResetTokensForUser(userId);
        _throttle.ClearFailures(ip, user.Email);
        return (true, null, deleted);
    }

    /// <summary>
    /// Change password: requires a new password-wrapped user data key.
    /// When TOTP is enabled, <paramref name="totpCode"/> is required (same as password reset).
    /// Permanently deletes all sends/collects owned by the user (old UDK material is unrecoverable).
    /// </summary>
    public (bool Ok, string? Error, int DeletedItems) ChangePassword(
        UserRecord user,
        string currentPassword,
        string newPassword,
        string newWrappedUserDataKey,
        string? totpCode)
    {
        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email))
        {
            _audit.AuthFailure("change_password_locked", ip, user.Email, "ip+email lockout active");
            return (false, "Too many attempts from this network. Try again later.", 0);
        }

        if (!_throttle.AllowPasswordInterval(ip, user.Email, _options.PasswordAttemptIntervalSeconds))
        {
            _audit.AuthFailure("change_password_interval", ip, user.Email, "progressive delay");
            return (false, "Too many attempts. Wait a few seconds and try again.", 0);
        }

        _throttle.NotePasswordAttempt(ip, user.Email);

        if (!_hasher.Verify(currentPassword, user.PasswordSalt, user.PasswordHash, user.PasswordHashIterations))
        {
            _audit.AuthFailure("change_password_invalid", ip, user.Email, "bad current password");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthPasswordFailed,
                $"{user.Email} failed a change-password attempt (wrong current password)",
                user.Id,
                user.Email,
                ip);
            if (_throttle.RegisterFailure(ip, user.Email))
                _audit.AuthLockout(ip, user.Email, "change password failures threshold");
            return (false, "Current password is incorrect.", 0);
        }
        if (newPassword.Length < _options.MinPasswordLength)
            return (false, $"Password must be at least {_options.MinPasswordLength} characters.", 0);
        if (newPassword.Length > _options.MaxPasswordLength)
            return (false, $"Password must be at most {_options.MaxPasswordLength} characters.", 0);
        if (string.IsNullOrWhiteSpace(newWrappedUserDataKey) || newWrappedUserDataKey.Length > 16_384)
            return (false, "wrappedUserDataKey is required.", 0);

        // Enforce TOTP when 2FA is enabled (session alone is insufficient).
        if (user.TotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(totpCode))
            {
                _audit.AuthFailure("change_password_totp_required", ip, user.Email, "missing totp");
                return (false, "Authenticator code is required to change this password.", 0);
            }
            if (user.TotpSecret is null || !_totp.Verify(user.TotpSecret, totpCode))
            {
                _audit.AuthFailure("change_password_totp_invalid", ip, user.Email, "bad totp on change password");
                RecordAuthCredentialFailure(
                    ActivityAuditStore.KindAuthTotpFailed,
                    $"{user.Email} failed an authenticator code attempt during change-password",
                    user.Id,
                    user.Email,
                    ip);
                if (_throttle.RegisterFailure(ip, user.Email))
                    _audit.AuthLockout(ip, user.Email, "change password totp failures threshold");
                return (false, "Invalid authenticator code.", 0);
            }
        }

        var deleted = _users.DeleteOwnedEncryptedData(user.Id);
        var hashed = _hasher.Hash(newPassword);
        var newStamp = IdGenerator.NewId();
        _users.UpdatePassword(
            user.Id, hashed.Salt, hashed.Hash, hashed.Iterations, newStamp, newWrappedUserDataKey.Trim());
        _users.DeleteAllSessionsForUser(user.Id);
        _users.ClearAuthStepFails(user.Id);
        _throttle.ClearFailures(ip, user.Email);
        _activityAudit.Append(
            ActivityAuditStore.KindPasswordChanged,
            $"{user.Email} changed their password",
            user.Id,
            user.Email,
            user.Id,
            "account",
            user.Id,
            ip);
        return (true, null, deleted);
    }

    public (bool Ok, string? OtpAuthUri, string? Error) BeginTotpEnroll(UserRecord user)
    {
        if (user.TotpEnabled)
            return (false, null, "Two-factor authentication is already enabled.");
        var secret = _totp.GenerateSecret();
        _users.SetTotpPending(user.Id, secret);
        var uri = _totp.BuildOtpAuthUri(user.Email, secret);
        return (true, uri, null);
    }

    public (bool Ok, string? Error) ConfirmTotpEnroll(UserRecord user, string code)
    {
        // Reload pending secret
        user = _users.FindById(user.Id)!;
        if (string.IsNullOrEmpty(user.TotpPendingSecret))
            return (false, "No pending TOTP enrollment. Start enrollment first.");
        if (!_totp.Verify(user.TotpPendingSecret, code))
            return (false, "Invalid authentication code.");
        _users.ConfirmTotp(user.Id, user.TotpPendingSecret);
        // Force re-authentication with the new second factor (all devices).
        _users.DeleteAllSessionsForUser(user.Id);
        _activityAudit.Append(
            ActivityAuditStore.KindTotpEnabled,
            $"{user.Email} enabled two-factor authentication (TOTP)",
            user.Id,
            user.Email,
            user.Id,
            "account",
            user.Id,
            ClientIp());
        return (true, null);
    }

    public (bool Ok, string? Error) DisableTotp(UserRecord user, string password, string code)
    {
        var ip = ClientIp();
        if (_throttle.IsLockedOut(ip, user.Email))
        {
            _audit.AuthFailure("totp_disable_locked", ip, user.Email, "ip+email lockout active");
            return (false, "Too many attempts from this network. Try again later.");
        }
        if (!_throttle.AllowPasswordInterval(ip, user.Email, _options.PasswordAttemptIntervalSeconds))
            return (false, "Too many attempts. Wait a few seconds and try again.");
        _throttle.NotePasswordAttempt(ip, user.Email);

        if (!_hasher.Verify(password, user.PasswordSalt, user.PasswordHash, user.PasswordHashIterations))
        {
            _audit.AuthFailure("totp_disable_password", ip, user.Email, "bad password");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthPasswordFailed,
                $"{user.Email} failed a TOTP-disable attempt (wrong password)",
                user.Id,
                user.Email,
                ip);
            if (_throttle.RegisterFailure(ip, user.Email))
                _audit.AuthLockout(ip, user.Email, "totp disable password failures");
            return (false, "Invalid password or code.");
        }
        if (!user.TotpEnabled || user.TotpSecret is null || !_totp.Verify(user.TotpSecret, code))
        {
            _audit.AuthFailure("totp_disable_code", ip, user.Email, "bad totp or not enabled");
            RecordAuthCredentialFailure(
                ActivityAuditStore.KindAuthTotpFailed,
                $"{user.Email} failed a TOTP-disable attempt (wrong authenticator code)",
                user.Id,
                user.Email,
                ip);
            return (false, "Invalid password or code.");
        }

        _users.DisableTotp(user.Id);
        _users.ClearAuthStepFails(user.Id);
        _throttle.ClearFailures(ip, user.Email);
        _activityAudit.Append(
            ActivityAuditStore.KindTotpDisabled,
            $"{user.Email} disabled two-factor authentication (TOTP)",
            user.Id,
            user.Email,
            user.Id,
            "account",
            user.Id,
            ip);
        return (true, null);
    }

    /// <summary>HMAC-SHA256 (keyed) for OTPs and reset tokens so DB leaks are not offline-bruteforceable for short OTPs.</summary>
    private string HashSensitiveToken(string raw)
    {
        var mac = HMACSHA256.HashData(_ticketKey, Encoding.UTF8.GetBytes(raw));
        return Base64Url.Encode(mac);
    }

    private string CreateAuthTicket(string userId, string securityStamp, string purpose)
    {
        // Opaque ticket: purpose.userId.stamp.exp.jti.hmac — jti is one-time in SQLite.
        var jti = IdGenerator.NewId();
        var expOffset = DateTimeOffset.UtcNow.Add(AuthTicketLifetime);
        var exp = expOffset.ToUnixTimeSeconds();
        var payload = $"{purpose}.{userId}.{securityStamp}.{exp}.{jti}";
        var mac = Base64Url.Encode(HMACSHA256.HashData(_ticketKey, Encoding.UTF8.GetBytes(payload)));
        _users.CreateAuthTicket(jti, purpose, userId, expOffset);
        return Base64Url.Encode(Encoding.UTF8.GetBytes($"{payload}.{mac}"));
    }

    private bool TryParseAuthTicket(string ticket, string expectedPurpose, out string userId, out string stamp)
    {
        userId = "";
        stamp = "";
        try
        {
            var decoded = Encoding.UTF8.GetString(Base64Url.Decode(ticket));
            var parts = decoded.Split('.');
            // purpose.userId.stamp.exp.jti.mac
            if (parts.Length != 6)
                return false;
            if (!string.Equals(parts[0], expectedPurpose, StringComparison.Ordinal))
                return false;
            userId = parts[1];
            stamp = parts[2];
            if (!long.TryParse(parts[3], out var exp))
                return false;
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp)
                return false;
            var jti = parts[4];
            var payload = $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}";
            var expected = Base64Url.Encode(HMACSHA256.HashData(_ticketKey, Encoding.UTF8.GetBytes(payload)));
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expected),
                    Encoding.UTF8.GetBytes(parts[5])))
                return false;
            // Live (unused) jti required for any attempt.
            return _users.AuthTicketIsLive(jti, expectedPurpose, userId);
        }
        catch
        {
            return false;
        }
    }

    private bool TryConsumeAuthTicket(string ticket, string expectedPurpose, string expectedUserId)
    {
        try
        {
            var decoded = Encoding.UTF8.GetString(Base64Url.Decode(ticket));
            var parts = decoded.Split('.');
            if (parts.Length != 6)
                return false;
            if (!string.Equals(parts[0], expectedPurpose, StringComparison.Ordinal))
                return false;
            if (!string.Equals(parts[1], expectedUserId, StringComparison.Ordinal))
                return false;
            return _users.TryConsumeAuthTicket(parts[4], expectedPurpose, expectedUserId);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsValidEmail(string email)
    {
        if (email.Length is < 3 or > 254)
            return false;
        var at = email.IndexOf('@');
        return at > 0 && at < email.Length - 1 && email.IndexOf('@', at + 1) < 0;
    }

    /// <summary>Stable short resource id for PoW binding (email or ticket).</summary>
    public static string PowBindId(string kind, string value)
    {
        var norm = value.Trim().ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(kind + "\n" + norm));
        return kind + ":" + Base64Url.Encode(hash.AsSpan(0, 16));
    }
}

public sealed class LoginResult
{
    public bool Ok { get; private init; }
    public bool TotpRequired { get; private init; }
    public bool EmailOtpRequired { get; private init; }
    public bool IsRateLimited { get; private init; }
    public int? RetryAfterSeconds { get; private init; }
    public string? Error { get; private init; }
    /// <summary>Stable machine code for clients (e.g. <c>email_send_failed</c>).</summary>
    public string? ErrorCode { get; private init; }
    public string? SessionId { get; private init; }
    public string? TotpTicket { get; private init; }
    public string? EmailOtpTicket { get; private init; }
    public UserRecord? User { get; private init; }

    public static LoginResult Fail(string error, string? errorCode = null) =>
        new() { Ok = false, Error = error, ErrorCode = errorCode };

    public static LoginResult FailRateLimited(string error, double retryAfterSeconds) => new()
    {
        Ok = false,
        Error = error,
        IsRateLimited = true,
        RetryAfterSeconds = Math.Max(1, (int)Math.Ceiling(retryAfterSeconds))
    };

    public static LoginResult NeedTotp(string ticket, UserRecord user) =>
        new() { Ok = true, TotpRequired = true, TotpTicket = ticket, User = user };
    public static LoginResult NeedEmailOtp(string ticket, UserRecord user) =>
        new() { Ok = true, EmailOtpRequired = true, EmailOtpTicket = ticket, User = user };
    public static LoginResult Success(string sessionId, UserRecord user) =>
        new() { Ok = true, SessionId = sessionId, User = user };
}
