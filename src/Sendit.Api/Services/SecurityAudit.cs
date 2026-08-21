namespace Sendit.Api.Services;

/// <summary>
/// Structured security-event logging (console always; file when SENDIT_LOG_FILE is set).
/// Identities (emails) are logged in full — no obfuscation.
/// </summary>
public sealed class SecurityAudit
{
    private readonly ILogger _log;

    public SecurityAudit(ILoggerFactory factory)
    {
        _log = factory.CreateLogger("Sendit.Security");
    }

    public void AuthFailure(string kind, string ip, string? identity, string detail)
    {
        _log.LogWarning(
            "AUTH_FAIL kind={Kind} ip={Ip} identity={Identity} detail={Detail}",
            kind,
            ip,
            string.IsNullOrWhiteSpace(identity) ? "-" : identity.Trim(),
            detail);
    }

    public void AuthLockout(string ip, string? identity, string detail)
    {
        _log.LogWarning(
            "AUTH_LOCKOUT ip={Ip} identity={Identity} detail={Detail}",
            ip,
            string.IsNullOrWhiteSpace(identity) ? "-" : identity.Trim(),
            detail);
    }

    public void RateLimited(string source, string ip, string path, double? retryAfterSeconds = null)
    {
        _log.LogWarning(
            "RATE_LIMIT_429 source={Source} ip={Ip} path={Path} retryAfterSeconds={RetryAfter}",
            source,
            ip,
            path,
            retryAfterSeconds);
    }

    public void EmailThrottled(string kind, string email)
    {
        _log.LogWarning(
            "EMAIL_THROTTLE kind={Kind} identity={Identity}",
            kind,
            string.IsNullOrWhiteSpace(email) ? "-" : email.Trim());
    }
}
