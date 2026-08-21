using Microsoft.Data.Sqlite;
using Sendit.Api.Data;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Append-only activity audit for the Audit UI. Rows are never updated or deleted
/// (SQLite triggers abort UPDATE/DELETE). Any authenticated user can list the full
/// site-wide log (all accounts and resources).
/// </summary>
public sealed class ActivityAuditStore
{
    public const string KindAccountRegistered = "account_registered";
    public const string KindPasswordChanged = "password_changed";
    public const string KindTotpEnabled = "totp_enabled";
    public const string KindTotpDisabled = "totp_disabled";
    public const string KindSendCreated = "send_created";
    public const string KindCollectCreated = "collect_created";
    public const string KindSendDeleted = "send_deleted";
    public const string KindCollectDeleted = "collect_deleted";
    public const string KindSendViewed = "send_viewed";
    public const string KindSendDecrypted = "send_decrypted";
    public const string KindCollectUploaded = "collect_uploaded";
    public const string KindCollectRetrieved = "collect_retrieved";
    /// <summary>Send meta/payload blocked: client IP outside AllowedCidr.</summary>
    public const string KindSendIpDenied = "send_ip_denied";
    /// <summary>Collect payload blocked: client IP outside SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS.</summary>
    public const string KindCollectIpDenied = "collect_ip_denied";
    /// <summary>Wrong password on sign-in, change-password, or TOTP disable.</summary>
    public const string KindAuthPasswordFailed = "auth_password_failed";
    /// <summary>Wrong or malformed email verification OTP.</summary>
    public const string KindAuthOtpFailed = "auth_otp_failed";
    /// <summary>Wrong authenticator code on login, reset, change-password, or TOTP disable.</summary>
    public const string KindAuthTotpFailed = "auth_totp_failed";

    private readonly DbConnectionFactory _db;
    private readonly ILogger<ActivityAuditStore> _log;

    public ActivityAuditStore(DbConnectionFactory db, ILogger<ActivityAuditStore> log)
    {
        _db = db;
        _log = log;
    }

    public void Append(
        string kind,
        string message,
        string? actorUserId,
        string? actorEmail,
        string? ownerUserId,
        string? resourceKind,
        string? resourceId,
        string? clientIp)
    {
        try
        {
            using var conn = _db.Create();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO audit_log (
                    Id, AtUtc, Kind, Message,
                    ActorUserId, ActorEmail, OwnerUserId,
                    ResourceKind, ResourceId, ClientIp
                ) VALUES (
                    @id, @at, @kind, @msg,
                    @actorId, @actorEmail, @ownerId,
                    @rk, @rid, @ip
                )
                """;
            cmd.Parameters.AddWithValue("@id", IdGenerator.NewId());
            cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("@kind", kind);
            cmd.Parameters.AddWithValue("@msg", message.Length > 512 ? message[..512] : message);
            cmd.Parameters.AddWithValue("@actorId", (object?)actorUserId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@actorEmail", (object?)NormalizeEmail(actorEmail) ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ownerId", (object?)ownerUserId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@rk", (object?)resourceKind ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@rid", (object?)resourceId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ip", (object?)TruncateIp(clientIp) ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            // Never fail the user action because audit write failed.
            _log.LogError(ex, "Failed to append audit_log kind={Kind}", kind);
        }
    }

    public const int DefaultPageSize = 500;
    public const int MaxPageSize = 500;

    /// <summary>
    /// Newest first, site-wide. Optional cursor (<paramref name="beforeAtUtc"/>,
    /// <paramref name="beforeId"/>) loads the next older page (infinite scroll).
    /// </summary>
    public IReadOnlyList<ActivityAuditEntry> ListPage(
        int limit = DefaultPageSize,
        string? beforeAtUtc = null,
        string? beforeId = null)
    {
        if (limit is < 1 or > MaxPageSize)
            limit = DefaultPageSize;

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();

        var useCursor = !string.IsNullOrWhiteSpace(beforeAtUtc)
            && !string.IsNullOrWhiteSpace(beforeId);

        if (useCursor)
        {
            // Strictly older than the last item of the previous page (AtUtc, then Id).
            cmd.CommandText = """
                SELECT Id, AtUtc, Kind, Message, ActorUserId, ActorEmail, OwnerUserId,
                       ResourceKind, ResourceId, ClientIp
                FROM audit_log
                WHERE AtUtc < @beforeAt
                   OR (AtUtc = @beforeAt AND Id < @beforeId)
                ORDER BY AtUtc DESC, Id DESC
                LIMIT @lim
                """;
            cmd.Parameters.AddWithValue("@beforeAt", beforeAtUtc!.Trim());
            cmd.Parameters.AddWithValue("@beforeId", beforeId!.Trim());
        }
        else
        {
            cmd.CommandText = """
                SELECT Id, AtUtc, Kind, Message, ActorUserId, ActorEmail, OwnerUserId,
                       ResourceKind, ResourceId, ClientIp
                FROM audit_log
                ORDER BY AtUtc DESC, Id DESC
                LIMIT @lim
                """;
        }

        cmd.Parameters.AddWithValue("@lim", limit);

        var list = new List<ActivityAuditEntry>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new ActivityAuditEntry(
                r.GetString(0),
                r.GetString(1),
                r.GetString(2),
                r.GetString(3),
                r.IsDBNull(4) ? null : r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5),
                r.IsDBNull(6) ? null : r.GetString(6),
                r.IsDBNull(7) ? null : r.GetString(7),
                r.IsDBNull(8) ? null : r.GetString(8),
                r.IsDBNull(9) ? null : r.GetString(9)));
        }
        return list;
    }

    private static string? NormalizeEmail(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();

    private static string? TruncateIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return null;
        var s = ip.Trim();
        return s.Length > 128 ? s[..128] : s;
    }
}

public sealed record ActivityAuditEntry(
    string Id,
    string AtUtc,
    string Kind,
    string Message,
    string? ActorUserId,
    string? ActorEmail,
    string? OwnerUserId,
    string? ResourceKind,
    string? ResourceId,
    string? ClientIp);
