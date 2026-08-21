using Microsoft.Data.Sqlite;
using Sendit.Api.Data;
using Sendit.Api.Models;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// User and session persistence. Every query uses bound parameters.
/// </summary>
public sealed class UserStore
{
    private readonly DbConnectionFactory _db;
    private readonly DataAtRestProtector _protector;

    public UserStore(DbConnectionFactory db, DataAtRestProtector protector)
    {
        _db = db;
        _protector = protector;
    }

    public UserRecord? FindByEmail(string email)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Id, Email, PasswordSalt, PasswordHash, PasswordHashIterations,
                   EmailConfirmed, CreatedAt, TotpSecret, TotpEnabled, TotpPendingSecret,
                   SecurityStamp, WrappedUserDataKey,
                   EmailOtpHash, EmailOtpExpiresAt, EmailOtpFailCount,
                   NotifyCollectReady, NotifySendOpened
            FROM users WHERE Email = @email LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@email", NormalizeEmail(email));
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadUser(r) : null;
    }

    public UserRecord? FindById(string id)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Id, Email, PasswordSalt, PasswordHash, PasswordHashIterations,
                   EmailConfirmed, CreatedAt, TotpSecret, TotpEnabled, TotpPendingSecret,
                   SecurityStamp, WrappedUserDataKey,
                   EmailOtpHash, EmailOtpExpiresAt, EmailOtpFailCount,
                   NotifyCollectReady, NotifySendOpened
            FROM users WHERE Id = @id LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadUser(r) : null;
    }

    public UserRecord Create(
        string email,
        byte[] salt,
        byte[] hash,
        int iterations,
        bool emailConfirmed,
        string wrappedUserDataKey)
    {
        var user = new UserRecord
        {
            Id = IdGenerator.NewId(),
            Email = NormalizeEmail(email),
            PasswordSalt = salt,
            PasswordHash = hash,
            PasswordHashIterations = iterations,
            EmailConfirmed = emailConfirmed,
            CreatedAt = UtcNow(),
            TotpSecret = null,
            TotpEnabled = false,
            TotpPendingSecret = null,
            SecurityStamp = IdGenerator.NewId(),
            WrappedUserDataKey = wrappedUserDataKey,
            NotifyCollectReady = false,
            NotifySendOpened = false
        };

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO users (
                Id, Email, PasswordSalt, PasswordHash, PasswordHashIterations,
                EmailConfirmed, CreatedAt, TotpSecret, TotpEnabled, TotpPendingSecret,
                SecurityStamp, WrappedUserDataKey
            ) VALUES (
                @id, @email, @salt, @hash, @iter,
                @confirmed, @created, NULL, 0, NULL,
                @stamp, @wudk
            )
            """;
        cmd.Parameters.AddWithValue("@id", user.Id);
        cmd.Parameters.AddWithValue("@email", user.Email);
        cmd.Parameters.AddWithValue("@salt", user.PasswordSalt);
        cmd.Parameters.AddWithValue("@hash", user.PasswordHash);
        cmd.Parameters.AddWithValue("@iter", user.PasswordHashIterations);
        cmd.Parameters.AddWithValue("@confirmed", user.EmailConfirmed ? 1 : 0);
        cmd.Parameters.AddWithValue("@created", user.CreatedAt);
        cmd.Parameters.AddWithValue("@stamp", user.SecurityStamp);
        cmd.Parameters.AddWithValue("@wudk", wrappedUserDataKey);
        cmd.ExecuteNonQuery();
        return user;
    }

    public void UpdatePassword(
        string userId,
        byte[] salt,
        byte[] hash,
        int iterations,
        string newSecurityStamp,
        string? newWrappedUserDataKey)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users
            SET PasswordSalt = @salt,
                PasswordHash = @hash,
                PasswordHashIterations = @iter,
                SecurityStamp = @stamp,
                WrappedUserDataKey = @wudk
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@salt", salt);
        cmd.Parameters.AddWithValue("@hash", hash);
        cmd.Parameters.AddWithValue("@iter", iterations);
        cmd.Parameters.AddWithValue("@stamp", newSecurityStamp);
        cmd.Parameters.AddWithValue("@wudk", (object?)newWrappedUserDataKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Delete all sends and collects owned by the user (used on password change/reset).</summary>
    public int DeleteOwnedEncryptedData(string userId)
    {
        using var conn = _db.Create();
        int n;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM secrets WHERE OwnerUserId = @uid";
            cmd.Parameters.AddWithValue("@uid", userId);
            n = cmd.ExecuteNonQuery();
        }
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM requests WHERE OwnerUserId = @uid";
            cmd.Parameters.AddWithValue("@uid", userId);
            n += cmd.ExecuteNonQuery();
        }
        return n;
    }

    public void SetEmailOtpFailCount(string userId, int count)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET EmailOtpFailCount = @c WHERE Id = @id";
        cmd.Parameters.AddWithValue("@c", count);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void ClearAuthStepFails(string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        // Only EmailOtpFailCount drives per-code wipe; lockout lives in auth_throttle_state.
        cmd.CommandText = "UPDATE users SET EmailOtpFailCount = 0 WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Remove all reset tokens for a user (e.g. before issuing a fresh one).</summary>
    public void InvalidateResetTokensForUser(string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM password_reset_tokens WHERE UserId = @uid";
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Atomically consume a reset token: succeeds only if unused and not expired.
    /// Returns userId when this call won the race; null if invalid/used/expired.
    /// </summary>
    public string? TryConsumeResetToken(string tokenHash)
    {
        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();
        string? userId;
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT UserId, ExpiresAt, UsedAt FROM password_reset_tokens
                WHERE TokenHash = @hash LIMIT 1
                """;
            sel.Parameters.AddWithValue("@hash", tokenHash);
            using var r = sel.ExecuteReader();
            if (!r.Read())
            {
                tx.Rollback();
                return null;
            }
            userId = r.GetString(0);
            var expires = r.GetString(1);
            var used = r.IsDBNull(2) ? null : r.GetString(2);
            r.Close();
            if (used is not null)
            {
                tx.Rollback();
                return null;
            }
            if (!DateTimeOffset.TryParse(expires, out var exp) || exp < DateTimeOffset.UtcNow)
            {
                tx.Rollback();
                return null;
            }
        }

        using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = """
                UPDATE password_reset_tokens
                SET UsedAt = @at
                WHERE TokenHash = @hash AND UsedAt IS NULL
                """;
            upd.Parameters.AddWithValue("@at", UtcNow());
            upd.Parameters.AddWithValue("@hash", tokenHash);
            if (upd.ExecuteNonQuery() != 1)
            {
                tx.Rollback();
                return null;
            }
        }

        tx.Commit();
        return userId;
    }

    public void SetWrappedUserDataKey(string userId, string wrappedUserDataKey)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET WrappedUserDataKey = @wudk WHERE Id = @id";
        cmd.Parameters.AddWithValue("@wudk", wrappedUserDataKey);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void CreateAuthTicket(string jti, string purpose, string userId, DateTimeOffset expiresAt)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO auth_tickets (Id, Purpose, UserId, ExpiresAt, UsedAt)
            VALUES (@id, @p, @uid, @exp, NULL)
            """;
        cmd.Parameters.AddWithValue("@id", jti);
        cmd.Parameters.AddWithValue("@p", purpose);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.Parameters.AddWithValue("@exp", expiresAt.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// True if ticket jti exists, matches purpose/user, is unused, and not expired.
    /// </summary>
    public bool AuthTicketIsLive(string jti, string purpose, string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT ExpiresAt, UsedAt, Purpose, UserId FROM auth_tickets
            WHERE Id = @id LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@id", jti);
        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return false;
        if (!string.Equals(r.GetString(2), purpose, StringComparison.Ordinal))
            return false;
        if (!string.Equals(r.GetString(3), userId, StringComparison.Ordinal))
            return false;
        if (!r.IsDBNull(1))
            return false;
        if (!DateTimeOffset.TryParse(r.GetString(0), out var exp) || exp < DateTimeOffset.UtcNow)
            return false;
        return true;
    }

    /// <summary>Atomically mark ticket used. Returns false if already used/missing/expired.</summary>
    public bool TryConsumeAuthTicket(string jti, string purpose, string userId)
    {
        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT ExpiresAt, UsedAt, Purpose, UserId FROM auth_tickets
                WHERE Id = @id LIMIT 1
                """;
            sel.Parameters.AddWithValue("@id", jti);
            using var r = sel.ExecuteReader();
            if (!r.Read())
            {
                tx.Rollback();
                return false;
            }
            var expires = r.GetString(0);
            var used = r.IsDBNull(1) ? null : r.GetString(1);
            var purp = r.GetString(2);
            var uid = r.GetString(3);
            r.Close();
            if (used is not null
                || !string.Equals(purp, purpose, StringComparison.Ordinal)
                || !string.Equals(uid, userId, StringComparison.Ordinal)
                || !DateTimeOffset.TryParse(expires, out var exp)
                || exp < DateTimeOffset.UtcNow)
            {
                tx.Rollback();
                return false;
            }
        }

        using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = """
                UPDATE auth_tickets SET UsedAt = @at
                WHERE Id = @id AND UsedAt IS NULL
                """;
            upd.Parameters.AddWithValue("@at", UtcNow());
            upd.Parameters.AddWithValue("@id", jti);
            if (upd.ExecuteNonQuery() != 1)
            {
                tx.Rollback();
                return false;
            }
        }

        tx.Commit();
        return true;
    }


    public void SetEmailOtp(string userId, string? otpHash, string? expiresAtIso)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users
            SET EmailOtpHash = @hash, EmailOtpExpiresAt = @exp, EmailOtpFailCount = 0
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@hash", (object?)otpHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@exp", (object?)expiresAtIso ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void ConfirmEmail(string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users
            SET EmailConfirmed = 1, EmailOtpHash = NULL, EmailOtpExpiresAt = NULL
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void SetTotpPending(string userId, string? pendingSecret)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET TotpPendingSecret = @pending WHERE Id = @id";
        // Encrypt TOTP material at rest (server key / DATA_KEY or ticket-key fallback).
        var stored = pendingSecret is null ? null : _protector.ProtectUtf8(pendingSecret);
        cmd.Parameters.AddWithValue("@pending", (object?)stored ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void ConfirmTotp(string userId, string secret)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users
            SET TotpSecret = @secret, TotpEnabled = 1, TotpPendingSecret = NULL
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@secret", _protector.ProtectUtf8(secret));
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public void DisableTotp(string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users
            SET TotpSecret = NULL, TotpEnabled = 0, TotpPendingSecret = NULL
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.ExecuteNonQuery();
    }

    public string CreateSession(string userId, string securityStamp, TimeSpan lifetime)
    {
        var id = IdGenerator.NewId() + IdGenerator.NewId(); // 256-bit session id
        var now = DateTimeOffset.UtcNow;
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO sessions (Id, UserId, SecurityStamp, CreatedAt, ExpiresAt)
            VALUES (@id, @userId, @stamp, @created, @expires)
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@userId", userId);
        cmd.Parameters.AddWithValue("@stamp", securityStamp);
        cmd.Parameters.AddWithValue("@created", now.ToString("O"));
        cmd.Parameters.AddWithValue("@expires", now.Add(lifetime).ToString("O"));
        cmd.ExecuteNonQuery();
        return id;
    }

    public UserRecord? GetUserForSession(string sessionId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT u.Id, u.Email, u.PasswordSalt, u.PasswordHash, u.PasswordHashIterations,
                   u.EmailConfirmed, u.CreatedAt, u.TotpSecret, u.TotpEnabled, u.TotpPendingSecret,
                   u.SecurityStamp, u.WrappedUserDataKey,
                   u.EmailOtpHash, u.EmailOtpExpiresAt, u.EmailOtpFailCount,
                   u.NotifyCollectReady, u.NotifySendOpened,
                   s.ExpiresAt, s.SecurityStamp AS SessStamp
            FROM sessions s
            INNER JOIN users u ON u.Id = s.UserId
            WHERE s.Id = @sid
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@sid", sessionId);
        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return null;

        var expires = DateTimeOffset.Parse(r.GetString(r.GetOrdinal("ExpiresAt")));
        if (expires < DateTimeOffset.UtcNow)
            return null;

        var userStamp = r.GetString(r.GetOrdinal("SecurityStamp"));
        var sessStamp = r.GetString(r.GetOrdinal("SessStamp"));
        if (!string.Equals(userStamp, sessStamp, StringComparison.Ordinal))
            return null;

        // Incomplete registration must never hold a usable session.
        if (r.GetInt32(r.GetOrdinal("EmailConfirmed")) == 0)
            return null;

        return ReadUser(r);
    }

    public void DeleteSession(string sessionId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sessions WHERE Id = @id";
        cmd.Parameters.AddWithValue("@id", sessionId);
        cmd.ExecuteNonQuery();
    }

    public void DeleteAllSessionsForUser(string userId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sessions WHERE UserId = @uid";
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.ExecuteNonQuery();
    }

    public void CreatePasswordResetToken(string userId, string tokenHash, DateTimeOffset expiresAt)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO password_reset_tokens (TokenHash, UserId, ExpiresAt, UsedAt)
            VALUES (@hash, @uid, @exp, NULL)
            """;
        cmd.Parameters.AddWithValue("@hash", tokenHash);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.Parameters.AddWithValue("@exp", expiresAt.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public (string UserId, string ExpiresAt, string? UsedAt)? FindResetToken(string tokenHash)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT UserId, ExpiresAt, UsedAt FROM password_reset_tokens
            WHERE TokenHash = @hash LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@hash", tokenHash);
        using var r = cmd.ExecuteReader();
        if (!r.Read())
            return null;
        return (
            r.GetString(0),
            r.GetString(1),
            r.IsDBNull(2) ? null : r.GetString(2)
        );
    }

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static string UtcNow() => DateTimeOffset.UtcNow.ToString("O");

    private UserRecord ReadUser(SqliteDataReader r)
    {
        string? wudk = null;
        try
        {
            var ord = r.GetOrdinal("WrappedUserDataKey");
            if (!r.IsDBNull(ord))
                wudk = r.GetString(ord);
        }
        catch
        {
            // Column may be absent mid-migration.
        }

        return new UserRecord
        {
            Id = r.GetString(r.GetOrdinal("Id")),
            Email = r.GetString(r.GetOrdinal("Email")),
            PasswordSalt = (byte[])r["PasswordSalt"],
            PasswordHash = (byte[])r["PasswordHash"],
            PasswordHashIterations = r.GetInt32(r.GetOrdinal("PasswordHashIterations")),
            EmailConfirmed = r.GetInt32(r.GetOrdinal("EmailConfirmed")) != 0,
            CreatedAt = r.GetString(r.GetOrdinal("CreatedAt")),
            TotpSecret = r.IsDBNull(r.GetOrdinal("TotpSecret"))
                ? null
                : _protector.UnprotectUtf8(r.GetString(r.GetOrdinal("TotpSecret"))),
            TotpEnabled = r.GetInt32(r.GetOrdinal("TotpEnabled")) != 0,
            TotpPendingSecret = r.IsDBNull(r.GetOrdinal("TotpPendingSecret"))
                ? null
                : _protector.UnprotectUtf8(r.GetString(r.GetOrdinal("TotpPendingSecret"))),
            SecurityStamp = r.GetString(r.GetOrdinal("SecurityStamp")),
            WrappedUserDataKey = wudk,
            EmailOtpHash = TryGetString(r, "EmailOtpHash"),
            EmailOtpExpiresAt = TryGetString(r, "EmailOtpExpiresAt"),
            EmailOtpFailCount = TryGetInt(r, "EmailOtpFailCount"),
            NotifyCollectReady = TryGetInt(r, "NotifyCollectReady") != 0,
            NotifySendOpened = TryGetInt(r, "NotifySendOpened") != 0
        };
    }

    /// <summary>Update optional email notification prefs (both fields required; default off).</summary>
    public bool SetNotificationPrefs(string userId, bool notifyCollectReady, bool notifySendOpened)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE users SET
                NotifyCollectReady = @collect,
                NotifySendOpened = @send
            WHERE Id = @id
            """;
        cmd.Parameters.AddWithValue("@id", userId);
        cmd.Parameters.AddWithValue("@collect", notifyCollectReady ? 1 : 0);
        cmd.Parameters.AddWithValue("@send", notifySendOpened ? 1 : 0);
        return cmd.ExecuteNonQuery() > 0;
    }

    private static string? TryGetString(SqliteDataReader r, string column)
    {
        try
        {
            var ord = r.GetOrdinal(column);
            return r.IsDBNull(ord) ? null : r.GetString(ord);
        }
        catch
        {
            return null;
        }
    }

    private static int TryGetInt(SqliteDataReader r, string column)
    {
        try
        {
            var ord = r.GetOrdinal(column);
            return r.IsDBNull(ord) ? 0 : r.GetInt32(ord);
        }
        catch
        {
            return 0;
        }
    }
}
