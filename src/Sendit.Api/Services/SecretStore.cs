using Microsoft.Data.Sqlite;
using Sendit.Api.Data;
using Sendit.Api.Models;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Encrypted send (secret link) persistence. Server never decrypts payloads.
/// All SQL uses bound parameters.
/// </summary>
public sealed class SecretStore
{
    private readonly DbConnectionFactory _db;

    public SecretStore(DbConnectionFactory db) => _db = db;

    /// <summary>
    /// Bytes of crypto payload stored for this owner (ciphertext + iv + wrapped key + eph pk).
    /// </summary>
    public long SumStoredPayloadBytes(string ownerUserId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT COALESCE(SUM(
                LENGTH(Ciphertext) + LENGTH(Iv) + LENGTH(WrappedKey)
                + COALESCE(LENGTH(EphemeralPublicKey), 0)
            ), 0)
            FROM secrets
            WHERE OwnerUserId = @owner
            """;
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        var o = cmd.ExecuteScalar();
        return o is long l ? l : Convert.ToInt64(o ?? 0L);
    }

    public string Create(
        string ownerUserId,
        string? label,
        byte[] ciphertext,
        byte[] iv,
        byte[] wrappedKey,
        byte[]? ephemeralPublicKey,
        string contentType,
        string? filename,
        bool oneTime,
        DateTimeOffset expiresAt,
        string? allowedCidr = null,
        bool hideTextByDefault = false,
        string? privateNoteCiphertext = null,
        int? maxAccessCount = null,
        string? encryptedLabelWire = null,
        bool passwordProtected = false)
    {
        var id = IdGenerator.NewId();
        var now = DateTimeOffset.UtcNow.ToString("O");
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO secrets (
                Id, OwnerUserId, Label, Ciphertext, Iv, WrappedKey, EphemeralPublicKey,
                ContentType, Filename, OneTime, CreatedAt, ExpiresAt, ConsumedAt, AllowedCidr,
                HideTextByDefault, PrivateNoteCiphertext, MaxAccessCount, AccessCount, EncryptedLabelWire,
                PasswordProtected
            ) VALUES (
                @id, @owner, @label, @ct, @iv, @wk, @epk,
                @ctype, @fname, @onetime, @created, @expires, NULL, @cidr,
                @hide, @note, @maxacc, 0, @elabel,
                @pw
            )
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        // Label holds owner UDK ciphertext of send name (or legacy plaintext), not shown publicly.
        cmd.Parameters.AddWithValue("@label", (object?)Truncate(label, FieldLimits.NameCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ct", ciphertext);
        cmd.Parameters.AddWithValue("@iv", iv);
        cmd.Parameters.AddWithValue("@wk", wrappedKey);
        cmd.Parameters.AddWithValue("@epk", (object?)ephemeralPublicKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ctype", Truncate(contentType, 128) ?? "application/octet-stream");
        cmd.Parameters.AddWithValue("@fname", (object?)Truncate(filename, 255) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@onetime", oneTime ? 1 : 0);
        cmd.Parameters.AddWithValue("@created", now);
        cmd.Parameters.AddWithValue("@expires", expiresAt.ToString("O"));
        cmd.Parameters.AddWithValue("@cidr", (object?)Truncate(allowedCidr, FieldLimits.AllowedIps) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@hide", hideTextByDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@note", (object?)Truncate(privateNoteCiphertext, FieldLimits.PrivateNoteCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@maxacc", (object?)maxAccessCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@elabel", (object?)Truncate(encryptedLabelWire, FieldLimits.NameCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pw", passwordProtected ? 1 : 0);
        cmd.ExecuteNonQuery();
        return id;
    }

    public SecretRecord? GetMeta(string id)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Id, OwnerUserId, Label, Ciphertext, Iv, WrappedKey, EphemeralPublicKey,
                   ContentType, Filename, OneTime, CreatedAt, ExpiresAt, ConsumedAt, AllowedCidr,
                   HideTextByDefault, PrivateNoteCiphertext, MaxAccessCount, AccessCount, EncryptedLabelWire,
                   PasswordProtected
            FROM secrets WHERE Id = @id LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    /// <summary>
    /// Retrieves payload. Increments access count for multi-view; burns when one-time
    /// or when multi-view hits MaxAccessCount.
    /// </summary>
    public SecretRecord? RetrieveAndMaybeBurn(string id)
    {
        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();

        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT Id, OwnerUserId, Label, Ciphertext, Iv, WrappedKey, EphemeralPublicKey,
                       ContentType, Filename, OneTime, CreatedAt, ExpiresAt, ConsumedAt, AllowedCidr,
                       HideTextByDefault, PrivateNoteCiphertext, MaxAccessCount, AccessCount, EncryptedLabelWire,
                       PasswordProtected
                FROM secrets WHERE Id = @id LIMIT 1
                """;
            sel.Parameters.AddWithValue("@id", id);
            using var r = sel.ExecuteReader();
            if (!r.Read())
            {
                tx.Rollback();
                return null;
            }
            var rec = Read(r);
            r.Close();

            if (DateTimeOffset.Parse(rec.ExpiresAt) < DateTimeOffset.UtcNow)
            {
                tx.Rollback();
                return null;
            }
            if (rec.ConsumedAt is not null || rec.Ciphertext.Length == 0)
            {
                tx.Rollback();
                return null;
            }

            // Atomic increment: prevent lost updates under concurrent multi-view opens.
            // WHERE AccessCount = @old acts as optimistic concurrency; max is enforced here.
            if (!rec.OneTime
                && rec.MaxAccessCount is int maxHit
                && rec.AccessCount >= maxHit)
            {
                tx.Rollback();
                return null;
            }

            var newCount = rec.AccessCount + 1;
            var shouldBurn = rec.OneTime
                || (rec.MaxAccessCount is int max && newCount >= max);

            if (shouldBurn)
            {
                using var upd = conn.CreateCommand();
                upd.Transaction = tx;
                upd.CommandText = """
                    UPDATE secrets
                    SET AccessCount = AccessCount + 1,
                        ConsumedAt = @at,
                        Ciphertext = x'',
                        Iv = x'',
                        WrappedKey = x'',
                        EphemeralPublicKey = NULL
                    WHERE Id = @id AND ConsumedAt IS NULL
                      AND AccessCount = @old
                    """;
                upd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
                upd.Parameters.AddWithValue("@id", id);
                upd.Parameters.AddWithValue("@old", rec.AccessCount);
                if (upd.ExecuteNonQuery() != 1)
                {
                    tx.Rollback();
                    return null;
                }
            }
            else
            {
                using var upd = conn.CreateCommand();
                upd.Transaction = tx;
                // Only succeed if still under max (NULL max = unlimited) and count unchanged.
                upd.CommandText = """
                    UPDATE secrets
                    SET AccessCount = AccessCount + 1
                    WHERE Id = @id AND ConsumedAt IS NULL
                      AND AccessCount = @old
                      AND (MaxAccessCount IS NULL OR AccessCount < MaxAccessCount)
                    """;
                upd.Parameters.AddWithValue("@id", id);
                upd.Parameters.AddWithValue("@old", rec.AccessCount);
                if (upd.ExecuteNonQuery() != 1)
                {
                    tx.Rollback();
                    return null;
                }
            }

            tx.Commit();
            return rec with { AccessCount = newCount };
        }
    }

    public bool DeleteOwned(string id, string ownerUserId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM secrets WHERE Id = @id AND OwnerUserId = @owner";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public List<DashboardItem> ListForOwner(string ownerUserId)
    {
        var list = new List<DashboardItem>();
        var now = DateTimeOffset.UtcNow;
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Id, Label, OneTime, CreatedAt, ExpiresAt, ConsumedAt, ContentType, Filename,
                   PrivateNoteCiphertext, MaxAccessCount, AccessCount, PasswordProtected, AllowedCidr
            FROM secrets
            WHERE OwnerUserId = @owner
            ORDER BY CreatedAt DESC
            """;
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var expires = r.GetString(r.GetOrdinal("ExpiresAt"));
            var consumed = r.IsDBNull(r.GetOrdinal("ConsumedAt")) ? null : r.GetString(r.GetOrdinal("ConsumedAt"));
            if (consumed is not null)
                continue;
            if (!DateTimeOffset.TryParse(expires, out var exp) || exp <= now)
                continue;

            int? maxAcc = null;
            if (HasColumn(r, "MaxAccessCount") && !r.IsDBNull(r.GetOrdinal("MaxAccessCount")))
                maxAcc = r.GetInt32(r.GetOrdinal("MaxAccessCount"));
            var acc = HasColumn(r, "AccessCount") && !r.IsDBNull(r.GetOrdinal("AccessCount"))
                ? r.GetInt32(r.GetOrdinal("AccessCount"))
                : 0;
            // Multi-view at limit without ConsumedAt (legacy) — treat as gone.
            if (maxAcc is int m && acc >= m)
                continue;

            string? note = null;
            if (HasColumn(r, "PrivateNoteCiphertext") && !r.IsDBNull(r.GetOrdinal("PrivateNoteCiphertext")))
                note = r.GetString(r.GetOrdinal("PrivateNoteCiphertext"));

            var passwordProtected = HasColumn(r, "PasswordProtected")
                && !r.IsDBNull(r.GetOrdinal("PasswordProtected"))
                && r.GetInt32(r.GetOrdinal("PasswordProtected")) != 0;

            // Non-empty allow-list (not bare "*") means this send is IP-restricted.
            string? allowedCidr = null;
            if (HasColumn(r, "AllowedCidr") && !r.IsDBNull(r.GetOrdinal("AllowedCidr")))
                allowedCidr = r.GetString(r.GetOrdinal("AllowedCidr"));
            var ipRestricted = !string.IsNullOrWhiteSpace(allowedCidr)
                && !string.Equals(allowedCidr.Trim(), "*", StringComparison.Ordinal);

            list.Add(new DashboardItem
            {
                Id = r.GetString(r.GetOrdinal("Id")),
                Kind = "send",
                Label = r.IsDBNull(r.GetOrdinal("Label")) ? null : r.GetString(r.GetOrdinal("Label")),
                OneTime = r.GetInt32(r.GetOrdinal("OneTime")) != 0,
                CreatedAt = r.GetString(r.GetOrdinal("CreatedAt")),
                ExpiresAt = expires,
                // List already skips expired/consumed rows; remaining sends are active.
                Status = "active",
                ContentType = r.IsDBNull(r.GetOrdinal("ContentType")) ? null : r.GetString(r.GetOrdinal("ContentType")),
                Filename = r.IsDBNull(r.GetOrdinal("Filename")) ? null : r.GetString(r.GetOrdinal("Filename")),
                PrivateNoteCiphertext = note,
                MaxAccessCount = maxAcc,
                AccessCount = acc,
                PasswordProtected = passwordProtected,
                IpRestricted = ipRestricted
            });
        }
        return list;
    }

    public int PurgeExpired()
    {
        using var conn = _db.Create();
        using (var sel = conn.CreateCommand())
        {
            sel.CommandText = """
                SELECT Id, ExpiresAt, ConsumedAt, OneTime, MaxAccessCount, AccessCount
                FROM secrets
                """;
            using var r = sel.ExecuteReader();
            var toDelete = new List<string>();
            var now = DateTimeOffset.UtcNow;
            while (r.Read())
            {
                var id = r.GetString(0);
                var expires = r.GetString(1);
                var consumed = r.IsDBNull(2) ? null : r.GetString(2);
                var oneTime = r.GetInt32(3) != 0;
                int? maxAcc = r.IsDBNull(4) ? null : r.GetInt32(4);
                var acc = r.IsDBNull(5) ? 0 : r.GetInt32(5);
                var atLimit = !oneTime && maxAcc is int m && acc >= m;
                if (consumed is not null
                    || atLimit
                    || !DateTimeOffset.TryParse(expires, out var exp)
                    || exp <= now)
                {
                    toDelete.Add(id);
                }
            }
            r.Close();

            if (toDelete.Count == 0)
                return 0;

            var n = 0;
            foreach (var id in toDelete)
            {
                using var del = conn.CreateCommand();
                del.CommandText = "DELETE FROM secrets WHERE Id = @id";
                del.Parameters.AddWithValue("@id", id);
                n += del.ExecuteNonQuery();
            }
            return n;
        }
    }

    private static SecretRecord Read(SqliteDataReader r) => new()
    {
        Id = r.GetString(r.GetOrdinal("Id")),
        OwnerUserId = r.GetString(r.GetOrdinal("OwnerUserId")),
        Label = r.IsDBNull(r.GetOrdinal("Label")) ? null : r.GetString(r.GetOrdinal("Label")),
        Ciphertext = (byte[])r["Ciphertext"],
        Iv = (byte[])r["Iv"],
        WrappedKey = (byte[])r["WrappedKey"],
        EphemeralPublicKey = r.IsDBNull(r.GetOrdinal("EphemeralPublicKey"))
            ? null
            : (byte[])r["EphemeralPublicKey"],
        ContentType = r.GetString(r.GetOrdinal("ContentType")),
        Filename = r.IsDBNull(r.GetOrdinal("Filename")) ? null : r.GetString(r.GetOrdinal("Filename")),
        OneTime = r.GetInt32(r.GetOrdinal("OneTime")) != 0,
        AllowedCidr = HasColumn(r, "AllowedCidr") && !r.IsDBNull(r.GetOrdinal("AllowedCidr"))
            ? r.GetString(r.GetOrdinal("AllowedCidr"))
            : null,
        HideTextByDefault = HasColumn(r, "HideTextByDefault")
            && !r.IsDBNull(r.GetOrdinal("HideTextByDefault"))
            && r.GetInt32(r.GetOrdinal("HideTextByDefault")) != 0,
        PrivateNoteCiphertext = HasColumn(r, "PrivateNoteCiphertext")
            && !r.IsDBNull(r.GetOrdinal("PrivateNoteCiphertext"))
            ? r.GetString(r.GetOrdinal("PrivateNoteCiphertext"))
            : null,
        MaxAccessCount = HasColumn(r, "MaxAccessCount") && !r.IsDBNull(r.GetOrdinal("MaxAccessCount"))
            ? r.GetInt32(r.GetOrdinal("MaxAccessCount"))
            : null,
        AccessCount = HasColumn(r, "AccessCount") && !r.IsDBNull(r.GetOrdinal("AccessCount"))
            ? r.GetInt32(r.GetOrdinal("AccessCount"))
            : 0,
        EncryptedLabelWire = HasColumn(r, "EncryptedLabelWire")
            && !r.IsDBNull(r.GetOrdinal("EncryptedLabelWire"))
            ? r.GetString(r.GetOrdinal("EncryptedLabelWire"))
            : null,
        PasswordProtected = HasColumn(r, "PasswordProtected")
            && !r.IsDBNull(r.GetOrdinal("PasswordProtected"))
            && r.GetInt32(r.GetOrdinal("PasswordProtected")) != 0,
        CreatedAt = r.GetString(r.GetOrdinal("CreatedAt")),
        ExpiresAt = r.GetString(r.GetOrdinal("ExpiresAt")),
        ConsumedAt = r.IsDBNull(r.GetOrdinal("ConsumedAt")) ? null : r.GetString(r.GetOrdinal("ConsumedAt"))
    };

    private static bool HasColumn(SqliteDataReader r, string name)
    {
        for (var i = 0; i < r.FieldCount; i++)
        {
            if (string.Equals(r.GetName(i), name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string? Truncate(string? s, int max) =>
        s is null ? null : (s.Length <= max ? s : s[..max]);
}
