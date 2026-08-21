using Microsoft.Data.Sqlite;
using Sendit.Api.Data;
using Sendit.Api.Models;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Secret-request persistence. Stores the uploader-facing public key and optional
/// owner private key (at-rest protected) so the owner can re-open collect links from the dashboard.
/// Payload ciphertext is still client-encrypted; the server does not decrypt secrets.
/// </summary>
public sealed class RequestStore
{
    private readonly DbConnectionFactory _db;
    private readonly DataAtRestProtector _protector;

    public RequestStore(DbConnectionFactory db, DataAtRestProtector protector)
    {
        _db = db;
        _protector = protector;
    }

    /// <summary>
    /// Bytes of uploaded crypto payload stored for this collect owner
    /// (ciphertext + iv + wrapped key + eph pk). Empty/pending collects count as 0.
    /// </summary>
    public long SumStoredPayloadBytes(string ownerUserId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT COALESCE(SUM(
                COALESCE(LENGTH(Ciphertext), 0) + COALESCE(LENGTH(Iv), 0)
                + COALESCE(LENGTH(WrappedKey), 0) + COALESCE(LENGTH(EphemeralPublicKey), 0)
            ), 0)
            FROM requests
            WHERE OwnerUserId = @owner
            """;
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        var o = cmd.ExecuteScalar();
        return o is long l ? l : Convert.ToInt64(o ?? 0L);
    }

    public string Create(
        string ownerUserId,
        string? label,
        byte[] publicKey,
        byte[]? ownerPrivateKeyPlain,
        bool oneTime,
        DateTimeOffset expiresAt,
        int? maxAccessCount = null,
        string? encryptedLabelWire = null,
        string? privateNoteCiphertext = null,
        bool hideTextByDefault = false,
        bool passwordProtected = false)
    {
        var id = IdGenerator.NewId();
        byte[]? protectedSk = null;
        if (ownerPrivateKeyPlain is { Length: > 0 })
            protectedSk = _protector.Protect(ownerPrivateKeyPlain);

        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests (
                Id, OwnerUserId, Label, PublicKey, OwnerPrivateKeyProtected,
                OneTime, CreatedAt, ExpiresAt, Uploaded, MaxAccessCount, AccessCount,
                EncryptedLabelWire, PrivateNoteCiphertext, HideTextByDefault, PasswordProtected
            ) VALUES (
                @id, @owner, @label, @pk, @osk,
                @onetime, @created, @expires, 0, @maxacc, 0,
                @elabel, @pnote, @hide, @pw
            )
            """;
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        // Owner dashboard: UDK ciphertext (or legacy plaintext). Not returned on public GET.
        cmd.Parameters.AddWithValue("@label", (object?)Truncate(label, FieldLimits.NameCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pk", publicKey);
        cmd.Parameters.AddWithValue("@osk", (object?)protectedSk ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@onetime", oneTime ? 1 : 0);
        cmd.Parameters.AddWithValue("@created", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@expires", expiresAt.ToString("O"));
        cmd.Parameters.AddWithValue("@maxacc", (object?)maxAccessCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@elabel", (object?)Truncate(encryptedLabelWire, FieldLimits.NameCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@pnote", (object?)Truncate(privateNoteCiphertext, FieldLimits.PrivateNoteCiphertext) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@hide", hideTextByDefault ? 1 : 0);
        cmd.Parameters.AddWithValue("@pw", passwordProtected ? 1 : 0);
        cmd.ExecuteNonQuery();
        return id;
    }

    public RequestRecord? Get(string id)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT Id, OwnerUserId, Label, PublicKey, OwnerPrivateKeyProtected, OneTime, CreatedAt, ExpiresAt, Uploaded,
                   Ciphertext, Iv, WrappedKey, EphemeralPublicKey, ContentType, Filename, ConsumedAt,
                   MaxAccessCount, AccessCount, EncryptedLabelWire, PrivateNoteCiphertext, HideTextByDefault,
                   PasswordProtected
            FROM requests WHERE Id = @id LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Read(r) : null;
    }

    public bool TryUpload(
        string id,
        byte[] ciphertext,
        byte[] iv,
        byte[] wrappedKey,
        byte[]? ephemeralPublicKey,
        string contentType,
        string? filename)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE requests
            SET Uploaded = 1,
                Ciphertext = @ct,
                Iv = @iv,
                WrappedKey = @wk,
                EphemeralPublicKey = @epk,
                ContentType = @ctype,
                Filename = @fname
            WHERE Id = @id
              AND Uploaded = 0
              AND ConsumedAt IS NULL
              AND ExpiresAt > @now
            """;
        cmd.Parameters.AddWithValue("@ct", ciphertext);
        cmd.Parameters.AddWithValue("@iv", iv);
        cmd.Parameters.AddWithValue("@wk", wrappedKey);
        cmd.Parameters.AddWithValue("@epk", (object?)ephemeralPublicKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ctype", Truncate(contentType, 128) ?? "application/octet-stream");
        cmd.Parameters.AddWithValue("@fname", (object?)Truncate(filename, 255) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        return cmd.ExecuteNonQuery() == 1;
    }

    /// <summary>
    /// Retrieves payload. Increments access count for multi-view; burns when one-time
    /// or when multi-view hits MaxAccessCount.
    /// </summary>
    public RequestRecord? RetrievePayloadAndMaybeBurn(string id)
    {
        using var conn = _db.Create();
        using var tx = conn.BeginTransaction();

        using var sel = conn.CreateCommand();
        sel.Transaction = tx;
        sel.CommandText = """
            SELECT Id, OwnerUserId, Label, PublicKey, OwnerPrivateKeyProtected, OneTime, CreatedAt, ExpiresAt, Uploaded,
                   Ciphertext, Iv, WrappedKey, EphemeralPublicKey, ContentType, Filename, ConsumedAt,
                   MaxAccessCount, AccessCount, EncryptedLabelWire, PrivateNoteCiphertext, HideTextByDefault,
                   PasswordProtected
            FROM requests WHERE Id = @id LIMIT 1
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

        if (!rec.Uploaded || rec.Ciphertext is null || rec.Ciphertext.Length == 0)
        {
            tx.Rollback();
            return null;
        }
        if (DateTimeOffset.Parse(rec.ExpiresAt) < DateTimeOffset.UtcNow)
        {
            tx.Rollback();
            return null;
        }
        if (rec.ConsumedAt is not null)
        {
            tx.Rollback();
            return null;
        }

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
                UPDATE requests
                SET AccessCount = AccessCount + 1,
                    ConsumedAt = @at,
                    Ciphertext = NULL,
                    Iv = NULL,
                    WrappedKey = NULL,
                    EphemeralPublicKey = NULL
                WHERE Id = @id AND ConsumedAt IS NULL AND Uploaded = 1
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
            upd.CommandText = """
                UPDATE requests
                SET AccessCount = AccessCount + 1
                WHERE Id = @id AND ConsumedAt IS NULL AND Uploaded = 1
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

    public bool DeleteOwned(string id, string ownerUserId)
    {
        using var conn = _db.Create();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM requests WHERE Id = @id AND OwnerUserId = @owner";
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
            SELECT Id, Label, OneTime, CreatedAt, ExpiresAt, Uploaded, ConsumedAt, ContentType, Filename,
                   OwnerPrivateKeyProtected, MaxAccessCount, AccessCount, PrivateNoteCiphertext, PasswordProtected
            FROM requests
            WHERE OwnerUserId = @owner
            ORDER BY CreatedAt DESC
            """;
        cmd.Parameters.AddWithValue("@owner", ownerUserId);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var expires = r.GetString(r.GetOrdinal("ExpiresAt"));
            var uploaded = r.GetInt32(r.GetOrdinal("Uploaded")) != 0;
            var consumed = r.IsDBNull(r.GetOrdinal("ConsumedAt")) ? null : r.GetString(r.GetOrdinal("ConsumedAt"));
            // Hide expired and consumed (one-time or max-access exhausted) items.
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
            var oneTime = r.GetInt32(r.GetOrdinal("OneTime")) != 0;
            if (!oneTime && maxAcc is int m && acc >= m)
                continue;

            string status = uploaded ? "ready" : "pending";

            string? collectSk = null;
            if (!r.IsDBNull(r.GetOrdinal("OwnerPrivateKeyProtected")))
            {
                try
                {
                    var protectedBlob = (byte[])r["OwnerPrivateKeyProtected"];
                    var plain = _protector.Unprotect(protectedBlob);
                    collectSk = Base64Url.Encode(plain);
                }
                catch
                {
                    // Wrong SENDIT_DATA_KEY or corrupt blob — omit reopen key.
                    collectSk = null;
                }
            }

            var passwordProtected = HasColumn(r, "PasswordProtected")
                && !r.IsDBNull(r.GetOrdinal("PasswordProtected"))
                && r.GetInt32(r.GetOrdinal("PasswordProtected")) != 0;

            list.Add(new DashboardItem
            {
                Id = r.GetString(r.GetOrdinal("Id")),
                Kind = "collect",
                Label = r.IsDBNull(r.GetOrdinal("Label")) ? null : r.GetString(r.GetOrdinal("Label")),
                OneTime = oneTime,
                CreatedAt = r.GetString(r.GetOrdinal("CreatedAt")),
                ExpiresAt = expires,
                Status = status,
                ContentType = r.IsDBNull(r.GetOrdinal("ContentType")) ? null : r.GetString(r.GetOrdinal("ContentType")),
                Filename = r.IsDBNull(r.GetOrdinal("Filename")) ? null : r.GetString(r.GetOrdinal("Filename")),
                CollectSecretKey = collectSk,
                MaxAccessCount = maxAcc,
                AccessCount = acc,
                PrivateNoteCiphertext = HasColumn(r, "PrivateNoteCiphertext")
                    && !r.IsDBNull(r.GetOrdinal("PrivateNoteCiphertext"))
                    ? r.GetString(r.GetOrdinal("PrivateNoteCiphertext"))
                    : null,
                PasswordProtected = passwordProtected
            });
        }
        return list;
    }

    public int PurgeExpired()
    {
        using var conn = _db.Create();
        // Remove past-expiry rows, consumed requests, and multi-view at max opens.
        using var sel = conn.CreateCommand();
        sel.CommandText = """
            SELECT Id, ExpiresAt, ConsumedAt, OneTime, MaxAccessCount, AccessCount
            FROM requests
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
            del.CommandText = "DELETE FROM requests WHERE Id = @id";
            del.Parameters.AddWithValue("@id", id);
            n += del.ExecuteNonQuery();
        }
        return n;
    }

    private static RequestRecord Read(SqliteDataReader r)
    {
        var hasOsk = false;
        try { _ = r.GetOrdinal("OwnerPrivateKeyProtected"); hasOsk = true; }
        catch { /* column missing on very old readers */ }

        return new RequestRecord
        {
            Id = r.GetString(r.GetOrdinal("Id")),
            OwnerUserId = r.GetString(r.GetOrdinal("OwnerUserId")),
            Label = r.IsDBNull(r.GetOrdinal("Label")) ? null : r.GetString(r.GetOrdinal("Label")),
            PublicKey = (byte[])r["PublicKey"],
            OwnerPrivateKeyProtected = hasOsk && !r.IsDBNull(r.GetOrdinal("OwnerPrivateKeyProtected"))
                ? (byte[])r["OwnerPrivateKeyProtected"]
                : null,
            OneTime = r.GetInt32(r.GetOrdinal("OneTime")) != 0,
            CreatedAt = r.GetString(r.GetOrdinal("CreatedAt")),
            ExpiresAt = r.GetString(r.GetOrdinal("ExpiresAt")),
            Uploaded = r.GetInt32(r.GetOrdinal("Uploaded")) != 0,
            Ciphertext = r.IsDBNull(r.GetOrdinal("Ciphertext")) ? null : (byte[])r["Ciphertext"],
            Iv = r.IsDBNull(r.GetOrdinal("Iv")) ? null : (byte[])r["Iv"],
            WrappedKey = r.IsDBNull(r.GetOrdinal("WrappedKey")) ? null : (byte[])r["WrappedKey"],
            EphemeralPublicKey = r.IsDBNull(r.GetOrdinal("EphemeralPublicKey"))
                ? null
                : (byte[])r["EphemeralPublicKey"],
            ContentType = r.IsDBNull(r.GetOrdinal("ContentType")) ? null : r.GetString(r.GetOrdinal("ContentType")),
            Filename = r.IsDBNull(r.GetOrdinal("Filename")) ? null : r.GetString(r.GetOrdinal("Filename")),
            ConsumedAt = r.IsDBNull(r.GetOrdinal("ConsumedAt")) ? null : r.GetString(r.GetOrdinal("ConsumedAt")),
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
            PrivateNoteCiphertext = HasColumn(r, "PrivateNoteCiphertext")
                && !r.IsDBNull(r.GetOrdinal("PrivateNoteCiphertext"))
                ? r.GetString(r.GetOrdinal("PrivateNoteCiphertext"))
                : null,
            HideTextByDefault = HasColumn(r, "HideTextByDefault")
                && !r.IsDBNull(r.GetOrdinal("HideTextByDefault"))
                && r.GetInt32(r.GetOrdinal("HideTextByDefault")) != 0,
            PasswordProtected = HasColumn(r, "PasswordProtected")
                && !r.IsDBNull(r.GetOrdinal("PasswordProtected"))
                && r.GetInt32(r.GetOrdinal("PasswordProtected")) != 0
        };
    }

    private static bool HasColumn(SqliteDataReader r, string name)
    {
        try
        {
            _ = r.GetOrdinal(name);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? Truncate(string? s, int max) =>
        s is null ? null : (s.Length <= max ? s : s[..max]);
}
