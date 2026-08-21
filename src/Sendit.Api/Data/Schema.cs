using Microsoft.Data.Sqlite;

namespace Sendit.Api.Data;

/// <summary>
/// Creates and migrates the SQLite schema. All statements are fixed SQL (no user input).
/// </summary>
public static class Schema
{
    public static void EnsureCreated(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                Id TEXT PRIMARY KEY NOT NULL,
                Email TEXT NOT NULL COLLATE NOCASE,
                PasswordSalt BLOB NOT NULL,
                PasswordHash BLOB NOT NULL,
                PasswordHashIterations INTEGER NOT NULL,
                EmailConfirmed INTEGER NOT NULL DEFAULT 0,
                CreatedAt TEXT NOT NULL,
                TotpSecret TEXT NULL,
                TotpEnabled INTEGER NOT NULL DEFAULT 0,
                TotpPendingSecret TEXT NULL,
                SecurityStamp TEXT NOT NULL,
                -- LastPasswordAttemptAt: legacy unused (throttle is in auth_throttle_state).
                LastPasswordAttemptAt TEXT NULL,
                WrappedUserDataKey TEXT NULL,
                EmailOtpHash TEXT NULL,
                EmailOtpExpiresAt TEXT NULL,
                NotifyCollectReady INTEGER NOT NULL DEFAULT 0,
                NotifySendOpened INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users(Email);

            CREATE TABLE IF NOT EXISTS sessions (
                Id TEXT PRIMARY KEY NOT NULL,
                UserId TEXT NOT NULL,
                SecurityStamp TEXT NOT NULL,
                CreatedAt TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                FOREIGN KEY (UserId) REFERENCES users(Id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(UserId);
            CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(ExpiresAt);

            -- Shared across API instances that use the same DB file (multi-instance PoW/scan).
            CREATE TABLE IF NOT EXISTS pow_challenges (
                Id TEXT PRIMARY KEY NOT NULL,
                ResourceKind TEXT NOT NULL,
                ResourceId TEXT NOT NULL,
                HmacKey BLOB NOT NULL,
                DifficultyBits INTEGER NOT NULL,
                ExpiresAt TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_pow_expires ON pow_challenges(ExpiresAt);

            CREATE TABLE IF NOT EXISTS scan_events (
                Kind TEXT NOT NULL,
                ClientKey TEXT NOT NULL,
                AtMs INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_scan_events ON scan_events(Kind, ClientKey, AtMs);

            -- Multi-instance auth lockout / progressive delay / email budget (shared DB).
            CREATE TABLE IF NOT EXISTS auth_throttle_state (
                Kind TEXT NOT NULL,
                Key TEXT NOT NULL,
                FailCount INTEGER NOT NULL DEFAULT 0,
                LockoutUntilMs INTEGER NULL,
                LastAttemptMs INTEGER NOT NULL DEFAULT 0,
                SendCount INTEGER NOT NULL DEFAULT 0,
                LastSendMs INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (Kind, Key)
            );

            -- Multi-instance fixed-window IP rate limits for auth/forgot/api (shared DB).
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                Bucket TEXT NOT NULL,
                ClientKey TEXT NOT NULL,
                AtMs INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_rate_limit_events ON rate_limit_events(Bucket, ClientKey, AtMs);

            -- One-time auth step tickets (email-otp / totp); jti bound into the HMAC ticket.
            CREATE TABLE IF NOT EXISTS auth_tickets (
                Id TEXT PRIMARY KEY NOT NULL,
                Purpose TEXT NOT NULL,
                UserId TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                UsedAt TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_auth_tickets_expires ON auth_tickets(ExpiresAt);

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                TokenHash TEXT PRIMARY KEY NOT NULL,
                UserId TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                UsedAt TEXT NULL,
                FOREIGN KEY (UserId) REFERENCES users(Id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_reset_user ON password_reset_tokens(UserId);

            -- Append-only activity audit (no UPDATE/DELETE APIs; SQLite triggers enforce immutability).
            CREATE TABLE IF NOT EXISTS audit_log (
                Id TEXT PRIMARY KEY NOT NULL,
                AtUtc TEXT NOT NULL,
                Kind TEXT NOT NULL,
                Message TEXT NOT NULL,
                ActorUserId TEXT NULL,
                ActorEmail TEXT NULL,
                OwnerUserId TEXT NULL,
                ResourceKind TEXT NULL,
                ResourceId TEXT NULL,
                ClientIp TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_audit_at ON audit_log(AtUtc);
            CREATE INDEX IF NOT EXISTS ix_audit_owner ON audit_log(OwnerUserId, AtUtc);
            CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_log(ActorUserId, AtUtc);

            CREATE TABLE IF NOT EXISTS secrets (
                Id TEXT PRIMARY KEY NOT NULL,
                OwnerUserId TEXT NOT NULL,
                Label TEXT NULL,
                Ciphertext BLOB NOT NULL,
                Iv BLOB NOT NULL,
                WrappedKey BLOB NOT NULL,
                EphemeralPublicKey BLOB NULL,
                ContentType TEXT NOT NULL,
                Filename TEXT NULL,
                OneTime INTEGER NOT NULL,
                CreatedAt TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                ConsumedAt TEXT NULL,
                AllowedCidr TEXT NULL,
                HideTextByDefault INTEGER NOT NULL DEFAULT 0,
                PrivateNoteCiphertext TEXT NULL,
                MaxAccessCount INTEGER NULL,
                AccessCount INTEGER NOT NULL DEFAULT 0,
                EncryptedLabelWire TEXT NULL,
                PasswordProtected INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (OwnerUserId) REFERENCES users(Id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_secrets_owner ON secrets(OwnerUserId);
            CREATE INDEX IF NOT EXISTS ix_secrets_expires ON secrets(ExpiresAt);

            CREATE TABLE IF NOT EXISTS requests (
                Id TEXT PRIMARY KEY NOT NULL,
                OwnerUserId TEXT NOT NULL,
                Label TEXT NULL,
                PublicKey BLOB NOT NULL,
                OwnerPrivateKeyProtected BLOB NULL,
                OneTime INTEGER NOT NULL,
                CreatedAt TEXT NOT NULL,
                ExpiresAt TEXT NOT NULL,
                Uploaded INTEGER NOT NULL DEFAULT 0,
                Ciphertext BLOB NULL,
                Iv BLOB NULL,
                WrappedKey BLOB NULL,
                EphemeralPublicKey BLOB NULL,
                ContentType TEXT NULL,
                Filename TEXT NULL,
                ConsumedAt TEXT NULL,
                MaxAccessCount INTEGER NULL,
                AccessCount INTEGER NOT NULL DEFAULT 0,
                EncryptedLabelWire TEXT NULL,
                PrivateNoteCiphertext TEXT NULL,
                HideTextByDefault INTEGER NOT NULL DEFAULT 0,
                PasswordProtected INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (OwnerUserId) REFERENCES users(Id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_requests_owner ON requests(OwnerUserId);
            CREATE INDEX IF NOT EXISTS ix_requests_expires ON requests(ExpiresAt);
            """;
        cmd.ExecuteNonQuery();
        EnsureColumn(conn, "requests", "OwnerPrivateKeyProtected", "BLOB NULL");
        EnsureColumn(conn, "requests", "MaxAccessCount", "INTEGER NULL");
        EnsureColumn(conn, "requests", "AccessCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "requests", "EncryptedLabelWire", "TEXT NULL");
        EnsureColumn(conn, "requests", "PrivateNoteCiphertext", "TEXT NULL");
        EnsureColumn(conn, "requests", "HideTextByDefault", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "requests", "PasswordProtected", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "secrets", "AllowedCidr", "TEXT NULL");
        EnsureColumn(conn, "secrets", "HideTextByDefault", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "secrets", "PrivateNoteCiphertext", "TEXT NULL");
        EnsureColumn(conn, "secrets", "MaxAccessCount", "INTEGER NULL");
        EnsureColumn(conn, "secrets", "AccessCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "secrets", "EncryptedLabelWire", "TEXT NULL");
        EnsureColumn(conn, "secrets", "PasswordProtected", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "users", "WrappedUserDataKey", "TEXT NULL");
        EnsureColumn(conn, "users", "EmailOtpHash", "TEXT NULL");
        EnsureColumn(conn, "users", "EmailOtpExpiresAt", "TEXT NULL");
        // Legacy per-user lockout columns (unused; lockout is auth_throttle_state). Keep for existing DBs.
        EnsureColumn(conn, "users", "PasswordFailCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "users", "LockoutUntil", "TEXT NULL");
        EnsureColumn(conn, "users", "EmailOtpFailCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "users", "TotpFailCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "users", "NotifyCollectReady", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(conn, "users", "NotifySendOpened", "INTEGER NOT NULL DEFAULT 0");

        // Immutable audit_log: block UPDATE/DELETE even if a future code path tries.
        EnsureAuditImmutabilityTriggers(conn);
    }

    private static void EnsureAuditImmutabilityTriggers(SqliteConnection conn)
    {
        using (var drop = conn.CreateCommand())
        {
            drop.CommandText = """
                DROP TRIGGER IF EXISTS audit_log_no_update;
                DROP TRIGGER IF EXISTS audit_log_no_delete;
                """;
            drop.ExecuteNonQuery();
        }

        using var create = conn.CreateCommand();
        create.CommandText = """
            CREATE TRIGGER audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is immutable');
            END;
            CREATE TRIGGER audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is immutable');
            END;
            """;
        create.ExecuteNonQuery();
    }

    /// <summary>Add a column if missing (safe for existing DBs). Names are fixed constants only.</summary>
    private static void EnsureColumn(SqliteConnection conn, string table, string column, string decl)
    {
        using var check = conn.CreateCommand();
        check.CommandText = $"PRAGMA table_info({table});";
        using var r = check.ExecuteReader();
        while (r.Read())
        {
            if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return;
        }
        r.Close();

        using var alter = conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {decl};";
        alter.ExecuteNonQuery();
    }
}
