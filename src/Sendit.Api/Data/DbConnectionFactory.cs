using Microsoft.Data.Sqlite;
using Sendit.Api.Configuration;

namespace Sendit.Api.Data;

/// <summary>
/// Creates SQLite connections. Callers must dispose connections.
/// All SQL in this project uses parameters — never string-concatenate user input into SQL.
/// </summary>
public sealed class DbConnectionFactory
{
    private readonly string _connectionString;

    public DbConnectionFactory(SenditOptions options)
    {
        var path = options.DbPath;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && dir != ".")
            Directory.CreateDirectory(dir);

        // Mode=ReadWriteCreate ensures the file is created if missing.
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            ForeignKeys = true
        }.ToString();
    }

    public SqliteConnection Create()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
            cmd.ExecuteNonQuery();
        }
        return conn;
    }
}
