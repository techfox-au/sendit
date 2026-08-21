using System.Collections.Concurrent;
using System.Globalization;

namespace Sendit.Api.Logging;

/// <summary>
/// Minimal thread-safe file logger. Enabled when SENDIT_LOG_FILE is set.
/// </summary>
public sealed class SimpleFileLoggerProvider : ILoggerProvider
{
    private readonly string _path;
    private readonly LogLevel _minLevel;
    private readonly ConcurrentDictionary<string, SimpleFileLogger> _loggers = new(StringComparer.Ordinal);
    private readonly object _writeLock = new();

    public SimpleFileLoggerProvider(string path, LogLevel minLevel = LogLevel.Information)
    {
        _path = path;
        _minLevel = minLevel;
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
    }

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new SimpleFileLogger(name, this, _minLevel));

    internal void Write(string line)
    {
        lock (_writeLock)
        {
            File.AppendAllText(_path, line + Environment.NewLine);
        }
    }

    public void Dispose() => _loggers.Clear();
}

internal sealed class SimpleFileLogger : ILogger
{
    private readonly string _category;
    private readonly SimpleFileLoggerProvider _provider;
    private readonly LogLevel _minLevel;

    public SimpleFileLogger(string category, SimpleFileLoggerProvider provider, LogLevel minLevel)
    {
        _category = category;
        _provider = provider;
        _minLevel = minLevel;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= _minLevel && logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;
        var msg = formatter(state, exception);
        // [UTC date - UTC time] then level + category (matches console TimestampFormat).
        var stamp = DateTime.UtcNow.ToString(
            "[yyyy-MM-dd - HH:mm:ss]",
            CultureInfo.InvariantCulture);
        var line = $"{stamp} [{logLevel}] {_category}: {msg}";
        if (exception is not null)
            line += Environment.NewLine + exception;
        _provider.Write(line);
    }
}
