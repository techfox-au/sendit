using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

/// <summary>
/// Test double for <see cref="IEmailSender"/> that records messages so OTP codes
/// and reset links can be read by integration tests.
/// </summary>
public sealed class CapturingEmailSender : IEmailSender
{
    private static readonly Regex OtpCodePattern = new(
        @"verification code is:\s*(\d{6})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ConcurrentQueue<(string To, string Subject, string Body, string? Html)> Messages { get; } =
        new();

    public Task SendAsync(
        string to,
        string subject,
        string plainBody,
        CancellationToken ct = default,
        string? htmlBody = null)
    {
        Messages.Enqueue((to, subject, plainBody, htmlBody));
        return Task.CompletedTask;
    }

    public string? TryGetLatestOtpCode()
    {
        var last = Messages.LastOrDefault(m =>
            m.Subject.Contains("verification", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrEmpty(last.Body))
            return null;
        var m = OtpCodePattern.Match(last.Body);
        return m.Success ? m.Groups[1].Value : null;
    }
}
