using System.Net;
using Microsoft.Extensions.Logging;
using Sendit.Api.Configuration;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Optional user notification emails (collect ready / send opened).
/// Uses the same <see cref="IEmailSender"/> path as email OTP: SMTP up to 7s, then Mailgun
/// up to 7s (failover), then fail. Sends are fire-and-forget so API latency is not blocked
/// for up to 14s; failures are logged only. HTML uses <see cref="EmailHtmlTemplate"/> with
/// a themed CID logo.
/// </summary>
public sealed class NotificationEmailService
{
    private readonly IEmailSender _email;
    private readonly UserStore _users;
    private readonly AuthThrottleService _throttle;
    private readonly ILogger<NotificationEmailService> _log;
    private readonly SenditOptions _options;

    public NotificationEmailService(
        IEmailSender email,
        UserStore users,
        SenditOptions options,
        AuthThrottleService throttle,
        ILogger<NotificationEmailService> log)
    {
        _email = email;
        _users = users;
        _options = options;
        _throttle = throttle;
        _log = log;
    }

    /// <summary>Someone uploaded to a collect link; notify owner if they opted in.</summary>
    public void TryNotifyCollectReady(string ownerUserId, string collectId)
    {
        var dash = DashboardUrl();
        var intro =
            "Someone submitted a response to one of your Sendit! collect links.";
        var footer =
            "If you did not expect this, you can ignore this email or turn off notifications in Settings.";

        TryNotify(
            ownerUserId,
            pref: u => u.NotifyCollectReady,
            prefName: "notifyCollectReady",
            kind: "collect_ready",
            subject: "Sendit! - A collect is ready",
            plainBody: BuildPlain(intro, "Collect id:", collectId, dash, footer),
            htmlBody: BuildNotifyHtml(
                "A collect is ready", intro, "Collect id:", collectId, dash, footer));
    }

    /// <summary>Recipient downloaded a send payload for browser decryption; notify owner if opted in.</summary>
    public void TryNotifySendOpened(string ownerUserId, string sendId)
    {
        var dash = DashboardUrl();
        var intro =
            "Someone opened one of your Sendit! links and downloaded the encrypted payload " +
            "for decryption in their browser.";
        var footer =
            "If you did not expect this, you can ignore this email or turn off notifications in Settings.";

        TryNotify(
            ownerUserId,
            pref: u => u.NotifySendOpened,
            prefName: "notifySendOpened",
            kind: "send_opened",
            subject: "Sendit! - A send was opened",
            plainBody: BuildPlain(intro, "Send id:", sendId, dash, footer),
            htmlBody: BuildNotifyHtml(
                "A send was opened", intro, "Send id:", sendId, dash, footer));
    }

    private static string BuildPlain(
        string intro,
        string idLabel,
        string idValue,
        string dashboardUrl,
        string footer) =>
        intro + "\n\n" +
        idLabel + " " + idValue + "\n\n" +
        "Dashboard\n" + dashboardUrl + "\n\n" +
        footer;

    private string BuildNotifyHtml(
        string heading,
        string intro,
        string idLabel,
        string idValue,
        string dashboardUrl,
        string footer)
    {
        var body =
            EmailHtmlTemplate.ParagraphsFromPlain(intro) +
            EmailHtmlTemplate.BoldLabelLine(idLabel, idValue, _options.Highlight) +
            EmailHtmlTemplate.CtaButton(dashboardUrl, "Open dashboard", _options.Highlight) +
            EmailHtmlTemplate.ParagraphsFromPlain(footer);
        return EmailHtmlTemplate.Render(heading, body, _options, preheader: intro);
    }

    private void TryNotify(
        string ownerUserId,
        Func<Models.UserRecord, bool> pref,
        string prefName,
        string kind,
        string subject,
        string plainBody,
        string htmlBody)
    {
        if (string.IsNullOrWhiteSpace(ownerUserId))
        {
            _log.LogWarning("Notification {Kind} skipped: missing owner user id.", kind);
            return;
        }

        var user = _users.FindById(ownerUserId);
        if (user is null)
        {
            _log.LogWarning(
                "Notification {Kind} skipped: owner {OwnerId} not found.",
                kind,
                ownerUserId);
            return;
        }

        if (!pref(user))
        {
            _log.LogDebug(
                "Notification {Kind} skipped for {Email}: preference {Pref} is off.",
                kind,
                user.Email,
                prefName);
            return;
        }

        // Do not gate on IsEmailTransportConfigured here — OTP and other mail go straight to
        // IEmailSender (SMTP / Mailgun / dev console).

        if (!_throttle.TryAllowNotifyEmail(user.Email, out var retryAfter))
        {
            _log.LogWarning(
                "Notification {Kind} throttled for {Email} (retry in {Retry:0}s). " +
                "Preference is on but the notify email budget is not ready yet.",
                kind,
                user.Email,
                retryAfter.TotalSeconds);
            return;
        }

        _log.LogInformation(
            "Notification {Kind} queued for {Email} (subject={Subject}).",
            kind,
            user.Email,
            subject);

        QueueSend(user.Email, subject, plainBody, htmlBody, kind);
    }

    private string DashboardUrl() =>
        (_options.PublicBaseUrl ?? "").TrimEnd('/') + "/dashboard";

    private void QueueSend(string to, string subject, string plainBody, string htmlBody, string kind)
    {
        _ = SendAndTrackAsync(to, subject, plainBody, htmlBody, kind);
    }

    private async Task SendAndTrackAsync(
        string to,
        string subject,
        string plainBody,
        string htmlBody,
        string kind)
    {
        try
        {
            await _email.SendAsync(to, subject, plainBody, htmlBody: htmlBody).ConfigureAwait(false);
            _throttle.NoteNotifyEmailSent(to);
            _log.LogInformation("Notification email sent kind={Kind} to={To}", kind, to);
        }
        catch (Exception ex)
        {
            _log.LogWarning(
                ex,
                "Notification email failed kind={Kind} to={To} (SMTP then Mailgun each up to 7s).",
                kind,
                to);
        }
    }
}
