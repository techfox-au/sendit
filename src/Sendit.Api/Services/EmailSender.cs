using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sendit.Api.Configuration;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// Transactional email: SMTP preferred when configured; Mailgun as primary when SMTP is
/// unset, or as failover when SMTP throws/times out. With neither transport, Development
/// logs the full message body; other environments log an error without secrets.
/// SMTP uses <see cref="SmtpClient"/> with EnableSsl → STARTTLS (port 587), not implicit SSL (465).
/// Each transport is limited to <see cref="TransportTimeout"/> (7s) so auth UI cannot hang.
/// </summary>
public sealed class EmailSender : IEmailSender
{
    /// <summary>Per-transport send timeout (SMTP and Mailgun each).</summary>
    public static readonly TimeSpan TransportTimeout = TimeSpan.FromSeconds(7);

    private readonly SenditOptions _options;
    private readonly ILogger<EmailSender> _log;
    private readonly IHostEnvironment _env;
    private readonly IHttpClientFactory _httpClientFactory;

    public EmailSender(
        SenditOptions options,
        ILogger<EmailSender> log,
        IHostEnvironment env,
        IHttpClientFactory httpClientFactory)
    {
        _options = options;
        _log = log;
        _env = env;
        _httpClientFactory = httpClientFactory;
    }

    public async Task SendAsync(
        string to,
        string subject,
        string plainBody,
        CancellationToken ct = default,
        string? htmlBody = null)
    {
        // Never deliver OTP, password-reset, or notification mail to banned addresses.
        if (_options.IsEmailBanned(to))
        {
            _log.LogInformation(
                "Suppressed outbound email to banned address (subject: {Subject}).",
                subject);
            return;
        }

        var smtp = _options.IsSmtpConfigured;
        var mailgun = _options.IsMailgunConfigured;

        if (!smtp && !mailgun)
        {
            LogNoTransport(to, subject, plainBody, htmlBody);
            return;
        }

        Exception? last = null;

        // SMTP first when configured; Mailgun is failover (or sole transport).
        if (smtp)
        {
            try
            {
                await SendSmtpAsync(to, subject, plainBody, htmlBody, ct);
                return;
            }
            catch (Exception ex)
            {
                last = ex;
                if (mailgun)
                {
                    _log.LogWarning(ex,
                        "SMTP send failed or timed out for {To} ({Subject}); failing over to Mailgun.",
                        to, subject);
                }
                else
                {
                    _log.LogError(ex, "SMTP send failed or timed out for {To} ({Subject}).", to, subject);
                    throw WrapSendFailure(ex);
                }
            }
        }

        if (mailgun)
        {
            try
            {
                await SendMailgunAsync(to, subject, plainBody, htmlBody, ct);
                return;
            }
            catch (Exception ex)
            {
                last = ex;
                _log.LogError(ex, "Mailgun send failed or timed out for {To} ({Subject}).", to, subject);
                throw WrapSendFailure(ex);
            }
        }

        throw WrapSendFailure(last ?? new InvalidOperationException("No email transport available."));
    }

    private static InvalidOperationException WrapSendFailure(Exception ex) =>
        new("Could not send email in time. Check mail settings or try again later.", ex);

    private async Task SendSmtpAsync(
        string to,
        string subject,
        string plainBody,
        string? htmlBody,
        CancellationToken ct)
    {
        using var client = new SmtpClient(_options.SmtpHost!, _options.SmtpPort)
        {
            EnableSsl = _options.SmtpEnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            // SmtpClient.Timeout is the primary abort for hung sockets (milliseconds).
            Timeout = (int)TransportTimeout.TotalMilliseconds
        };
        if (!string.IsNullOrEmpty(_options.SmtpUser))
            client.Credentials = new NetworkCredential(_options.SmtpUser, _options.SmtpPassword);

        using var msg = new MailMessage
        {
            From = new MailAddress(_options.SmtpFrom),
            Subject = subject
        };
        msg.To.Add(to);

        var inlineResources = new List<LinkedResource>();
        try
        {
            if (!string.IsNullOrWhiteSpace(htmlBody))
            {
                // multipart/alternative: plain + HTML. Logo + gutter spacers as LinkedResources
                // (cid:… so clients show them without loading remote images).
                msg.AlternateViews.Add(
                    AlternateView.CreateAlternateViewFromString(
                        plainBody, Encoding.UTF8, MediaTypeNames.Text.Plain));

                var htmlView = AlternateView.CreateAlternateViewFromString(
                    htmlBody, Encoding.UTF8, MediaTypeNames.Text.Html);
                foreach (var res in CreateInlineImageResources(htmlBody))
                {
                    inlineResources.Add(res);
                    htmlView.LinkedResources.Add(res);
                }
                msg.AlternateViews.Add(htmlView);
            }
            else
            {
                msg.Body = plainBody;
                msg.IsBodyHtml = false;
                msg.BodyEncoding = Encoding.UTF8;
            }

            // WaitAsync so we do not hang past TransportTimeout even if Timeout is ignored.
            try
            {
                await client.SendMailAsync(msg, ct).WaitAsync(TransportTimeout, ct);
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(
                    $"SMTP timed out after {(int)TransportTimeout.TotalSeconds}s.");
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"SMTP timed out after {(int)TransportTimeout.TotalSeconds}s.");
            }

            _log.LogInformation("Email sent via SMTP to {To} ({Subject}).", to, subject);
        }
        finally
        {
            foreach (var r in inlineResources)
                r.Dispose();
        }
    }

    /// <summary>
    /// CID images for HTML mail: themed logo + primary CTA button PNG (Outlook-safe colour).
    /// Page gutters are table spacers, not images.
    /// </summary>
    private List<LinkedResource> CreateInlineImageResources(string? htmlBody)
    {
        var list = new List<LinkedResource>();
        try
        {
            var png = HighlightColor.ThemeWordmarkLogoPng(_options.Highlight);
            list.Add(CreatePngLinkedResource(png, EmailHtmlTemplate.LogoContentId));
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "Could not generate themed logo PNG for SMTP (need libSkiaSharp + fontconfig in the image). " +
                "Sending HTML without embedded logo.");
        }

        TryAddCtaButtonResource(list, htmlBody);
        return list;
    }

    private void TryAddCtaButtonResource(List<LinkedResource> list, string? htmlBody)
    {
        if (string.IsNullOrEmpty(htmlBody)
            || !htmlBody.Contains(EmailHtmlTemplate.CtaButtonContentId, StringComparison.Ordinal))
            return;
        try
        {
            var label = EmailHtmlTemplate.TryParseCtaButtonAlt(htmlBody) ?? "CONTINUE";
            var png = HighlightColor.ThemeCtaButtonPng(label, _options.Highlight, out _, out _);
            list.Add(CreatePngLinkedResource(png, EmailHtmlTemplate.CtaButtonContentId));
        }
        catch (Exception ex)
        {
            _log.LogError(ex,
                "Could not generate themed CTA button PNG (need Skia + a font such as DejaVu).");
        }
    }

    private static LinkedResource CreatePngLinkedResource(byte[] png, string contentId)
    {
        var ms = new MemoryStream(png, writable: false);
        var res = new LinkedResource(ms, new ContentType("image/png"))
        {
            ContentId = contentId,
            TransferEncoding = TransferEncoding.Base64,
        };
        res.ContentType.Name = contentId;
        res.ContentType.MediaType = "image/png";
        res.ContentLink = new Uri("cid:" + contentId);
        return res;
    }

    private async Task SendMailgunAsync(
        string to,
        string subject,
        string plainBody,
        string? htmlBody,
        CancellationToken ct)
    {
        var domain = NormalizeMailgunDomain(_options.MailgunDomain!);
        var apiKey = _options.MailgunApiKey!.Trim();
        var from = ResolveMailgunFrom();
        var baseUrl = NormalizeMailgunBaseUrl(_options.MailgunBaseUrl);

        // Official: POST {base}/v3/{domain}/messages  (base has no /v3 suffix)
        var url = $"{baseUrl}/v3/{Uri.EscapeDataString(domain)}/messages";

        // Multipart: HTML references cid:sendit-logo.png; logo bytes go as Mailgun "inline"
        // so the delivered MIME embeds the image (not a remote URL).
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent(from), "from");
        content.Add(new StringContent(to), "to");
        content.Add(new StringContent(subject), "subject");
        content.Add(new StringContent(plainBody), "text");
        if (!string.IsNullOrWhiteSpace(htmlBody))
            content.Add(new StringContent(htmlBody, Encoding.UTF8, "text/html"), "html");

        if (!string.IsNullOrWhiteSpace(htmlBody))
        {
            try
            {
                var png = HighlightColor.ThemeWordmarkLogoPng(_options.Highlight);
                var logoPart = new ByteArrayContent(png);
                logoPart.Headers.ContentType = new MediaTypeHeaderValue("image/png");
                // Mailgun: form field name "inline" + filename → embedded CID matching HTML src.
                content.Add(logoPart, "inline", EmailHtmlTemplate.LogoContentId);
            }
            catch (Exception ex)
            {
                _log.LogError(ex,
                    "Could not generate themed logo PNG for Mailgun (need libSkiaSharp + fontconfig in the image). " +
                    "Sending HTML without embedded logo.");
            }

            if (htmlBody.Contains(EmailHtmlTemplate.CtaButtonContentId, StringComparison.Ordinal))
            {
                try
                {
                    var label = EmailHtmlTemplate.TryParseCtaButtonAlt(htmlBody) ?? "CONTINUE";
                    var cta = HighlightColor.ThemeCtaButtonPng(label, _options.Highlight, out _, out _);
                    var ctaPart = new ByteArrayContent(cta);
                    ctaPart.Headers.ContentType = new MediaTypeHeaderValue("image/png");
                    content.Add(ctaPart, "inline", EmailHtmlTemplate.CtaButtonContentId);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex,
                        "Could not generate themed CTA button PNG for Mailgun (need Skia + a font such as DejaVu).");
                }
            }
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{apiKey}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", auth);

        var http = _httpClientFactory.CreateClient(nameof(EmailSender));
        try
        {
            using var response = await http.SendAsync(request, ct).WaitAsync(TransportTimeout, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                var snippet = body.Length > 300 ? body[..300] + "…" : body;
                var code = (int)response.StatusCode;
                // 404 "page not found" is almost always wrong base region or domain path.
                var hint = code == 404
                    ? " Check SENDIT_MAILGUN_DOMAIN is the exact Mailgun sending domain " +
                      "(e.g. mg.example.com, not a mailbox address), and SENDIT_MAILGUN_BASE_URL " +
                      "matches the domain’s region: https://api.mailgun.net (US) or " +
                      "https://api.eu.mailgun.net (EU). Do not append /v3 to the base URL."
                    : "";
                throw new InvalidOperationException(
                    $"Mailgun send failed HTTP {code} for POST {url}: {snippet.Trim()}{hint}");
            }

            // 200 only means Mailgun accepted the message for delivery — not that the
            // recipient's mailbox has it yet. Log id for Mailgun dashboard / logs lookup.
            var mailgunId = TryParseMailgunMessageId(body);
            if (!string.IsNullOrEmpty(mailgunId))
            {
                _log.LogInformation(
                    "Email accepted by Mailgun to {To} ({Subject}); mailgunId={MailgunId} from={From}. " +
                    "If missing in inbox, check Mailgun Logs for that id, spam, and domain DNS (SPF/DKIM).",
                    to, subject, mailgunId, from);
            }
            else
            {
                _log.LogInformation(
                    "Email accepted by Mailgun to {To} ({Subject}); from={From}. " +
                    "If missing in inbox, check Mailgun Logs, spam, and domain DNS (SPF/DKIM).",
                    to, subject, from);
            }
        }
        catch (TimeoutException)
        {
            throw new TimeoutException(
                $"Mailgun timed out after {(int)TransportTimeout.TotalSeconds}s.");
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Mailgun timed out after {(int)TransportTimeout.TotalSeconds}s.", ex);
        }
    }

    /// <summary>Parse <c>{"id":"&lt;…@…&gt;","message":"Queued. Thank you."}</c> from a 200 body.</summary>
    private static string? TryParseMailgunMessageId(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        // Avoid a JSON package dependency: pull "id":"…"
        const string key = "\"id\"";
        var i = json.IndexOf(key, StringComparison.Ordinal);
        if (i < 0) return null;
        i = json.IndexOf(':', i + key.Length);
        if (i < 0) return null;
        i = json.IndexOf('"', i + 1);
        if (i < 0) return null;
        var j = json.IndexOf('"', i + 1);
        if (j <= i + 1) return null;
        return json[(i + 1)..j];
    }

    /// <summary>
    /// Base host only: strip trailing slash and accidental <c>/v3</c> so we never build
    /// <c>.../v3/v3/domain/messages</c>.
    /// </summary>
    public static string NormalizeMailgunBaseUrl(string? raw)
    {
        var baseUrl = string.IsNullOrWhiteSpace(raw)
            ? "https://api.mailgun.net"
            : raw.Trim().TrimEnd('/');
        if (baseUrl.EndsWith("/v3", StringComparison.OrdinalIgnoreCase))
            baseUrl = baseUrl[..^3].TrimEnd('/');
        return baseUrl;
    }

    /// <summary>
    /// Sending domain only (no scheme, path, or mailbox). Mailgun path is
    /// <c>/v3/{domain}/messages</c>.
    /// </summary>
    public static string NormalizeMailgunDomain(string raw)
    {
        var d = raw.Trim().TrimStart('@').Trim().TrimEnd('/');
        // Accidental full URL → host or last path segment.
        if (d.Contains("://", StringComparison.Ordinal))
        {
            if (Uri.TryCreate(d, UriKind.Absolute, out var uri))
            {
                // https://api.mailgun.net/v3/mg.example.com → use path tail if present
                var segs = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (segs.Length > 0 && !string.Equals(segs[^1], "v3", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(segs[^1], "messages", StringComparison.OrdinalIgnoreCase))
                    d = segs[^1];
                else if (!string.IsNullOrEmpty(uri.Host)
                         && !uri.Host.Contains("mailgun", StringComparison.OrdinalIgnoreCase))
                    d = uri.Host;
            }
        }
        var slash = d.IndexOf('/');
        if (slash >= 0)
            d = d[..slash];
        // Mailbox pasted by mistake: take domain part only.
        var at = d.LastIndexOf('@');
        if (at >= 0 && at < d.Length - 1)
            d = d[(at + 1)..];
        return d.Trim();
    }

    private string ResolveMailgunFrom()
    {
        if (!string.IsNullOrWhiteSpace(_options.MailgunFrom))
            return _options.MailgunFrom.Trim();
        if (!string.IsNullOrWhiteSpace(_options.SmtpFrom)
            && !string.Equals(_options.SmtpFrom, "noreply@localhost", StringComparison.OrdinalIgnoreCase))
            return _options.SmtpFrom.Trim();
        var domain = _options.MailgunDomain?.Trim();
        return string.IsNullOrEmpty(domain) ? "noreply@localhost" : $"noreply@{domain}";
    }

    private void LogNoTransport(string to, string subject, string plainBody, string? htmlBody)
    {
        if (_env.IsDevelopment())
        {
            var banner =
                "\n========== SENDIT EMAIL (no SMTP/Mailgun configured) ==========\n" +
                $"To: {to}\n" +
                $"Subject: {subject}\n" +
                $"{plainBody}\n" +
                (string.IsNullOrWhiteSpace(htmlBody) ? "" : $"--- HTML ---\n{htmlBody}\n") +
                "===============================================================\n";
            Console.WriteLine(banner);
            _log.LogWarning(
                "SMTP/Mailgun not configured. Dev fallback email to {To}: {Subject}\n{Body}",
                to, subject, plainBody);
        }
        else
        {
            _log.LogError(
                "No email transport configured in {Environment}. Transactional email to {To} ({Subject}) was NOT sent. " +
                "Set SENDIT_SMTP_HOST (and related SENDIT_SMTP_*) and/or SENDIT_MAILGUN_DOMAIN + SENDIT_MAILGUN_API_KEY.",
                _env.EnvironmentName, to, subject);
        }
    }
}
