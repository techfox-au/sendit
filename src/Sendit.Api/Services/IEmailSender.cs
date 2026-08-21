namespace Sendit.Api.Services;

public interface IEmailSender
{
    /// <param name="plainBody">Always required (clients that ignore HTML).</param>
    /// <param name="htmlBody">Optional HTML alternative; when set, multipart plain+html is sent
    /// and the themed Sendit! wordmark PNG is MIME-embedded (CID inline attachment), not
    /// linked as a remote image URL.</param>
    Task SendAsync(
        string to,
        string subject,
        string plainBody,
        CancellationToken ct = default,
        string? htmlBody = null);
}
