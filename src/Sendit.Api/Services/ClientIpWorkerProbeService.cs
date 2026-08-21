using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Sendit.Api.Configuration;
using Sendit.Api.Util;

namespace Sendit.Api.Services;

/// <summary>
/// One-shot after listen: POST <see cref="SenditOptions.PublicBaseUrl"/> to the Cloudflare
/// Worker canary and wait for its reply (not a scheduled loop).
/// <para>
/// Outcomes (see also <see cref="ClientIpCapability"/>):
/// </para>
/// <list type="bullet">
/// <item>Worker <c>ok: true</c> → <see cref="ClientIpCapability.MarkVerified"/> (restrictions stay on).</item>
/// <item>Worker <c>check.isPrivateOrLocal: true</c> or probe skipped →
/// <see cref="ClientIpCapability.MarkUnverified"/> + WARNING; if collect retrieve allow-list
/// is restrictive, ERROR and <see cref="Environment.Exit"/>(1).</item>
/// <item>Cannot reach Worker / inconclusive body → WARNING with attempted URL;
/// <see cref="ClientIpCapability.MarkInconclusive"/> (restrictions stay on).</item>
/// </list>
/// Worker source: <c>deploy/cloudflare-worker-check-ip/</c>.
/// </summary>
public sealed class ClientIpWorkerProbeService : BackgroundService
{
    public const string HttpClientName = nameof(ClientIpWorkerProbeService);

    private readonly ILogger<ClientIpWorkerProbeService> _log;
    private readonly SenditOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ClientIpCapability _capability;

    public ClientIpWorkerProbeService(
        ILogger<ClientIpWorkerProbeService> log,
        SenditOptions options,
        IHttpClientFactory httpClientFactory,
        IHostApplicationLifetime lifetime,
        ClientIpCapability capability)
    {
        _log = log;
        _options = options;
        _httpClientFactory = httpClientFactory;
        _lifetime = lifetime;
        _capability = capability;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait until Kestrel is accepting so the Worker can callback diagnostics.
        try
        {
            await Task.Delay(Timeout.Infinite, _lifetime.ApplicationStarted).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.ApplicationStarted.IsCancellationRequested)
        {
            // started
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }

        // Brief settle for nginx/proxy in front of the API.
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        var workerUrl = (_options.IpCheckWorkerUrl ?? "").Trim().TrimEnd('/');
        if (string.IsNullOrEmpty(workerUrl))
        {
            FailUnverified(
                "Client-IP Worker probe skipped: SENDIT_IP_CHECK_WORKER_URL is disabled. " +
                "IP-based restrictions are disabled.");
            return;
        }

        if (!Uri.TryCreate(workerUrl, UriKind.Absolute, out var workerUri)
            || (workerUri.Scheme != Uri.UriSchemeHttp && workerUri.Scheme != Uri.UriSchemeHttps))
        {
            FailUnverified(
                "Client-IP Worker probe skipped: SENDIT_IP_CHECK_WORKER_URL is not a valid http(s) URL. " +
                "IP-based restrictions are disabled.");
            return;
        }

        var baseUrl = (_options.PublicBaseUrl ?? "").Trim().TrimEnd('/');
        if (string.IsNullOrEmpty(baseUrl)
            || !Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps))
        {
            FailUnverified(
                "Client-IP Worker probe skipped: SENDIT_PUBLIC_BASE_URL is missing or invalid. " +
                "IP-based restrictions are disabled.");
            return;
        }

        // Cloudflare Workers cannot call private LAN / loopback origins (error 1003 / 403).
        // Skip the canary instead of a noisy inconclusive 502 in local HTTPS dev.
        if (IsHostUnreachableFromCloudflareWorker(baseUri.Host))
        {
            FailUnverified(
                "Client-IP Worker probe skipped: SENDIT_PUBLIC_BASE_URL host is not reachable " +
                "from the public Cloudflare Worker (" + baseUri.Host + " — localhost/LAN/private IP). " +
                "Use a public DNS hostname for production canary checks. " +
                "IP-based restrictions are disabled.");
            return;
        }

        _log.LogInformation(
            "Client-IP Worker probe (one-shot): POST {Worker} baseUrl={BaseUrl} …",
            workerUri,
            baseUrl);

        try
        {
            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var req = new HttpRequestMessage(HttpMethod.Post, workerUri);
            req.Content = new StringContent(
                JsonSerializer.Serialize(new { baseUrl }),
                Encoding.UTF8,
                "application/json");

            // Worker CALLER_SECRET gate (not the Sendit! diagnostics probe secret).
            var caller = (_options.IpCheckWorkerCallerSecret ?? "").Trim();
            if (!string.IsNullOrEmpty(caller))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
            }

            using var res = await client.SendAsync(req, stoppingToken).ConfigureAwait(false);
            var bodyText = await res.Content.ReadAsStringAsync(stoppingToken).ConfigureAwait(false);

            if (TryParseWorkerOk(bodyText, out var publicIp, out _, out var okUpstream))
            {
                _capability.MarkVerified();
                _log.LogInformation(
                    "Client-IP Worker probe OK: Worker reported public clientIp={ClientIp} " +
                    "(upstreamStatus={Upstream}). Proxy client-IP path looks good; " +
                    "IP-based restrictions remain enabled.",
                    publicIp ?? "(unknown)",
                    okUpstream?.ToString() ?? "?");
                return;
            }

            // Only a definitive non-public IP from the Worker disables restrictions.
            if (TryParseNonPublicClientIp(bodyText, out var privateIp, out var hint, out var badUpstream))
            {
                FailUnverified(
                    "Client-IP Worker probe FAILED: Worker reported a non-public client IP " +
                    "(clientIp=" + (privateIp ?? "(none)") +
                    ", upstreamStatus=" + (badUpstream?.ToString() ?? "?") +
                    ", hint=" + (string.IsNullOrWhiteSpace(hint) ? "(none)" : hint) +
                    "). Seeing only a local/non-public client IP; IP-based restrictions are disabled.");
                return;
            }

            _capability.MarkInconclusive();
            _log.LogWarning(
                "Client-IP Worker probe inconclusive: HTTP {Status} from Worker at {WorkerUrl} " +
                "(not a confirmed non-public client IP). IP-based restrictions remain enabled. Body: {Body}",
                (int)res.StatusCode,
                workerUri.ToString(),
                Truncate(bodyText, 300));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shut down mid-probe
        }
        catch (Exception ex)
        {
            // Network/DNS/TLS to Cloudflare — not a private-IP verdict.
            var attemptedUrl = workerUri.ToString();
            _capability.MarkInconclusive();
            _log.LogWarning(
                ex,
                "WARNING: could not reach Cloudflare Worker for client-IP canary. " +
                "Attempted URL: {WorkerUrl}. Error: {ErrorMessage}. " +
                "This is not treated as a private client IP; IP-based restrictions remain enabled. " +
                "Check outbound HTTPS, DNS, firewall, and CALLER_SECRET.",
                attemptedUrl,
                ex.Message);
        }
    }

    private void FailUnverified(string warningMessage)
    {
        _log.LogWarning("{Message}", warningMessage);
        _capability.MarkUnverified();
        AbortIfCollectIpRestrictionsConfigured();
    }

    private void AbortIfCollectIpRestrictionsConfigured()
    {
        if (!ClientIpCapability.IsRestrictiveCollectIpList(_options.CollectionRetrieveAllowedIps))
            return;

        _log.LogError(
            "SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS is set to a restrictive list ({List}), " +
            "but the client-IP probe confirmed a non-public client IP (or probe was skipped). " +
            "IP restrictions for collect retrieval cannot be enforced. " +
            "Fix reverse-proxy client IP forwarding, or clear SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS " +
            "(or set it to *). Shutting down.",
            _options.CollectionRetrieveAllowedIps);

        try
        {
            _lifetime.StopApplication();
        }
        catch
        {
            // ignore
        }

        Environment.Exit(1);
    }

    /// <summary>Worker top-level <c>ok: true</c> (public client IP path).</summary>
    public static bool TryParseWorkerOk(
        string? bodyText,
        out string? clientIp,
        out string? hint,
        out int? upstreamStatus)
    {
        clientIp = null;
        hint = null;
        upstreamStatus = null;
        if (!TryParseWorkerPayload(bodyText, out var root, out clientIp, out hint, out upstreamStatus))
            return false;

        return root.TryGetProperty("ok", out var okEl)
            && okEl.ValueKind is JsonValueKind.True or JsonValueKind.False
            && okEl.GetBoolean();
    }

    /// <summary>
    /// Worker body with <c>check.isPrivateOrLocal: true</c> — definitive non-public IP.
    /// </summary>
    public static bool TryParseNonPublicClientIp(
        string? bodyText,
        out string? clientIp,
        out string? hint,
        out int? upstreamStatus)
    {
        clientIp = null;
        hint = null;
        upstreamStatus = null;
        if (!TryParseWorkerPayload(bodyText, out var root, out clientIp, out hint, out upstreamStatus))
            return false;

        if (!root.TryGetProperty("check", out var checkEl) || checkEl.ValueKind != JsonValueKind.Object)
            return false;

        return checkEl.TryGetProperty("isPrivateOrLocal", out var privEl)
            && privEl.ValueKind == JsonValueKind.True;
    }

    private static bool TryParseWorkerPayload(
        string? bodyText,
        out JsonElement root,
        out string? clientIp,
        out string? hint,
        out int? upstreamStatus)
    {
        root = default;
        clientIp = null;
        hint = null;
        upstreamStatus = null;
        if (string.IsNullOrWhiteSpace(bodyText))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(bodyText);
            root = doc.RootElement.Clone();
            if (root.TryGetProperty("hint", out var hintEl) && hintEl.ValueKind == JsonValueKind.String)
                hint = hintEl.GetString();
            if (root.TryGetProperty("worker", out var workerEl)
                && workerEl.TryGetProperty("upstreamStatus", out var usEl)
                && usEl.TryGetInt32(out var us))
                upstreamStatus = us;
            if (root.TryGetProperty("check", out var checkEl)
                && checkEl.ValueKind == JsonValueKind.Object
                && checkEl.TryGetProperty("clientIp", out var ipEl)
                && ipEl.ValueKind == JsonValueKind.String)
                clientIp = ipEl.GetString();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Hosts the Worker edge cannot usefully probe: loopback, .local, and RFC1918/CGNAT IPs.
    /// </summary>
    public static bool IsHostUnreachableFromCloudflareWorker(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return true;
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || host is "127.0.0.1" or "::1"
            || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase))
            return true;

        // Bracketed IPv6 in URI Host is without brackets in Uri.Host.
        if (IPAddress.TryParse(host, out var ip) && ClientIp.IsPrivateOrLocal(ip))
            return true;

        return false;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
