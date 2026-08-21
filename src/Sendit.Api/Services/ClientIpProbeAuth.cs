using System.Security.Cryptography;
using System.Text;

namespace Sendit.Api.Services;

/// <summary>
/// Gates <c>GET /api/v1/diagnostics/client-ip</c> so it is not an anonymous IP oracle.
/// Callers must present the probe secret via <c>X-Sendit-Ip-Probe</c> or
/// <c>Authorization: Bearer</c> (constant-time compare).
/// <para>
/// Default secret is intentional and public (shared with the Cloudflare Worker sample and
/// <see cref="DefaultSecret"/>); override with <c>SENDIT_IP_PROBE_SECRET</c> (≥16 chars)
/// for a private deployment.
/// </para>
/// </summary>
public sealed class ClientIpProbeAuth
{
    public const string HeaderName = "X-Sendit-Ip-Probe";
    public const int MinSecretLength = 16;

    /// <summary>
    /// Built-in default (64 hex chars). Must match Worker <c>DEFAULT_PROBE_SECRET</c>
    /// in <c>deploy/cloudflare-worker-check-ip/src/index.js</c>.
    /// </summary>
    public const string DefaultSecret =
        "70fded0f66a1c64e08f16f253ce41d6adfb13701ca1dcedf62995ef6cea252a3";

    /// <summary>Active probe secret (env override or <see cref="DefaultSecret"/>).</summary>
    public string Token { get; }

    /// <summary>True when using the built-in default (env unset or shorter than <see cref="MinSecretLength"/>).</summary>
    public bool IsUsingDefault { get; }

    public ClientIpProbeAuth()
        : this(Environment.GetEnvironmentVariable("SENDIT_IP_PROBE_SECRET"))
    {
    }

    /// <summary>Explicit secret for tests / DI. Null or short → <see cref="DefaultSecret"/>.</summary>
    public ClientIpProbeAuth(string? secret)
    {
        if (!string.IsNullOrWhiteSpace(secret) && secret.Trim().Length >= MinSecretLength)
        {
            Token = secret.Trim();
            IsUsingDefault = string.Equals(Token, DefaultSecret, StringComparison.Ordinal);
            return;
        }

        Token = DefaultSecret;
        IsUsingDefault = true;
    }

    public bool IsAuthorized(HttpContext http)
    {
        if (http.Request.Headers.TryGetValue(HeaderName, out var presented)
            && !string.IsNullOrEmpty(presented))
        {
            return FixedTimeEqualsUtf8(presented.ToString(), Token);
        }

        var auth = http.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var bearer = auth["Bearer ".Length..].Trim();
            return FixedTimeEqualsUtf8(bearer, Token);
        }

        return false;
    }

    private static bool FixedTimeEqualsUtf8(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        if (ba.Length != bb.Length)
            return false;
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
