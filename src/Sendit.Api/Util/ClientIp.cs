using System.Net;
using System.Net.Sockets;

namespace Sendit.Api.Util;

/// <summary>
/// Resolve the client address for allow-lists, rate limits, and audit logs.
/// Uses <see cref="ConnectionInfo.RemoteIpAddress"/> (populated from
/// <c>X-Forwarded-For</c> when <c>UseForwardedHeaders</c> is active with KnownProxies).
/// Without a reverse proxy this is usually loopback, not the machine's LAN/public IP.
/// </summary>
public static class ClientIp
{
    public static IPAddress? Get(HttpContext http)
    {
        var ip = http.Connection.RemoteIpAddress;
        if (ip is null)
            return null;
        if (ip.IsIPv4MappedToIPv6)
            return ip.MapToIPv4();
        return ip;
    }

    /// <summary>
    /// True for loopback, link-local, RFC1918, CGNAT (100.64/10), and IPv6 ULA.
    /// Used by diagnostics and to decide whether the Worker canary “passed” as public.
    /// </summary>
    public static bool IsPrivateOrLocal(IPAddress? ip)
    {
        if (ip is null)
            return true;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip))
            return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10)
                return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                return true;
            if (b[0] == 192 && b[1] == 168)
                return true;
            if (b[0] == 169 && b[1] == 254)
                return true;
            // 100.64.0.0/10 CGNAT / shared (docker/VPN hairpin)
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                return true;
            return false;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            // fe80::/10 link-local
            if ((b[0] == 0xfe) && ((b[1] & 0xc0) == 0x80))
                return true;
            // fc00::/7 unique local
            if ((b[0] & 0xfe) == 0xfc)
                return true;
            return false;
        }
        return true;
    }

    /// <summary>Human-readable client IP for logs, including X-Forwarded-For when present.</summary>
    public static string Format(HttpContext http)
    {
        var ip = Get(http);
        var remote = ip?.ToString() ?? "unknown";
        if (ip is not null && IPAddress.IsLoopback(ip))
            remote += ip.AddressFamily == AddressFamily.InterNetworkV6 ? " (loopback v6)" : " (loopback v4)";

        var xff = http.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
            return remote + " xff=" + xff.Trim();
        return remote;
    }

    /// <summary>
    /// JSON shape for <c>GET /api/v1/diagnostics/client-ip</c> (and the Worker canary).
    /// <c>ok</c> is true only when the resolved client is not private/local.
    /// </summary>
    public static object Describe(HttpContext http)
    {
        var ip = Get(http);
        var privateOrLocal = IsPrivateOrLocal(ip);
        var xff = http.Request.Headers["X-Forwarded-For"].ToString();
        var xri = http.Request.Headers["X-Real-IP"].ToString();
        return new
        {
            ok = !privateOrLocal,
            clientIp = ip?.ToString() ?? "unknown",
            isPrivateOrLocal = privateOrLocal,
            xForwardedFor = string.IsNullOrWhiteSpace(xff) ? null : xff.Trim(),
            xRealIp = string.IsNullOrWhiteSpace(xri) ? null : xri.Trim(),
            formatted = Format(http)
        };
    }
}
