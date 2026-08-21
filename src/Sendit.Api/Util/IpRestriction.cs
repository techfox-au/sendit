using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Sendit.Api.Util;

/// <summary>
/// Optional allow-list for send links: one or more IPv4/IPv6 addresses or CIDRs
/// (comma-separated). Client and server both validate; only the server enforces on access.
/// </summary>
public static class IpRestriction
{
    public const int MaxInputLength = FieldLimits.AllowedIps;
    /// <summary>Entry cap for a max-length allow-list (short IPv4 forms).</summary>
    public const int MaxEntries = 250_000;

    /// <summary>
    /// Normalize and validate an optional restriction string.
    /// Empty/null → no restriction (canonical = null).
    /// Comma-separated list of single IPs and/or CIDRs.
    /// On success, <paramref name="canonical"/> is a stable form for storage
    /// (comma-joined, no spaces).
    /// </summary>
    public static bool TryNormalize(string? input, out string? canonical, out string? error)
    {
        canonical = null;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
            return true;

        var s = input.Trim();
        if (s.Length > MaxInputLength)
        {
            error = "Allowed IP/CIDR list is too long.";
            return false;
        }

        // Reject zone IDs anywhere (fe80::1%eth0).
        if (s.Contains('%', StringComparison.Ordinal))
        {
            error = "IPv6 zone identifiers are not allowed.";
            return false;
        }

        // Bare "*" (alone or with other entries) = allow any client IP.
        if (string.Equals(s, "*", StringComparison.Ordinal))
        {
            canonical = "*";
            return true;
        }

        var rawParts = s.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (rawParts.Length == 0)
            return true;

        if (rawParts.Any(p => p == "*"))
        {
            canonical = "*";
            return true;
        }

        if (rawParts.Length > MaxEntries)
        {
            error = $"At most {MaxEntries} IP/CIDR entries are allowed.";
            return false;
        }

        var normalized = new List<string>(rawParts.Length);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rawParts.Length; i++)
        {
            var part = rawParts[i];
            if (part.Any(char.IsWhiteSpace))
            {
                error = $"Entry {i + 1}: IP/CIDR must not contain spaces.";
                return false;
            }

            if (!TryNormalizeOne(part, out var one, out error))
            {
                error = $"Entry {i + 1}: {error}";
                return false;
            }

            if (seen.Add(one!))
                normalized.Add(one!);
        }

        if (normalized.Count == 0)
            return true;

        canonical = string.Join(',', normalized);
        return true;
    }

    /// <summary>
    /// True if <paramref name="client"/> matches any entry in the stored list
    /// (null/empty restriction or "*" = allow all).
    /// </summary>
    public static bool IsClientAllowed(string? allowedCidr, IPAddress? client)
    {
        if (string.IsNullOrEmpty(allowedCidr) || allowedCidr == "*")
            return true;
        if (client is null)
            return false;

        client = NormalizeClient(client);

        foreach (var entry in allowedCidr.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParseStored(entry, out var network, out var prefix))
                continue; // skip corrupt entry; others may still match
            if (client.AddressFamily != network.AddressFamily)
                continue;
            if (PrefixEqual(network, client, prefix))
                return true;
        }

        // If the list was non-empty but nothing matched (or all corrupt), deny.
        return false;
    }

    private static bool TryNormalizeOne(string s, out string? canonical, out string? error)
    {
        canonical = null;
        error = null;

        var slash = s.IndexOf('/');
        if (slash < 0)
            return TryNormalizeHost(s, out canonical, out error);

        if (s.Count(c => c == '/') != 1)
        {
            error = "CIDR must contain exactly one '/'.";
            return false;
        }

        var hostPart = s[..slash];
        var prefixPart = s[(slash + 1)..];
        if (hostPart.Length == 0 || prefixPart.Length == 0)
        {
            error = "CIDR must be address/prefix (e.g. 192.168.0.0/24).";
            return false;
        }

        if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
            || prefixPart != prefix.ToString(CultureInfo.InvariantCulture))
        {
            error = "CIDR prefix must be a decimal integer.";
            return false;
        }

        if (!TryParseStrictIp(hostPart, out var network, out error))
            return false;

        var maxPrefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > maxPrefix)
        {
            error = network.AddressFamily == AddressFamily.InterNetwork
                ? "IPv4 CIDR prefix must be between 0 and 32."
                : "IPv6 CIDR prefix must be between 0 and 128.";
            return false;
        }

        // Accept any host within the prefix; store the network address form.
        var masked = ApplyPrefixMask(network, prefix);
        canonical = FormatIp(masked) + "/" + prefix.ToString(CultureInfo.InvariantCulture);
        return true;
    }

    private static bool TryNormalizeHost(string host, out string? canonical, out string? error)
    {
        canonical = null;
        if (!TryParseStrictIp(host, out var ip, out error))
            return false;
        canonical = FormatIp(ip);
        return true;
    }

    /// <summary>Parse IPv4 or IPv6; reject IPv4-mapped IPv6 and non-IP forms.</summary>
    public static bool TryParseStrictIp(string host, out IPAddress ip, out string? error)
    {
        ip = IPAddress.None;
        error = null;

        if (!IPAddress.TryParse(host, out var parsed) || parsed is null)
        {
            error = "Invalid IP address.";
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.IsIPv4MappedToIPv6)
        {
            error = "Use a plain IPv4 address, not an IPv4-mapped IPv6 form.";
            return false;
        }

        if (parsed.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            error = "Only IPv4 and IPv6 addresses are allowed.";
            return false;
        }

        var formatted = FormatIp(parsed);
        if (!IPAddress.TryParse(formatted, out var again) || !parsed.Equals(again))
        {
            error = "Invalid IP address.";
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetwork && !IsCanonicalIPv4Input(host, parsed))
        {
            error = "Invalid IPv4 address (use dotted decimal, e.g. 192.168.1.1).";
            return false;
        }

        ip = parsed;
        return true;
    }

    private static bool IsCanonicalIPv4Input(string host, IPAddress parsed)
    {
        var parts = host.Split('.');
        if (parts.Length != 4)
            return false;
        var bytes = parsed.GetAddressBytes();
        for (var i = 0; i < 4; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                || n < 0 || n > 255
                || parts[i] != n.ToString(CultureInfo.InvariantCulture))
                return false;
            if (n != bytes[i])
                return false;
        }
        return true;
    }

    private static bool TryParseStored(string stored, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var slash = stored.IndexOf('/');
        if (slash < 0)
        {
            if (!IPAddress.TryParse(stored, out network!) || network is null)
                return false;
            prefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return true;
        }

        if (!IPAddress.TryParse(stored[..slash], out network!) || network is null)
            return false;
        if (!int.TryParse(stored[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix))
            return false;
        var max = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return prefix >= 0 && prefix <= max;
    }

    private static IPAddress NormalizeClient(IPAddress client)
    {
        if (client.IsIPv4MappedToIPv6)
            return client.MapToIPv4();
        return client;
    }

    private static string FormatIp(IPAddress ip) => ip.ToString();

    private static IPAddress ApplyPrefixMask(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var totalBits = bytes.Length * 8;
        if (prefixLength >= totalBits)
            return address;

        var fullBytes = prefixLength / 8;
        var remBits = prefixLength % 8;
        for (var i = fullBytes + (remBits > 0 ? 1 : 0); i < bytes.Length; i++)
            bytes[i] = 0;
        if (remBits > 0 && fullBytes < bytes.Length)
            bytes[fullBytes] = (byte)(bytes[fullBytes] & (byte)(0xFF << (8 - remBits)));

        return new IPAddress(bytes);
    }

    private static bool PrefixEqual(IPAddress network, IPAddress client, int prefixLength)
    {
        var a = network.GetAddressBytes();
        var b = client.GetAddressBytes();
        if (a.Length != b.Length)
            return false;
        if (prefixLength == 0)
            return true;

        var fullBytes = prefixLength / 8;
        var remBits = prefixLength % 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (a[i] != b[i])
                return false;
        }
        if (remBits == 0)
            return true;
        var mask = (byte)(0xFF << (8 - remBits));
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }
}
