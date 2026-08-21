namespace Sendit.Api.Util;

/// <summary>
/// URL-safe Base64 (RFC 4648 §5) without padding.
/// Used for opaque IDs and any binary values exposed in paths or JSON strings.
/// </summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var s = Convert.ToBase64String(data);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Decode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    /// <summary>
    /// Returns true if the string uses only base64url characters (A–Z a–z 0–9 - _).
    /// Used to reject malformed path IDs before they hit the database.
    /// </summary>
    public static bool IsBase64Url(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128)
            return false;
        foreach (var c in value)
        {
            if (c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_')
                continue;
            return false;
        }
        return true;
    }
}
