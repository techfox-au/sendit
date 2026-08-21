using System.Security.Cryptography;

namespace Sendit.Api.Util;

/// <summary>
/// Generates opaque 128-bit identifiers encoded as base64url (~22 characters).
/// </summary>
public static class IdGenerator
{
    public static string NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Base64Url.Encode(bytes);
    }
}
