using Sendit.Api.Configuration;

namespace Sendit.Api.Services;

/// <summary>
/// Per-user storage quota for owned send and collect payload blobs.
/// </summary>
public static class UserStorageQuota
{
    /// <summary>Size of one stored hybrid payload (ciphertext + iv + wrapped key + optional eph pk).</summary>
    public static long PayloadBytes(byte[] ciphertext, byte[] iv, byte[] wrappedKey, byte[]? ephemeralPublicKey)
        => ciphertext.LongLength
           + iv.LongLength
           + wrappedKey.LongLength
           + (ephemeralPublicKey?.LongLength ?? 0);

    public static long CurrentUsageBytes(SecretStore secrets, RequestStore requests, string ownerUserId)
        => secrets.SumStoredPayloadBytes(ownerUserId) + requests.SumStoredPayloadBytes(ownerUserId);

    /// <summary>
    /// Returns null if <paramref name="additionalBytes"/> fits; otherwise an error message for the client.
    /// </summary>
    public static string? CheckWouldExceed(
        SenditOptions options,
        SecretStore secrets,
        RequestStore requests,
        string ownerUserId,
        long additionalBytes)
    {
        if (additionalBytes <= 0)
            return null;

        var quota = options.UserStorageQuotaBytes;
        var used = CurrentUsageBytes(secrets, requests, ownerUserId);
        if (used + additionalBytes <= quota)
            return null;

        var quotaMb = options.UserStorageQuotaMb;
        var usedMb = used / (1024.0 * 1024.0);
        return $"Storage quota exceeded. This account may store up to {quotaMb} MB of encrypted data "
            + $"(currently using about {usedMb:0.##} MB). Delete old sends or collects and try again.";
    }
}
