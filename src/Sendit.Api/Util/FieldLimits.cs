namespace Sendit.Api.Util;

/// <summary>
/// Shared maximum field lengths for create forms, auth, and related API validation.
/// Plaintext limits are enforced in the browser; ciphertext / wire limits are enforced here.
/// </summary>
public static class FieldLimits
{
    /// <summary>Send/collect name (plaintext, client-side).</summary>
    public const int NamePlain = 256;

    /// <summary>
    /// Owner UDK ciphertext for name (base64url of AES-GCM pack). Comfortable headroom for
    /// <see cref="NamePlain"/> UTF-8 characters.
    /// </summary>
    public const int NameCiphertext = 4_096;

    /// <summary>Account passwords, link passwords, unlock / disable-TOTP passwords.</summary>
    public const int Password = 256;

    /// <summary>Private note plaintext (client-side maxlength).</summary>
    public const int PrivateNotePlain = 5_000_000;

    /// <summary>
    /// Private note UDK ciphertext (base64url). Sized for worst-case UTF-8
    /// (<see cref="PrivateNotePlain"/> × 4) plus AES-GCM overhead and base64url expansion.
    /// </summary>
    public const int PrivateNoteCiphertext = 30_000_000;

    /// <summary>Send Allowed IPs / CIDRs input (canonical form after normalize).</summary>
    public const int AllowedIps = 5_000_000;

    /// <summary>Secret text field (plaintext character count, client-side).</summary>
    public const int SecretTextPlain = 90_000_000;
}
