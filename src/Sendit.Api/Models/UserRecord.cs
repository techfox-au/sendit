namespace Sendit.Api.Models;

public sealed class UserRecord
{
    public required string Id { get; init; }
    public required string Email { get; init; }
    public required byte[] PasswordSalt { get; init; }
    public required byte[] PasswordHash { get; init; }
    public int PasswordHashIterations { get; init; }
    public bool EmailConfirmed { get; init; }
    public required string CreatedAt { get; init; }
    public string? TotpSecret { get; init; }
    public bool TotpEnabled { get; init; }
    public string? TotpPendingSecret { get; init; }
    public required string SecurityStamp { get; init; }
    /// <summary>
    /// Client-produced package: user data key wrapped with the account password (JSON/base64).
    /// Server never unwraps this; only the browser with the password can.
    /// </summary>
    public string? WrappedUserDataKey { get; init; }
    public string? EmailOtpHash { get; init; }
    public string? EmailOtpExpiresAt { get; init; }
    /// <summary>Wrong OTP attempts for the current code (wiped after MaxEmailOtpFails failures).</summary>
    public int EmailOtpFailCount { get; init; }
    /// <summary>Email when someone uploads to the owner's collect link (default off).</summary>
    public bool NotifyCollectReady { get; init; }
    /// <summary>Email when a recipient downloads a send payload for decryption (default off).</summary>
    public bool NotifySendOpened { get; init; }
}

public sealed record SecretRecord
{
    public required string Id { get; init; }
    public required string OwnerUserId { get; init; }
    /// <summary>Owner-only: UDK-encrypted send name (base64url), or legacy plaintext.</summary>
    public string? Label { get; init; }
    public required byte[] Ciphertext { get; init; }
    public required byte[] Iv { get; init; }
    public required byte[] WrappedKey { get; init; }
    public byte[]? EphemeralPublicKey { get; init; }
    public required string ContentType { get; init; }
    public string? Filename { get; init; }
    public bool OneTime { get; init; }
    /// <summary>Optional single IP or CIDR list; null = any client IP.</summary>
    public string? AllowedCidr { get; init; }
    /// <summary>When true, recipient UI masks secret text until revealed.</summary>
    public bool HideTextByDefault { get; init; }
    /// <summary>Owner-only UDK-encrypted private note (base64url); never on public APIs.</summary>
    public string? PrivateNoteCiphertext { get; init; }
    /// <summary>Multi-view only: max successful payload opens; null = unlimited.</summary>
    public int? MaxAccessCount { get; init; }
    /// <summary>Successful payload opens so far.</summary>
    public int AccessCount { get; init; }
    /// <summary>
    /// Hybrid-encrypted send name for public meta (JSON wire fields). Requires #sk= to decrypt.
    /// Plaintext <see cref="Label"/> remains for owner dashboard only.
    /// </summary>
    public string? EncryptedLabelWire { get; init; }
    /// <summary>
    /// Send only: fragment #sk is client password-wrapped (PBKDF2-SHA512 + AES-256-GCM).
    /// Public meta exposes this flag; server never holds the password or wrap package.
    /// </summary>
    public bool PasswordProtected { get; init; }
    public required string CreatedAt { get; init; }
    public required string ExpiresAt { get; init; }
    public string? ConsumedAt { get; init; }
}

public sealed record RequestRecord
{
    public required string Id { get; init; }
    public required string OwnerUserId { get; init; }
    public string? Label { get; init; }
    public required byte[] PublicKey { get; init; }
    /// <summary>At-rest protected owner X25519 private key (for dashboard re-open). Never exposed publicly.</summary>
    public byte[]? OwnerPrivateKeyProtected { get; init; }
    public bool OneTime { get; init; }
    public required string CreatedAt { get; init; }
    public required string ExpiresAt { get; init; }
    public bool Uploaded { get; init; }
    public byte[]? Ciphertext { get; init; }
    public byte[]? Iv { get; init; }
    public byte[]? WrappedKey { get; init; }
    public byte[]? EphemeralPublicKey { get; init; }
    public string? ContentType { get; init; }
    public string? Filename { get; init; }
    public string? ConsumedAt { get; init; }
    /// <summary>Multi-view only: max successful payload collects; null = unlimited until expiry.</summary>
    public int? MaxAccessCount { get; init; }
    /// <summary>Successful payload collects so far.</summary>
    public int AccessCount { get; init; }
    /// <summary>
    /// Collect name encrypted bound to the collect public key (JSON wire). Public APIs return this, not plaintext Label.
    /// </summary>
    public string? EncryptedLabelWire { get; init; }
    /// <summary>Owner-only UDK-encrypted private note (base64url); never on public APIs.</summary>
    public string? PrivateNoteCiphertext { get; init; }
    /// <summary>When true, collect reveal masks text until the eye control is used.</summary>
    public bool HideTextByDefault { get; init; }
    /// <summary>
    /// Collect link #sk is client password-wrapped (PBKDF2-SHA512 + AES-256-GCM).
    /// Public meta exposes this flag; server never holds the password or wrap package.
    /// </summary>
    public bool PasswordProtected { get; init; }
}

public sealed class DashboardItem
{
    public required string Id { get; init; }
    public required string Kind { get; init; } // "send" | "collect"
    public string? Label { get; init; }
    public bool OneTime { get; init; }
    public required string CreatedAt { get; init; }
    public required string ExpiresAt { get; init; }
    public required string Status { get; init; }
    public string? ContentType { get; init; }
    public string? Filename { get; init; }
    /// <summary>
    /// Owner-only: UDK ciphertext of collect re-open material (raw sk, or password-wrap package
    /// UTF-8 when PasswordProtected). Client decrypts with UDK then builds #sk=.
    /// </summary>
    public string? CollectSecretKey { get; init; }
    /// <summary>Owner-only UDK-encrypted private note (sends).</summary>
    public string? PrivateNoteCiphertext { get; init; }
    public int? MaxAccessCount { get; init; }
    public int AccessCount { get; init; }
    /// <summary>Send/collect: link password required to unwrap fragment #sk (client-side).</summary>
    public bool PasswordProtected { get; init; }
    /// <summary>
    /// True when access is IP-restricted: send has a non-empty AllowedCidr (not *),
    /// or collect retrieval is gated by <c>SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS</c>.
    /// </summary>
    public bool IpRestricted { get; init; }
}
