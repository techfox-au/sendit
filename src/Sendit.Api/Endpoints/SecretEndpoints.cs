using System.Text.Json;
using Sendit.Api.Configuration;
using Sendit.Api.Services;
using Sendit.Api.Util;

namespace Sendit.Api.Endpoints;

public static class SecretEndpoints
{
    public static void MapSecretEndpoints(this WebApplication app)
    {
        app.MapPost("/api/v1/send", (
            CreateSecretRequest body,
            AuthService auth,
            SecretStore secrets,
            RequestStore requests,
            SenditOptions options,
            ClientIpCapability ipCap,
            ActivityAuditStore activityAudit,
            HttpContext http) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();

            var err = ValidatePayload(body, options, out var expiresAt, out var ct, out var iv, out var wk, out var epk);
            if (err is not null)
                return Results.BadRequest(new { error = err });

            var addBytes = UserStorageQuota.PayloadBytes(ct!, iv!, wk!, epk);
            var quotaErr = UserStorageQuota.CheckWouldExceed(options, secrets, requests, user.Id, addBytes);
            if (quotaErr is not null)
                return Results.Json(new { error = quotaErr }, statusCode: StatusCodes.Status413PayloadTooLarge);

            if (!IpRestriction.TryNormalize(body.AllowedCidr, out var allowedCidr, out var cidrErr))
                return Results.BadRequest(new { error = cidrErr });

            // Reject new allow-lists when canary disabled IP enforcement (non-public client IP / skip).
            if (!string.IsNullOrEmpty(allowedCidr) && allowedCidr != "*"
                && !ipCap.IpRestrictionsEnabled)
            {
                return Results.BadRequest(new
                {
                    error = "IP restrictions are unavailable on this server (client-IP canary reported " +
                            "a non-public path). Leave Allowed IPs empty, or fix reverse-proxy forwarding."
                });
            }

            var oneTime = body.OneTime ?? true;
            int? maxAccess = null;
            if (!oneTime && body.MaxAccessCount is int mac)
            {
                if (mac is < 1 or > 100_000)
                    return Results.BadRequest(new { error = "maxAccessCount must be between 1 and 100000." });
                maxAccess = mac;
            }

            string? privateNote = null;
            if (!string.IsNullOrWhiteSpace(body.PrivateNoteCiphertext))
            {
                if (body.PrivateNoteCiphertext.Length > FieldLimits.PrivateNoteCiphertext)
                    return Results.BadRequest(new { error = "privateNoteCiphertext is too long." });
                privateNote = body.PrivateNoteCiphertext.Trim();
            }

            string? encryptedLabelWire = null;
            if (body.EncryptedLabel is not null)
            {
                var el = body.EncryptedLabel;
                if (string.IsNullOrWhiteSpace(el.Ciphertext) || string.IsNullOrWhiteSpace(el.Iv)
                    || string.IsNullOrWhiteSpace(el.WrappedKey) || string.IsNullOrWhiteSpace(el.EphemeralPublicKey))
                {
                    return Results.BadRequest(new
                    {
                        error = "encryptedLabel requires ciphertext, iv, wrappedKey, and ephemeralPublicKey."
                    });
                }
                try
                {
                    var elCt = Base64Url.Decode(el.Ciphertext);
                    var elIv = Base64Url.Decode(el.Iv);
                    var elWk = Base64Url.Decode(el.WrappedKey);
                    var elEph = Base64Url.Decode(el.EphemeralPublicKey);
                    if (elIv.Length != 12 || elEph.Length != 32 || elCt.Length == 0)
                        return Results.BadRequest(new { error = "encryptedLabel has invalid field lengths." });
                    if (elCt.LongLength > 4096)
                        return Results.BadRequest(new { error = "encryptedLabel is too large." });
                }
                catch
                {
                    return Results.BadRequest(new { error = "encryptedLabel has invalid base64url encoding." });
                }

                encryptedLabelWire = JsonSerializer.Serialize(new
                {
                    ciphertext = el.Ciphertext.Trim(),
                    iv = el.Iv.Trim(),
                    wrappedKey = el.WrappedKey.Trim(),
                    ephemeralPublicKey = el.EphemeralPublicKey.Trim()
                });
            }

            // Label is owner-only UDK ciphertext (not plaintext). Plain name max is FieldLimits.NamePlain.
            string? ownerLabel = null;
            if (!string.IsNullOrWhiteSpace(body.Label))
            {
                if (body.Label.Length > FieldLimits.NameCiphertext)
                    return Results.BadRequest(new { error = "label (owner ciphertext) is too long." });
                ownerLabel = body.Label.Trim();
            }

            var id = secrets.Create(
                user.Id,
                ownerLabel,
                ct!,
                iv!,
                wk!,
                epk,
                body.ContentType ?? "text/plain",
                body.Filename,
                oneTime,
                expiresAt,
                allowedCidr,
                body.HideTextByDefault == true,
                privateNote,
                maxAccess,
                encryptedLabelWire,
                body.PasswordProtected == true);

            activityAudit.Append(
                ActivityAuditStore.KindSendCreated,
                $"{user.Email} created a send (id {id})",
                user.Id,
                user.Email,
                user.Id,
                "send",
                id,
                ClientIp.Format(http));

            return Results.Ok(new { id });
        });

        // PoW challenge for ID access. Issued for any plausible id (even if missing or
        // malformed) so scrapers cannot learn existence/format from /pow alone.
        app.MapGet("/api/v1/send/{id}/pow", (
            string id,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (!IsPlausibleShareId(id))
                return ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            // Exhausted abuse or issue budget: do not allocate more challenges.
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryFail))
                return TooManyFailedLookups(http, retryFail, audit);
            if (scanGuard.IsChallengeIssueBudgetExceeded(client, out var retryIssue))
                return TooManyFailedLookups(http, retryIssue, audit);

            var ch = pow.Issue("send", id);
            scanGuard.RecordChallengeIssue(client);
            return Results.Ok(new
            {
                challengeId = ch.ChallengeId,
                hmacKey = ch.HmacKey,
                difficultyBits = ch.DifficultyBits,
                expiresAt = ch.ExpiresAt
            });
        });

        // Anti-scan: 404 and PoW failures count toward a per-IP budget → 429.
        // Successful lookups never increment the budget and never clear it.
        // PoW is verified first so scrapers pay work before learning hit vs 404.
        app.MapGet("/api/v1/send/{id}/meta", (
            string id,
            string? powChallengeId,
            string? powNonce,
            string? powHash,
            SecretStore secrets,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            ClientIpCapability ipCap,
            ActivityAuditStore activityAudit,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.SendAccess");
            if (!IsPlausibleShareId(id))
                return ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            // Refuse HMAC work once the IP is already rate-limited.
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return TooManyFailedLookups(http, retryPow, audit);

            var powErr = pow.TryConsume("send", id, powChallengeId, powNonce, powHash);
            if (powErr is not null)
                return PowDenied(scanGuard, http, log, audit, "meta", id, powErr);

            // Format check only after PoW so it is not a free oracle.
            if (!Base64Url.IsBase64Url(id))
                return ShareNotFound(scanGuard, http, audit: audit);

            var rec = secrets.GetMeta(id);
            if (rec is null)
                return ShareNotFound(scanGuard, http, audit: audit);
            if (DateTimeOffset.Parse(rec.ExpiresAt) < DateTimeOffset.UtcNow)
                return ShareNotFound(scanGuard, http, audit: audit);
            if (rec.ConsumedAt is not null || rec.Ciphertext.Length == 0)
                return ShareNotFound(scanGuard, http, "This secret is no longer available.", audit);
            if (!rec.OneTime
                && rec.MaxAccessCount is int maxMeta
                && rec.AccessCount >= maxMeta)
                return ShareNotFound(scanGuard, http, "This secret is no longer available.", audit);

            // Enforce stored allow-list only while ClientIpCapability says restrictions are on.
            var clientIp = ClientIp.Get(http);
            if (ipCap.IpRestrictionsEnabled
                && !IpRestriction.IsClientAllowed(rec.AllowedCidr, clientIp))
            {
                return IpForbidden(
                    log, http, id, rec.AllowedCidr, "meta", activityAudit, rec.OwnerUserId);
            }

            // Public meta never returns plaintext send name — only hybrid-encrypted wire for #sk=.
            object? encryptedLabel = null;
            if (!string.IsNullOrEmpty(rec.EncryptedLabelWire))
            {
                try
                {
                    encryptedLabel = JsonSerializer.Deserialize<JsonElement>(rec.EncryptedLabelWire);
                }
                catch
                {
                    encryptedLabel = null;
                }
            }

            // View of decrypt page (meta + PoW); payload download is logged separately as decrypt.
            var viewerIp = ClientIp.Format(http);
            activityAudit.Append(
                ActivityAuditStore.KindSendViewed,
                $"Send link viewed (id {rec.Id})",
                null,
                null,
                rec.OwnerUserId,
                "send",
                rec.Id,
                viewerIp);

            return Results.Ok(new
            {
                id = rec.Id,
                encryptedLabel,
                oneTime = rec.OneTime,
                expiresAt = rec.ExpiresAt,
                contentType = rec.ContentType,
                filename = rec.Filename,
                hideTextByDefault = rec.HideTextByDefault,
                maxAccessCount = rec.MaxAccessCount,
                accessCount = rec.AccessCount,
                passwordProtected = rec.PasswordProtected,
                hasPayload = rec.Ciphertext.Length > 0 && rec.ConsumedAt is null
            });
        });

        app.MapGet("/api/v1/send/{id}", (
            string id,
            string? powChallengeId,
            string? powNonce,
            string? powHash,
            SecretStore secrets,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            ClientIpCapability ipCap,
            NotificationEmailService notify,
            ActivityAuditStore activityAudit,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.SendAccess");
            if (!IsPlausibleShareId(id))
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return TooManyFailedLookups(http, retryPow, audit);

            // PoW before any burn — invalid PoW never consumes the secret.
            var powErr = pow.TryConsume("send", id, powChallengeId, powNonce, powHash);
            if (powErr is not null)
                return PowDenied(scanGuard, http, log, audit, "payload", id, powErr);

            if (!Base64Url.IsBase64Url(id))
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);

            // Check IP before burn so a wrong network cannot consume a one-time send.
            var peek = secrets.GetMeta(id);
            if (peek is null)
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);
            if (DateTimeOffset.Parse(peek.ExpiresAt) < DateTimeOffset.UtcNow)
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);
            if (peek.ConsumedAt is not null || peek.Ciphertext.Length == 0)
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);
            if (!peek.OneTime
                && peek.MaxAccessCount is int maxPeek
                && peek.AccessCount >= maxPeek)
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);

            // IP check before burn so a wrong network cannot consume a one-time send (when enabled).
            var clientIp = ClientIp.Get(http);
            if (ipCap.IpRestrictionsEnabled
                && !IpRestriction.IsClientAllowed(peek.AllowedCidr, clientIp))
            {
                return IpForbidden(
                    log, http, id, peek.AllowedCidr, "payload", activityAudit, peek.OwnerUserId);
            }

            var rec = secrets.RetrieveAndMaybeBurn(id);
            if (rec is null)
                return ShareNotFound(scanGuard, http, "Secret not found or already consumed.", audit);

            // Owner may have NotifySendOpened — fire-and-forget via same email transport as OTP.
            notify.TryNotifySendOpened(rec.OwnerUserId, rec.Id);

            activityAudit.Append(
                ActivityAuditStore.KindSendDecrypted,
                $"Send payload downloaded for decryption (id {rec.Id})",
                null,
                null,
                rec.OwnerUserId,
                "send",
                rec.Id,
                ClientIp.Format(http));

            // Never return owner Label (UDK ciphertext) on public payload.
            return Results.Ok(new
            {
                id = rec.Id,
                v = 1,
                ciphertext = Base64Url.Encode(rec.Ciphertext),
                iv = Base64Url.Encode(rec.Iv),
                wrappedKey = Base64Url.Encode(rec.WrappedKey),
                ephemeralPublicKey = rec.EphemeralPublicKey is null
                    ? null
                    : Base64Url.Encode(rec.EphemeralPublicKey),
                contentType = rec.ContentType,
                filename = rec.Filename,
                oneTime = rec.OneTime,
                expiresAt = rec.ExpiresAt,
                hideTextByDefault = rec.HideTextByDefault
            });
        });
        app.MapDelete("/api/v1/send/{id}", (
            string id,
            AuthService auth,
            SecretStore secrets,
            ActivityAuditStore activityAudit,
            HttpContext http) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (!Base64Url.IsBase64Url(id))
                return Results.NotFound();
            if (!secrets.DeleteOwned(id, user.Id))
                return Results.NotFound();
            activityAudit.Append(
                ActivityAuditStore.KindSendDeleted,
                $"{user.Email} deleted a send (id {id})",
                user.Id,
                user.Email,
                user.Id,
                "send",
                id,
                ClientIp.Format(http));
            return Results.Ok(new { ok = true });
        });
    }

    internal static IResult IpForbidden(
        ILogger log,
        HttpContext http,
        string id,
        string? allowedCidr,
        string stage,
        ActivityAuditStore? activityAudit = null,
        string? ownerUserId = null)
    {
        var ip = ClientIp.Format(http);
        log.LogWarning(
            "SEND_IP_DENY stage={Stage} id={Id} clientIp={ClientIp} allowed={Allowed}",
            stage,
            id,
            ip,
            string.IsNullOrEmpty(allowedCidr) ? "(none)" : allowedCidr);
        activityAudit?.Append(
            ActivityAuditStore.KindSendIpDenied,
            $"Send access denied: IP not allowed (id {id})",
            actorUserId: null,
            actorEmail: null,
            ownerUserId: ownerUserId,
            resourceKind: "send",
            resourceId: id,
            clientIp: ip);
        return Results.Json(
            new { error = "This send is not available from your IP address." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    /// <summary>
    /// Loose id gate for /pow and pre-PoW routing only (length). Does not require base64url
    /// so scrapers cannot skip PoW with a "malformed" id.
    /// </summary>
    internal static bool IsPlausibleShareId(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length is >= 1 and <= 128;

    /// <summary>
    /// Not-found path for share/collect lookups: failures count toward the per-IP budget.
    /// When the budget is exhausted, return 429 instead of 404.
    /// Always returns a JSON body so HTTP/2 clients (empty statusText) show a real message.
    /// </summary>
    internal static IResult ShareNotFound(
        ShareScanGuard scanGuard,
        HttpContext http,
        string? error = null,
        SecurityAudit? audit = null)
    {
        var client = ShareScanGuard.ClientKey(http);
        if (scanGuard.IsFailureBudgetExceeded(client, out var retryAfter))
            return TooManyFailedLookups(http, retryAfter, audit);

        scanGuard.RecordFailure(client);
        return Results.NotFound(new
        {
            error = string.IsNullOrWhiteSpace(error)
                ? "Secret not found or already consumed."
                : error
        });
    }

    /// <summary>
    /// Invalid/missing PoW: counts toward the same per-IP abuse budget as 404s.
    /// Returns 403 for the failure, or 429 once the budget is exhausted.
    /// </summary>
    internal static IResult PowDenied(
        ShareScanGuard scanGuard,
        HttpContext http,
        ILogger log,
        SecurityAudit? audit,
        string stage,
        string id,
        string reason)
    {
        var client = ShareScanGuard.ClientKey(http);
        log.LogWarning(
            "POW_DENY stage={Stage} id={Id} clientIp={ClientIp} reason={Reason}",
            stage,
            id,
            ClientIp.Format(http),
            reason);

        if (scanGuard.IsFailureBudgetExceeded(client, out var retryAfter))
            return TooManyFailedLookups(http, retryAfter, audit);

        scanGuard.RecordFailure(client);

        // After this failure the budget may now be full — still return 403 for this
        // response; the next probe gets 429 without further HMAC work.
        return Results.Json(new { error = reason }, statusCode: StatusCodes.Status403Forbidden);
    }

    internal static IResult TooManyFailedLookups(
        HttpContext http,
        double retryAfterSeconds,
        SecurityAudit? audit = null)
    {
        var seconds = Math.Max(1, (int)Math.Ceiling(retryAfterSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString();
        audit?.RateLimited(
            "lookup_scan",
            ShareScanGuard.ClientKey(http),
            http.Request.Path,
            seconds);
        return Results.Json(
            new
            {
                error = "Too many failed attempts. Wait before trying again.",
                retryAfterSeconds = seconds
            },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    internal static string? ValidatePayload(
        CreateSecretRequest body,
        SenditOptions options,
        out DateTimeOffset expiresAt,
        out byte[]? ciphertext,
        out byte[]? iv,
        out byte[]? wrappedKey,
        out byte[]? ephemeralPublicKey,
        long? maxCiphertextBytes = null)
    {
        expiresAt = default;
        ciphertext = iv = wrappedKey = ephemeralPublicKey = null;

        if (string.IsNullOrEmpty(body.Ciphertext) || string.IsNullOrEmpty(body.Iv) ||
            string.IsNullOrEmpty(body.WrappedKey))
            return "ciphertext, iv, and wrappedKey are required.";

        try
        {
            ciphertext = Base64Url.Decode(body.Ciphertext);
            iv = Base64Url.Decode(body.Iv);
            wrappedKey = Base64Url.Decode(body.WrappedKey);
            if (!string.IsNullOrEmpty(body.EphemeralPublicKey))
                ephemeralPublicKey = Base64Url.Decode(body.EphemeralPublicKey);
        }
        catch
        {
            return "Invalid base64url encoding.";
        }

        if (iv.Length != 12)
            return "iv must be 12 bytes.";
        if (ciphertext.Length == 0)
            return "ciphertext is empty.";
        // Default MaxUploadBytes (create-send + collect upload); callers may pass a tighter cap.
        var maxCt = maxCiphertextBytes ?? options.MaxUploadBytes;
        if (ciphertext.LongLength > maxCt)
            return "Payload exceeds maximum size.";
        if (ephemeralPublicKey is { Length: not 32 })
            return "ephemeralPublicKey must be 32 bytes when provided.";

        var minutes = ResolveExpiryMinutes(body.ExpiryMinutes, body.ExpiryHours, options, out var expiryError);
        if (expiryError is not null)
            return expiryError;

        expiresAt = DateTimeOffset.UtcNow.AddMinutes(minutes);
        return null;
    }

    /// <summary>
    /// Prefer expiryMinutes; fall back to expiryHours * 60 for older clients.
    /// Default: 24 hours.
    /// </summary>
    internal static int ResolveExpiryMinutes(
        int? expiryMinutes,
        int? expiryHours,
        SenditOptions options,
        out string? error)
    {
        error = null;
        var maxMinutes = options.MaxExpiryHours * 60;
        var minMinutes = Math.Max(1, options.MinExpiryMinutes);

        int minutes;
        if (expiryMinutes is > 0)
            minutes = expiryMinutes.Value;
        else if (expiryHours is > 0)
            minutes = expiryHours.Value * 60;
        else
            minutes = 24 * 60;

        if (minutes < minMinutes || minutes > maxMinutes)
        {
            error = $"Expiry must be between {minMinutes} minutes and {options.MaxExpiryHours} hours.";
            return 0;
        }

        return minutes;
    }

    public record CreateSecretRequest(
        string? Ciphertext,
        string? Iv,
        string? WrappedKey,
        string? EphemeralPublicKey,
        string? ContentType,
        string? Filename,
        string? Label,
        bool? OneTime,
        int? ExpiryHours,
        int? ExpiryMinutes,
        /// <summary>Optional single IPv4/IPv6 or CIDR list. Null/empty = any IP.</summary>
        string? AllowedCidr,
        bool? HideTextByDefault,
        /// <summary>Owner-only UDK-encrypted note (opaque base64url).</summary>
        string? PrivateNoteCiphertext,
        /// <summary>Multi-view only: max payload opens (1–100000).</summary>
        int? MaxAccessCount,
        /// <summary>Send name encrypted to the same X25519 key as the payload (hybrid wire).</summary>
        EncryptedLabelWire? EncryptedLabel,
        /// <summary>
        /// Client flag: fragment #sk is a PBKDF2-SHA512 + AES-256-GCM package of the X25519 sk
        /// (compact JSON {i,s,iv,ct}). Server stores the boolean only; password/package never uploaded.
        /// </summary>
        bool? PasswordProtected);

    public record EncryptedLabelWire(
        string? Ciphertext,
        string? Iv,
        string? WrappedKey,
        string? EphemeralPublicKey);
}
