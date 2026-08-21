using System.Text.Json;
using Sendit.Api.Configuration;
using Sendit.Api.Models;
using Sendit.Api.Services;
using Sendit.Api.Util;

namespace Sendit.Api.Endpoints;

public static class RequestEndpoints
{
    public static void MapRequestEndpoints(this WebApplication app)
    {
        app.MapPost("/api/v1/collect", (
            CreateRequestBody body,
            AuthService auth,
            RequestStore requests,
            SenditOptions options,
            ActivityAuditStore activityAudit,
            HttpContext http) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();

            if (string.IsNullOrEmpty(body.PublicKey))
                return Results.BadRequest(new { error = "publicKey is required." });

            byte[] pk;
            try { pk = Base64Url.Decode(body.PublicKey); }
            catch { return Results.BadRequest(new { error = "Invalid publicKey encoding." }); }

            if (pk.Length != 32)
                return Results.BadRequest(new { error = "publicKey must be 32 bytes (X25519)." });

            // Owner private key is already encrypted client-side with the user data key (opaque blob).
            // Server may apply SENDIT_DATA_KEY as a second at-rest layer. Never returned on public GET.
            byte[]? ownerSkCipher = null;
            if (!string.IsNullOrEmpty(body.PrivateKeyCiphertext))
            {
                try { ownerSkCipher = Base64Url.Decode(body.PrivateKeyCiphertext); }
                catch { return Results.BadRequest(new { error = "Invalid privateKeyCiphertext encoding." }); }
                if (ownerSkCipher.Length is < 28 or > 4096)
                    return Results.BadRequest(new { error = "privateKeyCiphertext has invalid length." });
            }

            var minutes = SecretEndpoints.ResolveExpiryMinutes(
                body.ExpiryMinutes, body.ExpiryHours, options, out var expiryError);
            if (expiryError is not null)
                return Results.BadRequest(new { error = expiryError });

            var oneTime = body.OneTime ?? true;
            int? maxAccess = null;
            if (!oneTime && body.MaxAccessCount is int mac)
            {
                if (mac is < 1 or > 100_000)
                    return Results.BadRequest(new { error = "maxAccessCount must be between 1 and 100000." });
                maxAccess = mac;
            }

            // Owner-only UDK ciphertext for dashboard collect name (never plaintext on public GET).
            string? ownerLabel = null;
            if (!string.IsNullOrWhiteSpace(body.Label))
            {
                if (body.Label.Length > FieldLimits.NameCiphertext)
                    return Results.BadRequest(new { error = "label (owner ciphertext) is too long." });
                ownerLabel = body.Label.Trim();
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
                if (string.IsNullOrWhiteSpace(el.Ciphertext) || string.IsNullOrWhiteSpace(el.Iv))
                {
                    return Results.BadRequest(new
                    {
                        error = "encryptedLabel requires ciphertext and iv."
                    });
                }
                try
                {
                    var elCt = Base64Url.Decode(el.Ciphertext);
                    var elIv = Base64Url.Decode(el.Iv);
                    if (elIv.Length != 12 || elCt.Length == 0)
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
                    v = el.V ?? 1,
                    bound = string.IsNullOrWhiteSpace(el.Bound) ? "collect-pk" : el.Bound.Trim(),
                    ciphertext = el.Ciphertext.Trim(),
                    iv = el.Iv.Trim()
                });
            }

            var id = requests.Create(
                user.Id,
                ownerLabel,
                pk,
                ownerSkCipher,
                oneTime,
                DateTimeOffset.UtcNow.AddMinutes(minutes),
                maxAccess,
                encryptedLabelWire,
                privateNote,
                body.HideTextByDefault == true,
                body.PasswordProtected == true);

            activityAudit.Append(
                ActivityAuditStore.KindCollectCreated,
                $"{user.Email} created a collection (id {id})",
                user.Id,
                user.Email,
                user.Id,
                "collect",
                id,
                ClientIp.Format(http));

            return Results.Ok(new { id });
        });

        // Public collect lookups: only not-found outcomes count toward scan budget.
        // PoW first so scrapers pay work before learning hit vs 404 / public key.
        app.MapGet("/api/v1/collect/{id}", (
            string id,
            string? powChallengeId,
            string? powNonce,
            string? powHash,
            RequestStore requests,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.CollectAccess");
            if (!SecretEndpoints.IsPlausibleShareId(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return SecretEndpoints.TooManyFailedLookups(http, retryPow, audit);

            var powErr = pow.TryConsume("collect", id, powChallengeId, powNonce, powHash);
            if (powErr is not null)
                return SecretEndpoints.PowDenied(scanGuard, http, log, audit, "collect-get", id, powErr);

            if (!Base64Url.IsBase64Url(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var rec = requests.Get(id);
            if (rec is null)
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);
            if (DateTimeOffset.Parse(rec.ExpiresAt) < DateTimeOffset.UtcNow)
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            // Public: encrypted collect name only (never owner UDK Label — that looks like gibberish).
            // Legacy short plaintext Label only when there is no encrypted wire.
            return Results.Ok(new
            {
                id = rec.Id,
                publicKey = Base64Url.Encode(rec.PublicKey),
                oneTime = rec.OneTime,
                expiresAt = rec.ExpiresAt,
                uploaded = rec.Uploaded,
                consumed = rec.ConsumedAt is not null,
                encryptedLabel = ParseEncryptedCollectLabel(rec.EncryptedLabelWire)
            });
        });
        app.MapPost("/api/v1/collect/{id}/upload", (
            string id,
            UploadBody body,
            RequestStore requests,
            SecretStore secrets,
            SenditOptions options,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            NotificationEmailService notify,
            ActivityAuditStore activityAudit,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.CollectAccess");
            if (!SecretEndpoints.IsPlausibleShareId(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return SecretEndpoints.TooManyFailedLookups(http, retryPow, audit);

            // PoW required at upload time (client issues challenge when submit is pressed).
            var powErr = pow.TryConsume("collect", id, body.PowChallengeId, body.PowNonce, body.PowHash);
            if (powErr is not null)
                return SecretEndpoints.PowDenied(scanGuard, http, log, audit, "upload", id, powErr);

            if (!Base64Url.IsBase64Url(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            // Expiry is fixed on the collect row; dummy only validates ciphertext fields.
            var dummy = new SecretEndpoints.CreateSecretRequest(
                body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey,
                body.ContentType, body.Filename, null, null, null, null, null, null, null, null, null, null);

            // Same large ciphertext cap as create-send (body limit raised in Program middleware).
            var err = SecretEndpoints.ValidatePayload(
                dummy, options, out _, out var ct, out var iv, out var wk, out var epk);
            if (err is not null)
                return Results.BadRequest(new { error = err });

            // Collect payload counts against the collect owner's storage quota.
            var existingForQuota = requests.Get(id);
            if (existingForQuota is not null)
            {
                var addBytes = UserStorageQuota.PayloadBytes(ct!, iv!, wk!, epk);
                var quotaErr = UserStorageQuota.CheckWouldExceed(
                    options, secrets, requests, existingForQuota.OwnerUserId, addBytes);
                if (quotaErr is not null)
                    return Results.Json(new { error = quotaErr }, statusCode: StatusCodes.Status413PayloadTooLarge);
            }

            if (!requests.TryUpload(id, ct!, iv!, wk!, epk, body.ContentType ?? "text/plain", body.Filename))
            {
                // Only missing/expired IDs count as scan failures; "already filled" is not scanning.
                var existing = requests.Get(id);
                if (existing is null
                    || DateTimeOffset.Parse(existing.ExpiresAt) < DateTimeOffset.UtcNow)
                {
                    return SecretEndpoints.ShareNotFound(
                        scanGuard, http, "Upload failed: request missing or expired.", audit);
                }
                return Results.Conflict(new
                {
                    error = "Upload failed: request missing, expired, or already filled."
                });
            }

            // Owner may have NotifyCollectReady — same SMTP/Mailgun timeouts as OTP (fire-and-forget).
            var ownerId = existingForQuota?.OwnerUserId ?? requests.Get(id)?.OwnerUserId;
            if (!string.IsNullOrEmpty(ownerId))
            {
                notify.TryNotifyCollectReady(ownerId, id);
                activityAudit.Append(
                    ActivityAuditStore.KindCollectUploaded,
                    $"Collect received an upload (id {id})",
                    null,
                    null,
                    ownerId,
                    "collect",
                    id,
                    ClientIp.Format(http));
            }

            return Results.Ok(new { ok = true });
        });

        // PoW for ID access. Issued for any plausible id (even if missing or malformed).
        app.MapGet("/api/v1/collect/{id}/pow", (
            string id,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            HttpContext http) =>
        {
            if (!SecretEndpoints.IsPlausibleShareId(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryFail))
                return SecretEndpoints.TooManyFailedLookups(http, retryFail, audit);
            if (scanGuard.IsChallengeIssueBudgetExceeded(client, out var retryIssue))
                return SecretEndpoints.TooManyFailedLookups(http, retryIssue, audit);

            var ch = pow.Issue("collect", id);
            scanGuard.RecordChallengeIssue(client);
            return Results.Ok(new
            {
                challengeId = ch.ChallengeId,
                hmacKey = ch.HmacKey,
                difficultyBits = ch.DifficultyBits,
                expiresAt = ch.ExpiresAt
            });
        });

        // Owner collect of submitted payload. Restricted by SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS
        // (blank/* = any). Checked before burn so a wrong network cannot consume one-time collects.
        app.MapGet("/api/v1/collect/{id}/payload", (
            string id,
            string? powChallengeId,
            string? powNonce,
            string? powHash,
            RequestStore requests,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            SenditOptions options,
            ClientIpCapability ipCap,
            ProofOfWorkService pow,
            ActivityAuditStore activityAudit,
            AuthService auth,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.CollectAccess");
            if (!SecretEndpoints.IsPlausibleShareId(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, "Payload not available.", audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return SecretEndpoints.TooManyFailedLookups(http, retryPow, audit);

            // PoW before burn — invalid PoW never consumes the payload.
            var powErr = pow.TryConsume("collect", id, powChallengeId, powNonce, powHash);
            if (powErr is not null)
                return SecretEndpoints.PowDenied(scanGuard, http, log, audit, "payload", id, powErr);

            if (!Base64Url.IsBase64Url(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, "Payload not available.", audit);

            // SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS — only when IP canary left restrictions enabled.
            var clientIp = ClientIp.Get(http);
            if (ipCap.IpRestrictionsEnabled
                && !IpRestriction.IsClientAllowed(options.CollectionRetrieveAllowedIps, clientIp))
            {
                var ip = ClientIp.Format(http);
                log.LogWarning(
                    "COLLECT_RETRIEVE_IP_DENY id={Id} clientIp={ClientIp} allowed={Allowed}",
                    id,
                    ip,
                    string.IsNullOrEmpty(options.CollectionRetrieveAllowedIps)
                        ? "(none)"
                        : options.CollectionRetrieveAllowedIps);
                // Owner for audit only (no burn); may be null if id is unknown after PoW.
                var ownerId = requests.Get(id)?.OwnerUserId;
                activityAudit.Append(
                    ActivityAuditStore.KindCollectIpDenied,
                    $"Collect access denied: IP not allowed (id {id})",
                    actorUserId: null,
                    actorEmail: null,
                    ownerUserId: ownerId,
                    resourceKind: "collect",
                    resourceId: id,
                    clientIp: ip);
                return Results.Json(
                    new { error = "Collecting this submission is not available from your IP address." },
                    statusCode: StatusCodes.Status403Forbidden);
            }

            var rec = requests.RetrievePayloadAndMaybeBurn(id);
            if (rec is null || rec.Ciphertext is null || rec.Iv is null || rec.WrappedKey is null)
                return SecretEndpoints.ShareNotFound(scanGuard, http, "Payload not available.", audit);

            var retriever = AuthEndpoints.CurrentUser(auth, http);
            activityAudit.Append(
                ActivityAuditStore.KindCollectRetrieved,
                retriever is not null
                    ? $"{retriever.Email} retrieved a collect (id {rec.Id})"
                    : $"Collect retrieved (id {rec.Id})",
                retriever?.Id,
                retriever?.Email,
                rec.OwnerUserId,
                "collect",
                rec.Id,
                ClientIp.Format(http));

            // Do not return Label — it is owner UDK ciphertext and would display as gibberish.
            // Collect name comes from meta encryptedLabel (client-side decrypt).
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

        app.MapGet("/api/v1/collect/{id}/meta", (
            string id,
            string? powChallengeId,
            string? powNonce,
            string? powHash,
            RequestStore requests,
            ShareScanGuard scanGuard,
            SecurityAudit audit,
            ProofOfWorkService pow,
            ILoggerFactory logFactory,
            HttpContext http) =>
        {
            var log = logFactory.CreateLogger("Sendit.CollectAccess");
            if (!SecretEndpoints.IsPlausibleShareId(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var client = ShareScanGuard.ClientKey(http);
            if (scanGuard.IsFailureBudgetExceeded(client, out var retryPow))
                return SecretEndpoints.TooManyFailedLookups(http, retryPow, audit);

            var powErr = pow.TryConsume("collect", id, powChallengeId, powNonce, powHash);
            if (powErr is not null)
                return SecretEndpoints.PowDenied(scanGuard, http, log, audit, "collect-meta", id, powErr);

            if (!Base64Url.IsBase64Url(id))
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            var rec = requests.Get(id);
            if (rec is null)
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);
            if (DateTimeOffset.Parse(rec.ExpiresAt) < DateTimeOffset.UtcNow)
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);
            if (!rec.OneTime
                && rec.MaxAccessCount is int maxMeta
                && rec.AccessCount >= maxMeta)
                return SecretEndpoints.ShareNotFound(scanGuard, http, audit: audit);

            return Results.Ok(new
            {
                id = rec.Id,
                encryptedLabel = ParseEncryptedCollectLabel(rec.EncryptedLabelWire),
                oneTime = rec.OneTime,
                expiresAt = rec.ExpiresAt,
                uploaded = rec.Uploaded,
                hasPayload = rec.Uploaded
                    && rec.ConsumedAt is null
                    && rec.Ciphertext is { Length: > 0 },
                contentType = rec.ContentType,
                filename = rec.Filename,
                maxAccessCount = rec.MaxAccessCount,
                accessCount = rec.AccessCount,
                hideTextByDefault = rec.HideTextByDefault,
                passwordProtected = rec.PasswordProtected
            });
        });

        app.MapDelete("/api/v1/collect/{id}", (
            string id,
            AuthService auth,
            RequestStore requests,
            ActivityAuditStore activityAudit,
            HttpContext http) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();
            if (!Base64Url.IsBase64Url(id))
                return Results.NotFound();
            if (!requests.DeleteOwned(id, user.Id))
                return Results.NotFound();
            activityAudit.Append(
                ActivityAuditStore.KindCollectDeleted,
                $"{user.Email} deleted a collection (id {id})",
                user.Id,
                user.Email,
                user.Id,
                "collect",
                id,
                ClientIp.Format(http));
            return Results.Ok(new { ok = true });
        });

        /// <summary>
        /// Immutable site-wide activity audit (all accounts). Auth required.
        /// Page size default 500. Pass beforeAtUtc + beforeId (last row of previous page)
        /// to load the next older page for infinite scroll.
        /// </summary>
        app.MapGet("/api/v1/me/audit", (
            AuthService auth,
            ActivityAuditStore activityAudit,
            HttpContext http,
            int? limit = null,
            string? beforeAtUtc = null,
            string? beforeId = null) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();

            var pageSize = limit ?? ActivityAuditStore.DefaultPageSize;
            if (pageSize is < 1 or > ActivityAuditStore.MaxPageSize)
                pageSize = ActivityAuditStore.DefaultPageSize;

            var items = activityAudit.ListPage(pageSize, beforeAtUtc, beforeId);
            // Full page ⇒ older rows may exist (client asks again with last row as cursor).
            var hasMore = items.Count >= pageSize;

            return Results.Ok(new
            {
                items = items.Select(e => new
                {
                    id = e.Id,
                    atUtc = e.AtUtc,
                    kind = e.Kind,
                    message = e.Message,
                    actorEmail = e.ActorEmail,
                    resourceKind = e.ResourceKind,
                    resourceId = e.ResourceId,
                    clientIp = e.ClientIp
                }),
                hasMore,
                pageSize
            });
        });

        /// <summary>
        /// Owner dashboard list (sends + collects). Default page size 100.
        /// Pass <c>beforeCreatedAt</c> + <c>beforeId</c> (last row of previous page) for older items.
        /// Without a cursor, returns the newest <c>limit</c> rows (used for poll refresh of the loaded window).
        /// </summary>
        app.MapGet("/api/v1/me/items", (
            AuthService auth,
            SecretStore secrets,
            RequestStore requests,
            SenditOptions options,
            HttpContext http,
            int? limit = null,
            string? beforeCreatedAt = null,
            string? beforeId = null) =>
        {
            var user = AuthEndpoints.CurrentUser(auth, http);
            if (user is null)
                return Results.Unauthorized();

            // Eager purge so expired / one-time-collected rows leave the DB as soon as the
            // owner opens the dashboard (background job also purges every minute).
            secrets.PurgeExpired();
            requests.PurgeExpired();

            // Collect retrieve allow-list is server-wide (env); show IP chip on every collect.
            var collectIpRestricted = ClientIpCapability.IsRestrictiveCollectIpList(
                options.CollectionRetrieveAllowedIps);

            const int defaultPage = 100;
            // Cursor pages (infinite scroll) stay modest; top-N without cursor can be larger for poll refresh.
            const int maxCursorPage = 100;
            const int maxTopN = 2000;
            var useCursor = !string.IsNullOrWhiteSpace(beforeCreatedAt)
                && !string.IsNullOrWhiteSpace(beforeId);
            var maxPage = useCursor ? maxCursorPage : maxTopN;
            var pageSize = limit ?? defaultPage;
            if (pageSize < 1)
                pageSize = defaultPage;
            if (pageSize > maxPage)
                pageSize = maxPage;

            var ordered = secrets.ListForOwner(user.Id)
                .Concat(requests.ListForOwner(user.Id))
                .OrderByDescending(i => i.CreatedAt)
                .ThenByDescending(i => i.Id)
                .ToList();

            IEnumerable<DashboardItem> pageQuery = ordered;
            if (useCursor)
            {
                var at = beforeCreatedAt!.Trim();
                var id = beforeId!.Trim();
                pageQuery = ordered.Where(i =>
                    string.CompareOrdinal(i.CreatedAt, at) < 0
                    || (string.CompareOrdinal(i.CreatedAt, at) == 0
                        && string.CompareOrdinal(i.Id, id) < 0));
            }

            var page = pageQuery.Take(pageSize).ToList();
            bool hasMore;
            if (page.Count == 0 || page.Count < pageSize)
            {
                hasMore = false;
            }
            else
            {
                var last = page[^1];
                hasMore = ordered.Any(i =>
                    string.CompareOrdinal(i.CreatedAt, last.CreatedAt) < 0
                    || (string.CompareOrdinal(i.CreatedAt, last.CreatedAt) == 0
                        && string.CompareOrdinal(i.Id, last.Id) < 0));
            }

            var items = page.Select(i =>
            {
                var isCollect = string.Equals(i.Kind, "collect", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(i.Kind, "request", StringComparison.OrdinalIgnoreCase);
                return new
                {
                    i.Id,
                    i.Kind,
                    i.Label,
                    i.OneTime,
                    i.CreatedAt,
                    i.ExpiresAt,
                    i.Status,
                    i.ContentType,
                    i.Filename,
                    // Owner-only ciphertext of collect private key (decrypt with UDK in browser).
                    collectSecretKeyCiphertext = i.CollectSecretKey,
                    // Owner-only UDK-encrypted private note (sends).
                    privateNoteCiphertext = i.PrivateNoteCiphertext,
                    maxAccessCount = i.MaxAccessCount,
                    accessCount = i.AccessCount,
                    passwordProtected = i.PasswordProtected,
                    // Send: per-item AllowedCidr; collect: SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS.
                    ipRestricted = isCollect ? collectIpRestricted : i.IpRestricted
                };
            });

            return Results.Ok(new { items, hasMore, pageSize });
        });
    }

    public record CreateRequestBody(
        string? PublicKey,
        /// <summary>Optional client-encrypted (user data key) owner private key for dashboard re-open.</summary>
        string? PrivateKeyCiphertext,
        /// <summary>Owner-only UDK ciphertext of collect name (dashboard).</summary>
        string? Label,
        bool? OneTime,
        int? ExpiryHours,
        int? ExpiryMinutes,
        /// <summary>Multi-view only: max payload collects (1–100000). Null = unlimited until expiry.</summary>
        int? MaxAccessCount,
        /// <summary>Collect name encrypted bound to collect public key (public meta/upload).</summary>
        EncryptedCollectLabelWire? EncryptedLabel,
        /// <summary>Owner-only UDK-encrypted private note.</summary>
        string? PrivateNoteCiphertext,
        /// <summary>When true, text is masked on collect reveal until the eye control is used.</summary>
        bool? HideTextByDefault,
        /// <summary>
        /// Client flag: collect link #sk is PBKDF2-SHA512 + AES-256-GCM package of the owner sk.
        /// Server stores the boolean only; password/package never uploaded.
        /// </summary>
        bool? PasswordProtected);

    public sealed class EncryptedCollectLabelWire
    {
        public int? V { get; set; }
        public string? Bound { get; set; }
        public string? Ciphertext { get; set; }
        public string? Iv { get; set; }
    }

    /// <summary>
    /// Parse stored collect-name wire into a plain object for JSON responses
    /// (avoids JsonElement serialization quirks).
    /// </summary>
    internal static object? ParseEncryptedCollectLabel(string? wire)
    {
        if (string.IsNullOrWhiteSpace(wire))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(wire);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object)
                return null;
            if (!r.TryGetProperty("ciphertext", out var ctEl) || !r.TryGetProperty("iv", out var ivEl))
                return null;
            var ct = ctEl.GetString();
            var iv = ivEl.GetString();
            if (string.IsNullOrWhiteSpace(ct) || string.IsNullOrWhiteSpace(iv))
                return null;
            var v = 1;
            if (r.TryGetProperty("v", out var vEl) && vEl.TryGetInt32(out var vi))
                v = vi;
            var bound = "collect-pk";
            if (r.TryGetProperty("bound", out var bEl) && bEl.GetString() is { Length: > 0 } bs)
                bound = bs;
            return new { v, bound, ciphertext = ct, iv };
        }
        catch
        {
            return null;
        }
    }


    public record UploadBody(
        string? Ciphertext,
        string? Iv,
        string? WrappedKey,
        string? EphemeralPublicKey,
        string? ContentType,
        string? Filename,
        string? PowChallengeId,
        string? PowNonce,
        string? PowHash);
}
