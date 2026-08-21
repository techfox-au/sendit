namespace Sendit.Api.Services;

/// <summary>
/// Runtime gate for send/collect IP allow-lists after the Cloudflare Worker canary.
/// <list type="bullet">
/// <item><b>Default:</b> restrictions <see cref="IpRestrictionsEnabled"/> = true (optimistic).</item>
/// <item><b>MarkVerified:</b> Worker saw a public client IP — keep enabled; set <see cref="PublicClientIpVerified"/>.</item>
/// <item><b>MarkUnverified:</b> Worker saw non-public IP, or probe skipped — disable restrictions
/// (and may force process exit if collect retrieve allow-list is set).</item>
/// <item><b>MarkInconclusive:</b> cannot reach Worker / odd response — do <em>not</em> disable restrictions.</item>
/// </list>
/// Consumed by <c>POST /api/v1/send</c>, send meta/payload, collect payload, and
/// <c>GET /api/v1/branding/config</c> (UI hides Allowed IPs when disabled).
/// </summary>
public sealed class ClientIpCapability
{
    private readonly object _gate = new();
    private bool _verified;
    private bool _disabled;
    private bool _probeFinished;

    /// <summary>True only after a successful public-IP Worker probe this process lifetime.</summary>
    public bool PublicClientIpVerified
    {
        get { lock (_gate) return _verified; }
    }

    /// <summary>
    /// When false, create-send Allowed IPs is rejected/hidden and allow-lists are not enforced.
    /// True by default; false only after <see cref="MarkUnverified"/>.
    /// </summary>
    public bool IpRestrictionsEnabled
    {
        get { lock (_gate) return !_disabled; }
    }

    /// <summary>True after the one-shot probe finished (any outcome, including inconclusive).</summary>
    public bool ProbeFinished
    {
        get { lock (_gate) return _probeFinished; }
    }

    /// <summary>Worker JSON <c>ok: true</c> with a public client IP.</summary>
    public void MarkVerified()
    {
        lock (_gate)
        {
            _verified = true;
            _disabled = false;
            _probeFinished = true;
        }
    }

    /// <summary>
    /// Definitive non-public client IP or probe skipped (local base URL / Worker disabled).
    /// Turns restrictions off.
    /// </summary>
    public void MarkUnverified()
    {
        lock (_gate)
        {
            _verified = false;
            _disabled = true;
            _probeFinished = true;
        }
    }

    /// <summary>
    /// Worker unreachable or response not a proven public/non-public IP.
    /// Leaves restriction enablement unchanged (still enabled unless previously unverified).
    /// </summary>
    public void MarkInconclusive()
    {
        lock (_gate)
        {
            _probeFinished = true;
        }
    }

    /// <summary>
    /// True when <c>SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS</c> is a real allow-list
    /// (not null/empty/"*") — used to hard-fail startup if restrictions must be disabled.
    /// </summary>
    public static bool IsRestrictiveCollectIpList(string? collectionRetrieveAllowedIps)
    {
        if (string.IsNullOrWhiteSpace(collectionRetrieveAllowedIps))
            return false;
        return collectionRetrieveAllowedIps.Trim() != "*";
    }
}
