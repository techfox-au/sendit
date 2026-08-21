using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class ClientIpCapabilityTests
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    [InlineData("*", false)]
    [InlineData("  *  ", false)]
    [InlineData("10.0.0.1", true)]
    [InlineData("203.0.113.0/24,10.0.0.1", true)]
    public void IsRestrictiveCollectIpList(string? list, bool restrictive)
    {
        Assert.Equal(restrictive, ClientIpCapability.IsRestrictiveCollectIpList(list));
    }

    [Fact]
    public void Default_restrictions_enabled()
    {
        var cap = new ClientIpCapability();
        Assert.True(cap.IpRestrictionsEnabled);
        Assert.False(cap.PublicClientIpVerified);
        Assert.False(cap.ProbeFinished);
    }

    [Fact]
    public void MarkVerified_keeps_restrictions_enabled()
    {
        var cap = new ClientIpCapability();
        cap.MarkVerified();
        Assert.True(cap.IpRestrictionsEnabled);
        Assert.True(cap.PublicClientIpVerified);
        Assert.True(cap.ProbeFinished);
    }

    [Fact]
    public void MarkUnverified_disables_restrictions()
    {
        var cap = new ClientIpCapability();
        cap.MarkVerified();
        cap.MarkUnverified();
        Assert.False(cap.IpRestrictionsEnabled);
        Assert.True(cap.ProbeFinished);
        Assert.False(cap.PublicClientIpVerified);
    }

    [Fact]
    public void MarkInconclusive_does_not_disable_restrictions()
    {
        var cap = new ClientIpCapability();
        Assert.True(cap.IpRestrictionsEnabled);
        cap.MarkInconclusive();
        Assert.True(cap.IpRestrictionsEnabled);
        Assert.True(cap.ProbeFinished);
        Assert.False(cap.PublicClientIpVerified);
    }

    [Fact]
    public void MarkInconclusive_does_not_re_enable_after_unverified()
    {
        var cap = new ClientIpCapability();
        cap.MarkUnverified();
        Assert.False(cap.IpRestrictionsEnabled);
        cap.MarkInconclusive();
        Assert.False(cap.IpRestrictionsEnabled);
    }
}

public class ClientIpWorkerProbeTests
{
    [Fact]
    public void TryParseWorkerOk_accepts_success_payload()
    {
        var json = """
            {
              "ok": true,
              "worker": { "called": "https://ex/api/v1/diagnostics/client-ip", "upstreamStatus": 200 },
              "check": { "ok": true, "clientIp": "1.2.3.4", "isPrivateOrLocal": false },
              "hint": "good"
            }
            """;
        Assert.True(ClientIpWorkerProbeService.TryParseWorkerOk(json, out var ip, out var hint, out var us));
        Assert.Equal("1.2.3.4", ip);
        Assert.Equal("good", hint);
        Assert.Equal(200, us);
    }

    [Fact]
    public void TryParseWorkerOk_rejects_failure_payload()
    {
        var json = """
            {
              "ok": false,
              "worker": { "upstreamStatus": 503 },
              "check": { "ok": false, "clientIp": "10.0.0.1", "isPrivateOrLocal": true },
              "hint": "private"
            }
            """;
        Assert.False(ClientIpWorkerProbeService.TryParseWorkerOk(json, out var ip, out var hint, out var us));
        Assert.Equal("10.0.0.1", ip);
        Assert.Equal("private", hint);
        Assert.Equal(503, us);
    }

    [Fact]
    public void TryParseWorkerOk_rejects_empty_or_garbage()
    {
        Assert.False(ClientIpWorkerProbeService.TryParseWorkerOk(null, out _, out _, out _));
        Assert.False(ClientIpWorkerProbeService.TryParseWorkerOk("", out _, out _, out _));
        Assert.False(ClientIpWorkerProbeService.TryParseWorkerOk("not-json", out _, out _, out _));
    }

    [Fact]
    public void TryParseNonPublicClientIp_detects_private_flag()
    {
        var json = """
            {
              "ok": false,
              "worker": { "upstreamStatus": 503 },
              "check": { "ok": false, "clientIp": "10.0.0.1", "isPrivateOrLocal": true },
              "hint": "private"
            }
            """;
        Assert.True(ClientIpWorkerProbeService.TryParseNonPublicClientIp(json, out var ip, out var hint, out var us));
        Assert.Equal("10.0.0.1", ip);
        Assert.Equal("private", hint);
        Assert.Equal(503, us);
    }

    [Theory]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("192.168.1.10", true)]
    [InlineData("10.0.0.5", true)]
    [InlineData("172.16.1.1", true)]
    [InlineData("sendit.example.com", false)]
    [InlineData("1.1.1.1", false)]
    public void IsHostUnreachableFromCloudflareWorker(string host, bool unreachable)
    {
        Assert.Equal(unreachable, ClientIpWorkerProbeService.IsHostUnreachableFromCloudflareWorker(host));
    }

    [Fact]
    public void TryParseNonPublicClientIp_ignores_success_and_auth_failures()
    {
        var ok = """
            { "ok": true, "check": { "ok": true, "clientIp": "1.2.3.4", "isPrivateOrLocal": false } }
            """;
        Assert.False(ClientIpWorkerProbeService.TryParseNonPublicClientIp(ok, out _, out _, out _));

        var secret404 = """
            {
              "ok": false,
              "worker": { "upstreamStatus": 404 },
              "check": null,
              "hint": "diagnostics/client-ip returned 404"
            }
            """;
        Assert.False(ClientIpWorkerProbeService.TryParseNonPublicClientIp(secret404, out _, out _, out _));

        Assert.False(ClientIpWorkerProbeService.TryParseNonPublicClientIp(null, out _, out _, out _));
        Assert.False(ClientIpWorkerProbeService.TryParseNonPublicClientIp("not-json", out _, out _, out _));
    }
}
