using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sendit.Api.Configuration;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class CheckIpEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    public CheckIpEndpointTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private WebApplicationFactory<Program> CreateFactory(string? probeSecret)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "sendit-checkip-" + Guid.NewGuid().ToString("N") + ".db");
        return _baseFactory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                var optionsDesc = services.Single(d => d.ServiceType == typeof(SenditOptions));
                services.Remove(optionsDesc);
                services.AddSingleton(new SenditOptions
                {
                    DbPath = dbPath,
                    PasswordHashIterations = 5_000,
                    PasswordAttemptIntervalSeconds = 0,
                    PublicBaseUrl = "http://localhost",
                    MinExpiryMinutes = 1,
                    PowDifficultyBits = 1
                });

                var authDesc = services.SingleOrDefault(d => d.ServiceType == typeof(ClientIpProbeAuth));
                if (authDesc is not null)
                    services.Remove(authDesc);
                services.AddSingleton(new ClientIpProbeAuth(probeSecret));
            });
        });
    }

    [Fact]
    public async Task CheckIp_without_header_returns_404()
    {
        await using var factory = CreateFactory(ClientIpProbeAuth.DefaultSecret);
        var client = factory.CreateClient();
        var res = await client.GetAsync("/api/v1/diagnostics/client-ip");
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task CheckIp_null_secret_uses_built_in_default()
    {
        await using var factory = CreateFactory(null);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(ClientIpProbeAuth.HeaderName, ClientIpProbeAuth.DefaultSecret);
        var res = await client.GetAsync("/api/v1/diagnostics/client-ip");
        // TestServer peer is loopback → 503 with valid default secret.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);
    }

    [Fact]
    public async Task CheckIp_with_wrong_secret_returns_404()
    {
        await using var factory = CreateFactory("test-probe-secret-ok16");
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(ClientIpProbeAuth.HeaderName, "wrong-secret-value!!");
        var res = await client.GetAsync("/api/v1/diagnostics/client-ip");
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task CheckIp_with_valid_secret_reports_private_loopback_as_503()
    {
        const string secret = "test-probe-secret-ok16";
        await using var factory = CreateFactory(secret);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(ClientIpProbeAuth.HeaderName, secret);

        var res = await client.GetAsync("/api/v1/diagnostics/client-ip");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);

        var doc = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.True(doc.GetProperty("isPrivateOrLocal").GetBoolean());
        Assert.True(doc.TryGetProperty("clientIp", out var ipEl));
        Assert.False(string.IsNullOrWhiteSpace(ipEl.GetString()));
    }

    [Fact]
    public async Task CheckIp_accepts_bearer_secret()
    {
        const string secret = "test-probe-secret-ok16";
        await using var factory = CreateFactory(secret);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", secret);

        var res = await client.GetAsync("/api/v1/diagnostics/client-ip");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);
    }
}
