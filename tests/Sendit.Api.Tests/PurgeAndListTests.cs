using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sendit.Api.Configuration;
using Sendit.Api.Services;
using Sendit.Api.Util;

namespace Sendit.Api.Tests;

/// <summary>
/// Expired and one-time-consumed secrets must leave the dashboard list and be purged from the DB.
/// </summary>
public class PurgeAndListTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    public PurgeAndListTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private (WebApplicationFactory<Program> Factory, CapturingEmailSender Email, string DbPath) CreateFactory()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "sendit-purge-" + Guid.NewGuid().ToString("N") + ".db");
        var email = new CapturingEmailSender();

        var factory = _baseFactory.WithWebHostBuilder(builder =>
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
                    MaxExpiryHours = 1080,
                    PowDifficultyBits = 1 // cheap always-on PoW for tests
                });

                var emailDesc = services.Single(d => d.ServiceType == typeof(IEmailSender));
                services.Remove(emailDesc);
                services.AddSingleton<IEmailSender>(email);
            });
        });

        return (factory, email, dbPath);
    }

    private static readonly string DummyWrappedKey =
        "{\"v\":1,\"alg\":\"test\",\"iterations\":1,\"salt\":\"YQ\",\"iv\":\"YQ\",\"ct\":\"YQ\"}";

    [Fact]
    public async Task Dashboard_hides_and_purges_expired_and_consumed_secrets()
    {
        var (factory, email, _) = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = true
        });

        await RegisterAndConfirmAsync(client, email, "purge@example.com", "password123");

        // Active share (long expiry) — stays.
        var activeId = await CreateShareAsync(client, label: "active", oneTime: true, expiryMinutes: 60);

        // Already-expired share — must not appear on dashboard.
        var expiredId = CreateSecretDirect(factory, "purge@example.com", "expired",
            oneTime: true, expiresAt: DateTimeOffset.UtcNow.AddMinutes(-5));

        // One-time share we will burn via retrieve.
        var burnId = await CreateShareAsync(client, label: "burn-me", oneTime: true, expiryMinutes: 60);

        var before = await client.GetFromJsonAsync<ItemsDto>("/api/v1/me/items");
        Assert.NotNull(before);
        Assert.Contains(before.Items!, i => i.Id == activeId);
        Assert.DoesNotContain(before.Items!, i => i.Id == expiredId);
        Assert.Contains(before.Items!, i => i.Id == burnId);

        // Collect (burn) the one-time share.
        var pow = await PowTestHelper.SolveSendAsync(client, burnId);
        var payload = await client.GetAsync($"/api/v1/send/{burnId}{PowTestHelper.ToQuery(pow)}");
        Assert.Equal(HttpStatusCode.OK, payload.StatusCode);

        // List must hide consumed immediately; purge should remove expired+consumed from DB.
        var after = await client.GetFromJsonAsync<ItemsDto>("/api/v1/me/items");
        Assert.NotNull(after);
        Assert.Contains(after.Items!, i => i.Id == activeId);
        Assert.DoesNotContain(after.Items!, i => i.Id == burnId);
        Assert.DoesNotContain(after.Items!, i => i.Id == expiredId);

        // Direct store checks: purge deleted expired + consumed rows.
        using var scope = factory.Services.CreateScope();
        var secrets = scope.ServiceProvider.GetRequiredService<SecretStore>();
        Assert.Null(secrets.GetMeta(expiredId));
        Assert.Null(secrets.GetMeta(burnId));
        Assert.NotNull(secrets.GetMeta(activeId));
    }

    private static string CreateSecretDirect(
        WebApplicationFactory<Program> factory,
        string ownerEmail,
        string label,
        bool oneTime,
        DateTimeOffset expiresAt)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserStore>();
        var secrets = scope.ServiceProvider.GetRequiredService<SecretStore>();
        var user = users.FindByEmail(ownerEmail)
            ?? throw new InvalidOperationException("user missing");

        // Minimal valid AES-GCM-shaped blobs (server does not validate crypto of stored bytes).
        var ct = new byte[32];
        var iv = new byte[12];
        var wk = new byte[48];
        Random.Shared.NextBytes(ct);
        Random.Shared.NextBytes(iv);
        Random.Shared.NextBytes(wk);

        return secrets.Create(
            user.Id,
            label,
            ct,
            iv,
            wk,
            ephemeralPublicKey: null,
            contentType: "text/plain",
            filename: null,
            oneTime,
            expiresAt);
    }

    private static async Task<string> CreateShareAsync(
        HttpClient client,
        string label,
        bool oneTime,
        int expiryMinutes)
    {
        // Dummy ciphertext fields that pass length checks.
        var ct = Base64Url.Encode(new byte[64]);
        var iv = Base64Url.Encode(new byte[12]);
        var wk = Base64Url.Encode(new byte[48]);
        var epk = Base64Url.Encode(new byte[32]);

        var res = await client.PostAsJsonAsync("/api/v1/send", new
        {
            ciphertext = ct,
            iv,
            wrappedKey = wk,
            ephemeralPublicKey = epk,
            contentType = "text/plain",
            label,
            oneTime,
            expiryMinutes
        });
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task RegisterAndConfirmAsync(
        HttpClient client,
        CapturingEmailSender email,
        string address,
        string password)
    {
        var loginPow = await PowTestHelper.SolveLoginAsync(client, address);
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = address,
            password,
            wrappedUserDataKey = DummyWrappedKey,
            powChallengeId = loginPow.ChallengeId,
            powNonce = loginPow.Nonce,
            powHash = loginPow.Hash
        });
        login.EnsureSuccessStatusCode();
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);

        var code = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(code));

        var otpPow = await PowTestHelper.SolveEmailOtpAsync(client, loginBody.EmailOtpTicket!);
        var otp = await client.PostAsJsonAsync("/api/v1/auth/login/email-otp", new
        {
            emailOtpTicket = loginBody.EmailOtpTicket,
            code,
            powChallengeId = otpPow.ChallengeId,
            powNonce = otpPow.Nonce,
            powHash = otpPow.Hash
        });
        otp.EnsureSuccessStatusCode();
    }

    private sealed class LoginDto
    {
        public bool EmailOtpRequired { get; set; }
        public string? EmailOtpTicket { get; set; }
    }

    private sealed class ItemsDto
    {
        public List<ItemDto>? Items { get; set; }
    }

    private sealed class ItemDto
    {
        public string? Id { get; set; }
        public string? Status { get; set; }
        public string? Kind { get; set; }
    }
}
