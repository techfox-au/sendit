using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sendit.Api.Configuration;
using Sendit.Api.Services;
using Sendit.Api.Util;

namespace Sendit.Api.Tests;

public class UserStorageQuotaTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    public UserStorageQuotaTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private static readonly string DummyWrappedKey =
        "{\"v\":1,\"alg\":\"test\",\"iterations\":1,\"salt\":\"YQ\",\"iv\":\"YQ\",\"ct\":\"YQ\"}";

    private (WebApplicationFactory<Program> Factory, CapturingEmailSender Email) CreateFactory(int quotaMb)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "sendit-quota-" + Guid.NewGuid().ToString("N") + ".db");
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
                    PowDifficultyBits = 1,
                    UserStorageQuotaMb = quotaMb,
                    MaxUploadBytes = 50_000_000
                });

                var emailDesc = services.Single(d => d.ServiceType == typeof(IEmailSender));
                services.Remove(emailDesc);
                services.AddSingleton<IEmailSender>(email);
            });
        });

        return (factory, email);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });

    [Fact]
    public void Default_quota_is_1024_mb()
    {
        var o = new SenditOptions();
        Assert.Equal(1024, o.UserStorageQuotaMb);
        Assert.Equal(1024L * 1024 * 1024, o.UserStorageQuotaBytes);
    }

    [Fact]
    public async Task Send_rejected_when_quota_exceeded()
    {
        // ~1 KB quota so a modest ciphertext fails after a first small send.
        var (factory, email) = CreateFactory(quotaMb: 1);
        using var client = CreateClient(factory);
        await RegisterAndConfirmAsync(client, email, "quota@example.com", "password123");

        // First send: ~200 KB ciphertext fits in 1 MB.
        var ok = await CreateSendAsync(client, payloadBytes: 200_000);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        // Second send: another ~900 KB would exceed 1 MB total.
        var over = await CreateSendAsync(client, payloadBytes: 900_000);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, over.StatusCode);
        var body = await over.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Contains("quota", body?.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<HttpResponseMessage> CreateSendAsync(HttpClient client, int payloadBytes)
    {
        var ct = RandomNumberGenerator.GetBytes(payloadBytes);
        var iv = RandomNumberGenerator.GetBytes(12);
        var wk = RandomNumberGenerator.GetBytes(48);
        var eph = RandomNumberGenerator.GetBytes(32);
        return await client.PostAsJsonAsync("/api/v1/send", new
        {
            ciphertext = Base64Url.Encode(ct),
            iv = Base64Url.Encode(iv),
            wrappedKey = Base64Url.Encode(wk),
            ephemeralPublicKey = Base64Url.Encode(eph),
            contentType = "application/octet-stream",
            oneTime = true,
            expiryMinutes = 60
        });
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

    private sealed class ErrorDto
    {
        public string? Error { get; set; }
    }
}
