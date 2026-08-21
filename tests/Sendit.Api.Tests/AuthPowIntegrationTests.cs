using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sendit.Api.Configuration;
using Sendit.Api.Data;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

/// <summary>
/// Auth login + email-OTP always require proof-of-work (difficulty ≥ 1).
/// Challenges are bound to email / ticket.
/// </summary>
public class AuthPowIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    public AuthPowIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private (WebApplicationFactory<Program> Factory, CapturingEmailSender Email) CreateFactory(int powBits)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "sendit-auth-pow-" + Guid.NewGuid().ToString("N") + ".db");
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
                    PowDifficultyBits = powBits
                });

                var emailDesc = services.Single(d => d.ServiceType == typeof(IEmailSender));
                services.Remove(emailDesc);
                services.AddSingleton<IEmailSender>(email);
            });
        });

        return (factory, email);
    }

    private static readonly string DummyWrappedKey =
        "{\"v\":1,\"alg\":\"test\",\"iterations\":1,\"salt\":\"YQ\",\"iv\":\"YQ\",\"ct\":\"YQ\"}";

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });

    [Fact]
    public void Default_pow_difficulty_is_12()
    {
        Assert.Equal(12, new SenditOptions().PowDifficultyBits);
        Assert.Equal(12, SenditOptions.RecommendedPowDifficultyBits);
    }

    [Fact]
    public async Task Login_without_pow_returns_403()
    {
        var (factory, _) = CreateFactory(powBits: 4);
        using var client = CreateClient(factory);

        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = "nopow@example.com",
            password = "password123",
            wrappedUserDataKey = DummyWrappedKey
        });
        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
    }

    [Fact]
    public async Task Login_pow_for_wrong_email_rejected()
    {
        var (factory, _) = CreateFactory(powBits: 4);
        using var client = CreateClient(factory);

        // Challenge issued for other@… must not authorize login for withpow@…
        var loginPow = await SolveAuthPowAsync(client, "/api/v1/auth/login/pow?email=other@example.com");
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = "withpow@example.com",
            password = "password123",
            wrappedUserDataKey = DummyWrappedKey,
            powChallengeId = loginPow.ChallengeId,
            powNonce = loginPow.Nonce,
            powHash = loginPow.Hash
        });
        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
    }

    [Fact]
    public async Task Login_and_email_otp_succeed_with_valid_pow()
    {
        var (factory, email) = CreateFactory(powBits: 4);
        using var client = CreateClient(factory);

        const string address = "withpow@example.com";
        var loginPow = await SolveAuthPowAsync(
            client,
            "/api/v1/auth/login/pow?email=" + Uri.EscapeDataString(address));
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = address,
            password = "password123",
            wrappedUserDataKey = DummyWrappedKey,
            powChallengeId = loginPow.ChallengeId,
            powNonce = loginPow.Nonce,
            powHash = loginPow.Hash
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);

        var code = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(code));

        var otpPow = await SolveAuthPowAsync(
            client,
            "/api/v1/auth/login/email-otp/pow?ticket=" + Uri.EscapeDataString(loginBody.EmailOtpTicket!));
        var otp = await client.PostAsJsonAsync("/api/v1/auth/login/email-otp", new
        {
            emailOtpTicket = loginBody.EmailOtpTicket,
            code,
            powChallengeId = otpPow.ChallengeId,
            powNonce = otpPow.Nonce,
            powHash = otpPow.Hash
        });
        Assert.Equal(HttpStatusCode.OK, otp.StatusCode);
    }

    [Fact]
    public async Task Challenge_issue_requires_email_and_returns_bits()
    {
        var (factory, _) = CreateFactory(powBits: 4);
        using var client = CreateClient(factory);
        var missing = await client.GetAsync("/api/v1/auth/login/pow");
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        var res = await client.GetAsync("/api/v1/auth/login/pow?email=a@example.com");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadFromJsonAsync<ChallengeDto>();
        Assert.NotNull(body);
        Assert.Equal(4, body.DifficultyBits);
        Assert.False(string.IsNullOrEmpty(body.ChallengeId));
        Assert.False(string.IsNullOrEmpty(body.HmacKey));
    }

    [Fact]
    public async Task Me_does_not_include_wrapped_user_data_key()
    {
        var (factory, email) = CreateFactory(powBits: 1);
        using var client = CreateClient(factory);

        const string address = "mewrap@example.com";
        var loginPow = await PowTestHelper.SolveLoginAsync(client, address);
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email = address,
            password = "password123",
            wrappedUserDataKey = DummyWrappedKey,
            powChallengeId = loginPow.ChallengeId,
            powNonce = loginPow.Nonce,
            powHash = loginPow.Hash
        });
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        var code = email.TryGetLatestOtpCode();
        var otpPow = await PowTestHelper.SolveEmailOtpAsync(client, loginBody!.EmailOtpTicket!);
        await client.PostAsJsonAsync("/api/v1/auth/login/email-otp", new
        {
            emailOtpTicket = loginBody.EmailOtpTicket,
            code,
            powChallengeId = otpPow.ChallengeId,
            powNonce = otpPow.Nonce,
            powHash = otpPow.Hash
        });

        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meJson = await me.Content.ReadAsStringAsync();
        Assert.DoesNotContain("wrappedUserDataKey", meJson, StringComparison.OrdinalIgnoreCase);

        var pack = await client.GetAsync("/api/v1/auth/user-data-key");
        Assert.Equal(HttpStatusCode.OK, pack.StatusCode);
        var packBody = await pack.Content.ReadFromJsonAsync<KeyPackDto>();
        Assert.False(string.IsNullOrEmpty(packBody!.WrappedUserDataKey));
    }

    [Fact]
    public void Zero_or_negative_pow_bits_clamp_to_one()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "pow-clamp-" + Guid.NewGuid().ToString("N") + ".db");
        var opts = new SenditOptions { DbPath = dbPath, PowDifficultyBits = 0 };
        var pow = new ProofOfWorkService(opts, new DbConnectionFactory(opts));
        Assert.Equal(1, pow.DifficultyBits);

        opts.PowDifficultyBits = -3;
        var powNeg = new ProofOfWorkService(opts, new DbConnectionFactory(opts));
        Assert.Equal(1, powNeg.DifficultyBits);
    }

    private static async Task<(string ChallengeId, string Nonce, string Hash)> SolveAuthPowAsync(
        HttpClient client,
        string path)
    {
        var s = await PowTestHelper.SolveAsync(client, path);
        return (s.ChallengeId, s.Nonce, s.Hash);
    }

    private sealed class ChallengeDto
    {
        public string? ChallengeId { get; set; }
        public string? HmacKey { get; set; }
        public int DifficultyBits { get; set; }
        public string? ExpiresAt { get; set; }
    }

    private sealed class LoginDto
    {
        public bool EmailOtpRequired { get; set; }
        public string? EmailOtpTicket { get; set; }
    }

    private sealed class KeyPackDto
    {
        public string? WrappedUserDataKey { get; set; }
    }
}
