using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sendit.Api.Configuration;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class AuthIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    public AuthIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private (WebApplicationFactory<Program> Factory, CapturingEmailSender Email) CreateFactory()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "sendit-auth-" + Guid.NewGuid().ToString("N") + ".db");
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
                    // Always-on PoW: 1 bit is cheap for tests but still issues challenges.
                    PowDifficultyBits = 1
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

    private static async Task<HttpResponseMessage> PostLoginAsync(
        HttpClient client,
        string email,
        string password,
        string? wrap = null)
    {
        var pow = await PowTestHelper.SolveLoginAsync(client, email);
        return await client.PostAsJsonAsync("/api/v1/auth/login", new
        {
            email,
            password,
            wrappedUserDataKey = wrap,
            powChallengeId = pow.ChallengeId,
            powNonce = pow.Nonce,
            powHash = pow.Hash
        });
    }

    private static async Task<HttpResponseMessage> PostEmailOtpAsync(
        HttpClient client,
        string ticket,
        string code)
    {
        var pow = await PowTestHelper.SolveEmailOtpAsync(client, ticket);
        return await client.PostAsJsonAsync("/api/v1/auth/login/email-otp", new
        {
            emailOtpTicket = ticket,
            code,
            powChallengeId = pow.ChallengeId,
            powNonce = pow.Nonce,
            powHash = pow.Hash
        });
    }

    [Fact]
    public async Task Health_ok()
    {
        var (factory, _) = CreateFactory();
        using var client = factory.CreateClient();
        var res = await client.GetAsync("/api/v1/health");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Register_requires_email_otp_before_session()
    {
        var (factory, _) = CreateFactory();
        using var client = CreateClient(factory);

        var login = await PostLoginAsync(client, "user@example.com", "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.NotNull(loginBody);
        Assert.True(loginBody.EmailOtpRequired);
        Assert.False(string.IsNullOrEmpty(loginBody.EmailOtpTicket));

        var meDenied = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, meDenied.StatusCode);
        var guest = await meDenied.Content.ReadFromJsonAsync<MeGuestDto>();
        Assert.False(guest!.Authenticated);
    }

    [Fact]
    public async Task Email_otp_wrong_code_returns_401()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        var login = await PostLoginAsync(client, "otp-fail@example.com", "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);

        var realCode = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(realCode));

        // Deliberately wrong code (invert digits so it cannot match).
        var wrong = new string(realCode!.Select(c => c == '0' ? '1' : '0').ToArray());
        if (wrong == realCode)
            wrong = "000000";

        var otp = await PostEmailOtpAsync(client, loginBody.EmailOtpTicket!, wrong);
        Assert.Equal(HttpStatusCode.Unauthorized, otp.StatusCode);

        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var guest = await me.Content.ReadFromJsonAsync<MeGuestDto>();
        Assert.False(guest!.Authenticated);
    }

    [Fact]
    public async Task Email_otp_invalidated_after_five_wrong_attempts()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "otp-lockout@example.com";
        const string password = "password123";

        var login = await PostLoginAsync(client, address, password, DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);
        var ticket = loginBody.EmailOtpTicket!;

        var realCode = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(realCode));

        // 5 wrong codes → OTP wiped (counter resets server-side).
        for (var i = 0; i < AuthService.MaxEmailOtpFails; i++)
        {
            var wrong = (i + 1).ToString("D6"); // 000001..000005 — not the real code
            if (wrong == realCode)
                wrong = "999999";

            var bad = await PostEmailOtpAsync(client, ticket, wrong);
            Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        }

        // Original code must no longer work after invalidation (OTP row cleared).
        var stale = await PostEmailOtpAsync(client, ticket, realCode!);
        Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        var staleBody = await stale.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Contains("pending", staleBody?.Error ?? "", StringComparison.OrdinalIgnoreCase);

        // Wait past email budget + progressive password interval after OTP fails,
        // then a new sign-in must issue a fresh OTP that works.
        await Task.Delay(TimeSpan.FromSeconds(20));

        var relogin = await PostLoginAsync(client, address, password, DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, relogin.StatusCode);
        var reloginBody = await relogin.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(reloginBody!.EmailOtpRequired);

        var newCode = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(newCode));
        Assert.NotEqual(realCode, newCode);

        var ok = await PostEmailOtpAsync(client, reloginBody.EmailOtpTicket!, newCode!);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Email_otp_success_issues_session()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "otp-ok@example.com";
        var login = await PostLoginAsync(client, address, "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);

        var code = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(code));

        var otp = await PostEmailOtpAsync(client, loginBody.EmailOtpTicket!, code!);
        Assert.Equal(HttpStatusCode.OK, otp.StatusCode);
        var otpBody = await otp.Content.ReadFromJsonAsync<LoginDto>();
        Assert.NotNull(otpBody);
        Assert.False(otpBody.EmailOtpRequired);
        Assert.False(otpBody.TotpRequired);
        Assert.Equal(address, otpBody.User?.Email);

        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadFromJsonAsync<MeDto>();
        Assert.Equal(address, meBody!.Email);
    }

    [Fact]
    public async Task Password_login_wrong_returns_401()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        await RegisterAndConfirmAsync(client, email, "pwd-fail@example.com", "password123");
        await client.PostAsJsonAsync("/api/v1/auth/logout", new { });

        var bad = await PostLoginAsync(client, "pwd-fail@example.com", "not-the-password");
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);

        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var guest = await me.Content.ReadFromJsonAsync<MeGuestDto>();
        Assert.False(guest!.Authenticated);
    }

    [Fact]
    public async Task Password_login_success_returns_session()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "pwd-ok@example.com";
        const string password = "password123";
        await RegisterAndConfirmAsync(client, email, address, password);
        await client.PostAsJsonAsync("/api/v1/auth/logout", new { });

        var meAfterLogout = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, meAfterLogout.StatusCode);
        var guestAfter = await meAfterLogout.Content.ReadFromJsonAsync<MeGuestDto>();
        Assert.False(guestAfter!.Authenticated);

        var login = await PostLoginAsync(client, address, password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.NotNull(body);
        Assert.False(body.EmailOtpRequired);
        Assert.False(body.TotpRequired);
        Assert.Equal(address, body.User?.Email);

        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadFromJsonAsync<MeDto>();
        Assert.Equal(address, meBody!.Email);
    }

    [Fact]
    public async Task Unconfirmed_relogin_with_same_password_reissues_or_reuses_otp()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "relogin@example.com";
        const string password = "password123";

        var first = await PostLoginAsync(client, address, password, DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstBody = await first.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(firstBody!.EmailOtpRequired);
        Assert.False(string.IsNullOrEmpty(email.TryGetLatestOtpCode()));

        // Abandon OTP; sign in again with same credentials.
        var second = await PostLoginAsync(client, address, password, DummyWrappedKey);
        var secondText = await second.Content.ReadAsStringAsync();
        Assert.True(
            second.IsSuccessStatusCode,
            $"Expected success re-login for unconfirmed account, got {(int)second.StatusCode}: {secondText}");
        var secondBody = await second.Content.ReadFromJsonAsync<LoginDto>();
        Assert.NotNull(secondBody);
        Assert.True(secondBody.EmailOtpRequired);
        Assert.False(string.IsNullOrEmpty(secondBody.EmailOtpTicket));
    }

    [Fact]
    public async Task Unconfirmed_relogin_with_new_password_restarts_registration()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "relogin-newpw@example.com";

        var first = await PostLoginAsync(client, address, "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.True((await first.Content.ReadFromJsonAsync<LoginDto>())!.EmailOtpRequired);
        var firstCode = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(firstCode));

        // Email budget: first OTP just sent; wait past the fast-lane interval before resend.
        await Task.Delay(AuthThrottleService.EmailFastInterval + TimeSpan.FromMilliseconds(200));

        // Abandoned OTP; start again with a different password (common after a typo).
        var second = await PostLoginAsync(client, address, "different-password", DummyWrappedKey);
        var secondText = await second.Content.ReadAsStringAsync();
        Assert.True(
            second.IsSuccessStatusCode,
            $"Expected registration restart for unconfirmed account, got {(int)second.StatusCode}: {secondText}");
        var secondBody = await second.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(secondBody!.EmailOtpRequired);

        var code = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(code));
        Assert.NotEqual(firstCode, code); // password change must invalidate prior OTP

        var otp = await PostEmailOtpAsync(client, secondBody.EmailOtpTicket!, code!);
        Assert.Equal(HttpStatusCode.OK, otp.StatusCode);

        // Old password must no longer work after restart (account is now confirmed).
        using var client2 = CreateClient(factory);
        var oldPw = await PostLoginAsync(client2, address, "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.Unauthorized, oldPw.StatusCode);
    }

    [Fact]
    public async Task Unconfirmed_relogin_without_wrap_and_wrong_password_is_invalid()
    {
        var (factory, _) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "relogin-bad@example.com";

        var first = await PostLoginAsync(client, address, "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // API clients that omit wrap still get the generic invalid credentials response.
        var second = await PostLoginAsync(client, address, "wrong-password");
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        var body = await second.Content.ReadFromJsonAsync<ErrorDto>();
        Assert.Equal("Invalid email or password.", body!.Error);
    }

    [Fact]
    public async Task Forgot_password_does_not_email_unconfirmed_accounts()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "forgot-unconfirmed@example.com";
        var start = await PostLoginAsync(client, address, "password123", DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, start.StatusCode);
        Assert.True((await start.Content.ReadFromJsonAsync<LoginDto>())!.EmailOtpRequired);
        Assert.False(string.IsNullOrEmpty(email.TryGetLatestOtpCode()));
        var messagesBefore = email.Messages.Count;

        var forgot = await PostForgotPasswordAsync(client, address);
        Assert.Equal(HttpStatusCode.OK, forgot.StatusCode);
        // Generic success — but no password-reset mail for incomplete registration.
        Assert.Equal(messagesBefore, email.Messages.Count);
        Assert.DoesNotContain(
            email.Messages,
            m => m.Subject.Contains("password reset", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Send_payload_download_emails_owner_when_notify_send_opened()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "notify-send@example.com";
        const string password = "password123";
        await RegisterAndConfirmAsync(client, email, address, password);

        // Enable send-opened notifications.
        var patch = await client.PatchAsJsonAsync(
            "/api/v1/auth/notifications",
            new { notifyCollectReady = false, notifySendOpened = true });
        var patchBody = await patch.Content.ReadAsStringAsync();
        Assert.True(patch.IsSuccessStatusCode, "PATCH notifications failed: " + patchBody);
        Assert.Contains("notifySendOpened", patchBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("true", patchBody, StringComparison.OrdinalIgnoreCase);

        var me = await client.GetAsync("/api/v1/auth/me");
        var meJson = await me.Content.ReadAsStringAsync();
        Assert.Contains("\"notifySendOpened\":true", meJson.Replace(" ", ""), StringComparison.Ordinal);

        static string B64Url(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var create = await client.PostAsJsonAsync(
            "/api/v1/send",
            new
            {
                ciphertext = B64Url(new byte[64]),
                iv = B64Url(new byte[12]),
                wrappedKey = B64Url(new byte[48]),
                ephemeralPublicKey = B64Url(new byte[32]),
                contentType = "text/plain",
                oneTime = false,
                expiryMinutes = 60,
            });
        var createBody = await create.Content.ReadAsStringAsync();
        Assert.True(create.IsSuccessStatusCode, "Create send failed: " + createBody);
        var created = await create.Content.ReadFromJsonAsync<IdDto>();
        Assert.False(string.IsNullOrEmpty(created!.Id));

        while (email.Messages.TryDequeue(out _)) { }

        // Guest client retrieves payload (triggers notify).
        using var guest = CreateClient(factory);
        var pow = await PowTestHelper.SolveSendAsync(guest, created.Id!);
        var get = await guest.GetAsync(
            "/api/v1/send/" + Uri.EscapeDataString(created.Id!) + PowTestHelper.ToQuery(pow));
        var getBody = await get.Content.ReadAsStringAsync();
        Assert.True(get.IsSuccessStatusCode, "Payload get failed: " + getBody);

        // Fire-and-forget email — wait for background send + capture.
        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (DateTime.UtcNow < deadline && email.Messages.IsEmpty)
            await Task.Delay(50);

        Assert.False(
            email.Messages.IsEmpty,
            "Expected a notification email after payload download. Messages=" +
            string.Join(" | ", email.Messages.Select(m => m.Subject + "->" + m.To)));
        Assert.Contains(
            email.Messages,
            m =>
                m.To.Equals(address, StringComparison.OrdinalIgnoreCase)
                && m.Subject.Contains("send was opened", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Forgot_password_emails_confirmed_accounts()
    {
        var (factory, email) = CreateFactory();
        using var client = CreateClient(factory);

        const string address = "forgot-ok@example.com";
        await RegisterAndConfirmAsync(client, email, address, "password123");
        await client.PostAsJsonAsync("/api/v1/auth/logout", new { });

        // OTP and reset share the progressive email budget; wait out the fast interval.
        await Task.Delay(AuthThrottleService.EmailFastInterval + TimeSpan.FromMilliseconds(200));

        // Clear capture so we only assert on the reset message (OTP already sent during register).
        while (email.Messages.TryDequeue(out _)) { }

        var forgot = await PostForgotPasswordAsync(client, address);
        Assert.Equal(HttpStatusCode.OK, forgot.StatusCode);
        Assert.Contains(
            email.Messages,
            m =>
                m.Subject.Contains("password reset", StringComparison.OrdinalIgnoreCase)
                && m.To.Equals(address, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<HttpResponseMessage> PostForgotPasswordAsync(HttpClient client, string email)
    {
        var pow = await PowTestHelper.SolveAsync(
            client,
            "/api/v1/auth/forgot-password/pow?email=" + Uri.EscapeDataString(email));
        return await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new
        {
            email,
            powChallengeId = pow.ChallengeId,
            powNonce = pow.Nonce,
            powHash = pow.Hash
        });
    }

    private static async Task RegisterAndConfirmAsync(
        HttpClient client,
        CapturingEmailSender email,
        string address,
        string password)
    {
        var login = await PostLoginAsync(client, address, password, DummyWrappedKey);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginBody = await login.Content.ReadFromJsonAsync<LoginDto>();
        Assert.True(loginBody!.EmailOtpRequired);

        var code = email.TryGetLatestOtpCode();
        Assert.False(string.IsNullOrEmpty(code));

        var otp = await PostEmailOtpAsync(client, loginBody.EmailOtpTicket!, code!);
        Assert.Equal(HttpStatusCode.OK, otp.StatusCode);
    }

    private sealed class LoginDto
    {
        public bool EmailOtpRequired { get; set; }
        public bool TotpRequired { get; set; }
        public string? EmailOtpTicket { get; set; }
        public string? TotpTicket { get; set; }
        public UserDto? User { get; set; }
    }

    private sealed class UserDto
    {
        public string? Id { get; set; }
        public string? Email { get; set; }
    }

    private sealed class MeDto
    {
        public bool Authenticated { get; set; }
        public string? Email { get; set; }
    }

    private sealed class MeGuestDto
    {
        public bool Authenticated { get; set; }
    }

    private sealed class ErrorDto
    {
        public string? Error { get; set; }
    }

    private sealed class NotifyPrefsDto
    {
        public bool NotifyCollectReady { get; set; }
        public bool NotifySendOpened { get; set; }
    }

    private sealed class IdDto
    {
        public string? Id { get; set; }
    }
}
