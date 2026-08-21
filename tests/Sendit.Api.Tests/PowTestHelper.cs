using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

/// <summary>Solve server PoW challenges in integration tests (difficulty is always ≥ 1).</summary>
internal static class PowTestHelper
{
    public sealed record Solution(string ChallengeId, string Nonce, string Hash);

    public static async Task<Solution> SolveAsync(HttpClient client, string challengePath)
    {
        var res = await client.GetAsync(challengePath);
        res.EnsureSuccessStatusCode();
        var ch = await res.Content.ReadFromJsonAsync<ChallengeDto>();
        Assert.NotNull(ch);
        Assert.False(string.IsNullOrEmpty(ch.ChallengeId));
        Assert.False(string.IsNullOrEmpty(ch.HmacKey));
        Assert.True(ch.DifficultyBits >= 1);

        var key = Base64UrlDecode(ch.HmacKey!);
        for (var n = 0; n < 2_000_000; n++)
        {
            var s = n.ToString();
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(s));
            if (ProofOfWorkService.HasLeadingZeroBits(mac, ch.DifficultyBits))
                return new Solution(ch.ChallengeId!, s, Base64UrlEncode(mac));
        }

        throw new InvalidOperationException("Could not solve PoW within iteration budget.");
    }

    public static async Task<Solution> SolveLoginAsync(HttpClient client, string email) =>
        await SolveAsync(client, "/api/v1/auth/login/pow?email=" + Uri.EscapeDataString(email));

    public static async Task<Solution> SolveEmailOtpAsync(HttpClient client, string ticket) =>
        await SolveAsync(
            client,
            "/api/v1/auth/login/email-otp/pow?ticket=" + Uri.EscapeDataString(ticket));

    public static async Task<Solution> SolveSendAsync(HttpClient client, string id) =>
        await SolveAsync(client, "/api/v1/send/" + Uri.EscapeDataString(id) + "/pow");

    public static string ToQuery(Solution pow) =>
        "?powChallengeId=" + Uri.EscapeDataString(pow.ChallengeId)
        + "&powNonce=" + Uri.EscapeDataString(pow.Nonce)
        + "&powHash=" + Uri.EscapeDataString(pow.Hash);

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class ChallengeDto
    {
        public string? ChallengeId { get; set; }
        public string? HmacKey { get; set; }
        public int DifficultyBits { get; set; }
        public string? ExpiresAt { get; set; }
    }
}
