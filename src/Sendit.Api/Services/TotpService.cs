using OtpNet;

namespace Sendit.Api.Services;

/// <summary>
/// TOTP (RFC 6238) helpers using Otp.NET.
/// Enrollment flow: Begin → show otpauth URI / QR → Confirm with a valid code → enabled.
/// Codes are 8 digits, SHA1, 30s step, ±1 step clock skew.
/// </summary>
public sealed class TotpService
{
    private const string Issuer = "Sendit!";
    private const int StepSeconds = 30;
    private const int Digits = 8;
    private const OtpHashMode HashMode = OtpHashMode.Sha1;

    public string GenerateSecret()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    public string BuildOtpAuthUri(string email, string base32Secret)
    {
        var label = Uri.EscapeDataString($"{Issuer}:{email}");
        var secret = Uri.EscapeDataString(base32Secret);
        var issuer = Uri.EscapeDataString(Issuer);
        return $"otpauth://totp/{label}?secret={secret}&issuer={issuer}" +
               $"&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
    }

    public bool Verify(string base32Secret, string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;
        // Digits only — strip spaces, hyphens, and any non-digit paste noise.
        code = new string(code.Where(char.IsDigit).ToArray());
        if (code.Length != Digits)
            return false;

        try
        {
            var key = Base32Encoding.ToBytes(base32Secret);
            var totp = new Totp(key, step: StepSeconds, mode: HashMode, totpSize: Digits);
            // Allow ±1 step clock skew.
            return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
        }
        catch
        {
            return false;
        }
    }
}
