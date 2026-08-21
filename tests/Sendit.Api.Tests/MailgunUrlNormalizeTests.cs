using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class MailgunUrlNormalizeTests
{
    [Theory]
    [InlineData(null, "https://api.mailgun.net")]
    [InlineData("", "https://api.mailgun.net")]
    [InlineData("https://api.mailgun.net/", "https://api.mailgun.net")]
    [InlineData("https://api.mailgun.net/v3", "https://api.mailgun.net")]
    [InlineData("https://api.eu.mailgun.net/v3/", "https://api.eu.mailgun.net")]
    public void NormalizeMailgunBaseUrl(string? input, string expected)
    {
        Assert.Equal(expected, EmailSender.NormalizeMailgunBaseUrl(input));
    }

    [Theory]
    [InlineData("mg.example.com", "mg.example.com")]
    [InlineData(" mg.example.com/ ", "mg.example.com")]
    [InlineData("@mg.example.com", "mg.example.com")]
    [InlineData("noreply@mg.example.com", "mg.example.com")]
    [InlineData("sandbox123.mailgun.org", "sandbox123.mailgun.org")]
    public void NormalizeMailgunDomain(string input, string expected)
    {
        Assert.Equal(expected, EmailSender.NormalizeMailgunDomain(input));
    }
}
