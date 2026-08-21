using Sendit.Api.Configuration;

namespace Sendit.Api.Tests;

public class BannedEmailsTests
{
    [Fact]
    public void Empty_list_bans_nobody()
    {
        var o = new SenditOptions();
        Assert.False(o.IsEmailBanned("anyone@example.com"));
        Assert.True(o.IsRegistrationAllowed("anyone@example.com"));
    }

    [Fact]
    public void Parses_and_enforces_comma_list()
    {
        var o = new SenditOptions
        {
            BannedEmails = SenditOptions.ParseEmailList(
                "bad@example.com,  SPAM@Evil.ORG ,not-an-email, @nodomain, local@")
        };
        Assert.Equal(2, o.BannedEmails.Count);
        Assert.True(o.IsEmailBanned("bad@example.com"));
        Assert.True(o.IsEmailBanned("BAD@EXAMPLE.COM"));
        Assert.True(o.IsEmailBanned("spam@evil.org"));
        Assert.False(o.IsEmailBanned("good@example.com"));
        Assert.False(o.IsRegistrationAllowed("bad@example.com"));
        Assert.True(o.IsRegistrationAllowed("good@example.com"));
    }

    [Fact]
    public void Ban_overrides_open_domain_allow_list()
    {
        var o = new SenditOptions
        {
            AllowedEmailDomains = SenditOptions.ParseDomainList("*"),
            BannedEmails = SenditOptions.ParseEmailList("blocked@corp.example")
        };
        Assert.True(o.IsEmailDomainAllowed("blocked@corp.example"));
        Assert.False(o.IsRegistrationAllowed("blocked@corp.example"));
        Assert.True(o.IsRegistrationAllowed("ok@corp.example"));
    }

    [Fact]
    public void Ban_with_domain_allow_list()
    {
        var o = new SenditOptions
        {
            AllowedEmailDomains = SenditOptions.ParseDomainList("corp.example"),
            BannedEmails = SenditOptions.ParseEmailList("alice@corp.example")
        };
        Assert.False(o.IsRegistrationAllowed("alice@corp.example"));
        Assert.True(o.IsRegistrationAllowed("bob@corp.example"));
        Assert.False(o.IsRegistrationAllowed("eve@other.com"));
    }

    [Fact]
    public void FromEnvironment_loads_banned_emails()
    {
        var prev = Environment.GetEnvironmentVariable("SENDIT_BANNED_EMAILS");
        try
        {
            Environment.SetEnvironmentVariable("SENDIT_BANNED_EMAILS", "x@y.com, Z@Y.COM ");
            var o = SenditOptions.FromEnvironment();
            Assert.True(o.IsEmailBanned("x@y.com"));
            Assert.True(o.IsEmailBanned("z@y.com"));
            Assert.False(o.IsRegistrationAllowed("x@y.com"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENDIT_BANNED_EMAILS", prev);
        }
    }
}
