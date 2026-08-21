using Sendit.Api.Configuration;

namespace Sendit.Api.Tests;

public class AllowedEmailDomainsTests
{
    [Fact]
    public void Empty_list_allows_any_domain()
    {
        var o = new SenditOptions();
        Assert.True(o.IsEmailDomainAllowed("anyone@gmail.com"));
    }

    [Fact]
    public void Parses_and_enforces_comma_list()
    {
        var o = new SenditOptions
        {
            AllowedEmailDomains = SenditOptions.ParseDomainList("example.com, example.com.au")
        };
        Assert.True(o.IsEmailDomainAllowed("a@example.com"));
        Assert.True(o.IsEmailDomainAllowed("b@EXAMPLE.COM.AU"));
        Assert.False(o.IsEmailDomainAllowed("c@evil.com"));
        Assert.False(o.IsEmailDomainAllowed("not-an-email"));
    }

    [Fact]
    public void Star_alone_allows_any_domain()
    {
        var o = new SenditOptions
        {
            AllowedEmailDomains = SenditOptions.ParseDomainList("*")
        };
        Assert.Contains("*", o.AllowedEmailDomains);
        Assert.True(o.IsEmailDomainAllowed("anyone@gmail.com"));
        Assert.True(o.IsEmailDomainAllowed("user@corp.example"));
    }

    [Fact]
    public void Star_in_list_still_allows_any_domain()
    {
        var o = new SenditOptions
        {
            AllowedEmailDomains = SenditOptions.ParseDomainList("example.com, *")
        };
        Assert.True(o.IsEmailDomainAllowed("c@evil.com"));
    }
}
