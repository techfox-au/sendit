using System.Net;
using Sendit.Api.Util;

namespace Sendit.Api.Tests;

public class IpRestrictionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_means_no_restriction(string? input)
    {
        Assert.True(IpRestriction.TryNormalize(input, out var canon, out var err));
        Assert.Null(err);
        Assert.Null(canon);
        Assert.True(IpRestriction.IsClientAllowed(null, IPAddress.Parse("1.2.3.4")));
    }

    [Theory]
    [InlineData("192.168.1.1", "192.168.1.1")]
    [InlineData("0.0.0.0", "0.0.0.0")]
    [InlineData("255.255.255.255", "255.255.255.255")]
    public void Accepts_single_ipv4(string input, string expected)
    {
        Assert.True(IpRestriction.TryNormalize(input, out var canon, out var err), err);
        Assert.Equal(expected, canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse(expected)));
        Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("10.0.0.1")));
    }

    [Theory]
    [InlineData("2001:db8::1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public void Accepts_single_ipv6(string input)
    {
        Assert.True(IpRestriction.TryNormalize(input, out var canon, out var err), err);
        Assert.NotNull(canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse(input)));
        Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db8::2")));
    }

    [Theory]
    [InlineData("192.168.0.0/24", "192.168.0.0/24")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    public void Accepts_ipv4_cidr(string input, string expected)
    {
        Assert.True(IpRestriction.TryNormalize(input, out var canon, out var err), err);
        Assert.Equal(expected, canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("192.168.0.50")) || !input.StartsWith("192"));
        if (input.StartsWith("192.168"))
        {
            Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("192.168.0.50")));
            Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("192.168.1.1")));
        }
    }

    [Fact]
    public void Accepts_ipv6_cidr()
    {
        Assert.True(IpRestriction.TryNormalize("2001:db8::/32", out var canon, out var err), err);
        Assert.Equal("2001:db8::/32", canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db8::abcd")));
        Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db9::1")));
    }

    [Theory]
    [InlineData("192.168.0.0/33")]
    [InlineData("192.168.0.0/-1")]
    [InlineData("192.168.0.0/500")]
    [InlineData("not-an-ip")]
    [InlineData("1.2.3")]
    [InlineData("01.2.3.4")]
    [InlineData("::ffff:1.2.3.4")]
    [InlineData("fe80::1%eth0")]
    [InlineData("1.2.3.4/24/8")]
    [InlineData("2001:db8::/129")]
    public void Rejects_malformed(string input)
    {
        Assert.False(IpRestriction.TryNormalize(input, out var canon, out var err));
        Assert.Null(canon);
        Assert.False(string.IsNullOrEmpty(err));
    }

    [Fact]
    public void Accepts_cidr_with_host_bits_set()
    {
        Assert.True(IpRestriction.TryNormalize("192.168.1.5/24", out var canon, out var err), err);
        Assert.Equal("192.168.1.0/24", canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("192.168.1.200")));
    }

    [Fact]
    public void Ipv4_mapped_client_matches_ipv4_rule()
    {
        Assert.True(IpRestriction.TryNormalize("127.0.0.1", out var canon, out _));
        var mapped = IPAddress.Parse("::ffff:127.0.0.1");
        Assert.True(IpRestriction.IsClientAllowed(canon, mapped));
    }

    [Fact]
    public void Family_mismatch_denies()
    {
        Assert.True(IpRestriction.TryNormalize("192.168.0.0/16", out var v4, out _));
        Assert.False(IpRestriction.IsClientAllowed(v4, IPAddress.Parse("2001:db8::1")));
        Assert.True(IpRestriction.TryNormalize("2001:db8::/32", out var v6, out _));
        Assert.False(IpRestriction.IsClientAllowed(v6, IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public void Accepts_comma_separated_list()
    {
        Assert.True(
            IpRestriction.TryNormalize(
                "203.0.113.10, 192.168.1.0/24, 2001:db8::1, 2001:db8:1::/48",
                out var canon,
                out var err),
            err);
        Assert.Equal("203.0.113.10,192.168.1.0/24,2001:db8::1,2001:db8:1::/48", canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("203.0.113.10")));
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("192.168.1.50")));
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db8::1")));
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db8:1::abcd")));
        Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public void Rejects_list_with_one_bad_entry()
    {
        Assert.False(IpRestriction.TryNormalize("1.2.3.4, not-an-ip", out var canon, out var err));
        Assert.Null(canon);
        Assert.Contains("Entry 2", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Dedupes_list_entries()
    {
        Assert.True(IpRestriction.TryNormalize("1.2.3.4, 1.2.3.4, 10.0.0.0/8", out var canon, out _));
        Assert.Equal("1.2.3.4,10.0.0.0/8", canon);
    }

    [Theory]
    [InlineData("*")]
    [InlineData(" * ")]
    [InlineData("1.2.3.4, *")]
    [InlineData("*, 10.0.0.0/8")]
    public void Star_wildcard_allows_any_ip(string input)
    {
        Assert.True(IpRestriction.TryNormalize(input, out var canon, out var err), err);
        Assert.Equal("*", canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("203.0.113.50")));
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Collection_retrieve_option_parses_like_send_allowlist()
    {
        // Same normalization as SENDIT_COLLECTION_RETRIEVE_ALLOWED_IPS at startup.
        Assert.True(
            IpRestriction.TryNormalize("203.0.113.10, 10.0.0.0/8", out var canon, out var err),
            err);
        Assert.Equal("203.0.113.10,10.0.0.0/8", canon);
        Assert.True(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("10.1.2.3")));
        Assert.False(IpRestriction.IsClientAllowed(canon, IPAddress.Parse("198.51.100.1")));
        Assert.True(IpRestriction.IsClientAllowed(null, IPAddress.Parse("198.51.100.1")));
        Assert.True(IpRestriction.IsClientAllowed("*", IPAddress.Parse("198.51.100.1")));
    }
}
