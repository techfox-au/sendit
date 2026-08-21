using System.Net;
using Sendit.Api.Util;

namespace Sendit.Api.Tests;

public class ClientIpTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("10.0.0.5", true)]
    [InlineData("172.16.1.2", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.1.10", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("2001:4860:4860::8888", false)]
    public void IsPrivateOrLocal_classifies_addresses(string ip, bool expectPrivate)
    {
        Assert.Equal(expectPrivate, ClientIp.IsPrivateOrLocal(IPAddress.Parse(ip)));
    }

    [Fact]
    public void IsPrivateOrLocal_null_is_private()
    {
        Assert.True(ClientIp.IsPrivateOrLocal(null));
    }
}
