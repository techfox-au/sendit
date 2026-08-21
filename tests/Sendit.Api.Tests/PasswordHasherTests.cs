using Sendit.Api.Configuration;
using Sendit.Api.Services;

namespace Sendit.Api.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Hash_and_verify_round_trip()
    {
        var hasher = new PasswordHasher(new SenditOptions { PasswordHashIterations = 10_000 });
        var result = hasher.Hash("correct horse battery staple");
        Assert.Equal(64, result.Salt.Length);
        Assert.Equal(64, result.Hash.Length);
        Assert.True(hasher.Verify("correct horse battery staple", result.Salt, result.Hash, result.Iterations));
        Assert.False(hasher.Verify("wrong password!!", result.Salt, result.Hash, result.Iterations));
    }

    [Fact]
    public void Rejects_short_password()
    {
        var hasher = new PasswordHasher(new SenditOptions { PasswordHashIterations = 1000 });
        Assert.Throws<ArgumentException>(() => hasher.Hash("short"));
    }
}
