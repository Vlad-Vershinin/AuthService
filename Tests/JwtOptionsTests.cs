using Core.Models;
using FluentAssertions;

namespace Tests;

public class JwtOptionsTests
{
    [Fact]
    public void JwtOptions_ShouldHaveDefaultValues()
    {
        var options = new JwtOptions();

        options.SecretKey.Should().Be(string.Empty);
        options.Issuer.Should().Be(string.Empty);
        options.Audience.Should().Be(string.Empty);
        options.ExpiryInMinutes.Should().Be(180);
    }

    [Fact]
    public void JwtOptions_ShouldAllowSettingProperties()
    {
        var options = new JwtOptions
        {
            SecretKey = "my-secret-key-that-is-at-least-32-characters-long!!",
            Issuer = "MyIssuer",
            Audience = "MyAudience",
            ExpiryInMinutes = 120
        };

        options.SecretKey.Should().Be("my-secret-key-that-is-at-least-32-characters-long!!");
        options.Issuer.Should().Be("MyIssuer");
        options.Audience.Should().Be("MyAudience");
        options.ExpiryInMinutes.Should().Be(120);
    }

    [Fact]
    public void JwtOptions_ShouldAllowModifyingPropertiesAfterCreation()
    {
        var options = new JwtOptions();

        options.SecretKey = "another-secret-key-that-is-at-least-32-chars-long!!";
        options.Issuer = "AnotherIssuer";
        options.Audience = "AnotherAudience";
        options.ExpiryInMinutes = 60;

        options.SecretKey.Should().Be("another-secret-key-that-is-at-least-32-chars-long!!");
        options.Issuer.Should().Be("AnotherIssuer");
        options.Audience.Should().Be("AnotherAudience");
        options.ExpiryInMinutes.Should().Be(60);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(1440)]
    [InlineData(10080)]
    public void JwtOptions_ShouldAcceptVariousExpiryValues(int expiryMinutes)
    {
        var options = new JwtOptions { ExpiryInMinutes = expiryMinutes };

        options.ExpiryInMinutes.Should().Be(expiryMinutes);
    }

    [Fact]
    public void JwtOptions_ShouldAcceptEmptyStrings()
    {
        var options = new JwtOptions();

        options.SecretKey = "";
        options.Issuer = "";
        options.Audience = "";

        options.SecretKey.Should().Be("");
        options.Issuer.Should().Be("");
        options.Audience.Should().Be("");
    }

    [Fact]
    public void JwtOptions_ShouldAcceptNullStrings()
    {
        var options = new JwtOptions();

        options.SecretKey = null!;
        options.Issuer = null!;
        options.Audience = null!;

        options.SecretKey.Should().BeNull();
        options.Issuer.Should().BeNull();
        options.Audience.Should().BeNull();
    }
}
