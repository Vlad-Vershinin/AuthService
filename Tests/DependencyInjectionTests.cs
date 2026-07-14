using Core.Extensions;
using Core.Interfaces;
using Core.Models;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace Tests;

public class DependencyInjectionTests
{
    private const string TestSecret = "super-secret-key-that-is-at-least-32-characters-long!";
    private const string TestIssuer = "MyAuthService";
    private const string TestAudience = "MyApps";

    [Fact]
    public void AddCustomAuth_ShouldRegisterRequiredServices()
    {
        var services = new ServiceCollection();
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 180
        };

        services.AddCustomAuth<Guid>(options);

        var serviceProvider = services.BuildServiceProvider();

        var passwordHasher = serviceProvider.GetService<IPasswordHasher>();
        passwordHasher.Should().NotBeNull();
        passwordHasher.Should().BeOfType<Core.Services.PasswordHasher>();

        var jwtTokenService = serviceProvider.GetService<IJwtTokenService<Guid>>();
        jwtTokenService.Should().NotBeNull();
        jwtTokenService.Should().BeOfType<Core.Services.JwtTokenService<Guid>>();

        var registeredOptions = serviceProvider.GetService<JwtOptions>();
        registeredOptions.Should().NotBeNull();
        registeredOptions.Should().Be(options);
    }

    [Fact]
    public void AddCustomAuth_WithNullOptions_ShouldThrowArgumentNullException()
    {
        var services = new ServiceCollection();

        var action = () => services.AddCustomAuth<Guid>(null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    [Fact]
    public void AddCustomAuth_WithShortSecretKey_ShouldThrowArgumentException()
    {
        var services = new ServiceCollection();
        var options = new JwtOptions
        {
            SecretKey = "too-short",
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var action = () => services.AddCustomAuth<Guid>(options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddCustomAuth_WithEmptySecretKey_ShouldThrowArgumentException()
    {
        var services = new ServiceCollection();
        var options = new JwtOptions
        {
            SecretKey = string.Empty,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var action = () => services.AddCustomAuth<Guid>(options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddCustomAuth_ShouldRegisterAuthenticationScheme()
    {
        var services = new ServiceCollection();
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        services.AddCustomAuth<Guid>(options);

        var registeredSchemes = services.FirstOrDefault(x => 
            x.ServiceType.Name == "IAuthenticationSchemeProvider");
        registeredSchemes.Should().NotBeNull("Authentication scheme should be registered");
    }

    [Fact]
    public void AddCustomAuth_ShouldReturnServiceCollection()
    {
        var services = new ServiceCollection();
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var result = services.AddCustomAuth<Guid>(options);

        result.Should().NotBeNull();
        result.Should().BeAssignableTo<IServiceCollection>();
    }
}
