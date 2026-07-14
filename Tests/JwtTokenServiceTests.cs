using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Core.Interfaces;
using Core.Models;
using Core.Services;
using FluentAssertions;

namespace Tests;

public class JwtTokenServiceTests
{
    private readonly IJwtTokenService<Guid> _tokenService;
    private const string TestSecret = "super-secret-key-that-is-at-least-32-characters-long!";
    private const string TestIssuer = "MyAuthService";
    private const string TestAudience = "MyApps";

    public JwtTokenServiceTests()
    {
        _tokenService = new JwtTokenService<Guid>();
    }

    private class TestUser : IAuthUser<Guid>
    {
        public Guid Id { get; set; }
        public string Identity { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public IEnumerable<Claim> CustomClaims { get; set; } = Enumerable.Empty<Claim>();
    }

    [Fact]
    public void GenerateToken_ShouldCreateValidJwtWithCorrectClaims()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "user_test"
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var tokenString = _tokenService.GenerateToken(user, options);

        tokenString.Should().NotBeNullOrWhiteSpace();

        var handler = new JwtSecurityTokenHandler();
        handler.CanReadToken(tokenString).Should().BeTrue();

        var jwtToken = handler.ReadJwtToken(tokenString);

        jwtToken.Issuer.Should().Be(TestIssuer);
        jwtToken.Audiences.Should().Contain(TestAudience);

        var nameIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
        nameIdClaim.Should().NotBeNull();
        nameIdClaim!.Value.Should().Be(user.Id.ToString());

        var nameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
        nameClaim.Should().NotBeNull();
        nameClaim!.Value.Should().Be(user.Identity);
    }

    [Fact]
    public void GenerateToken_WithShortSecret_ShouldThrowArgumentException()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var shortSecret = "too-short";

        var options = new JwtOptions
        {
            SecretKey = shortSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var action = () => _tokenService.GenerateToken(user, options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GenerateToken_WithNullUser_ShouldThrowArgumentNullException()
    {
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var action = () => _tokenService.GenerateToken(null!, options);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("user");
    }

    [Fact]
    public void GenerateToken_WithNullOptions_ShouldThrowArgumentNullException()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };

        var action = () => _tokenService.GenerateToken(user, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    [Fact]
    public void GenerateToken_WithEmptySecretKey_ShouldThrowArgumentException()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = string.Empty,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var action = () => _tokenService.GenerateToken(user, options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GenerateToken_ShouldIncludeCustomClaims()
    {
        var customClaims = new List<Claim>
        {
            new Claim("role", "admin"),
            new Claim("department", "engineering")
        };

        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "admin_user",
            CustomClaims = customClaims
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 60
        };

        var tokenString = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(tokenString);

        var roleClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "role");
        roleClaim.Should().NotBeNull();
        roleClaim!.Value.Should().Be("admin");

        var departmentClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "department");
        departmentClaim.Should().NotBeNull();
        departmentClaim!.Value.Should().Be("engineering");
    }

    [Fact]
    public void GenerateToken_ShouldSetCorrectExpiration()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "user_test"
        };

        int expiryMinutes = 60;
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = expiryMinutes
        };

        var tokenString = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(tokenString);

        var timeDifference = (jwtToken.ValidTo - DateTime.UtcNow).TotalMinutes;
        timeDifference.Should().BeGreaterThanOrEqualTo(expiryMinutes - 1)
            .And.BeLessThanOrEqualTo(expiryMinutes + 1);
    }

    [Fact]
    public void GenerateToken_ShouldIncludeJtiClaim()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "user_test"
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var tokenString = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(tokenString);

        var jtiClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
        jtiClaim.Should().NotBeNull();
        Guid.TryParse(jtiClaim!.Value, out _).Should().BeTrue();
    }
}