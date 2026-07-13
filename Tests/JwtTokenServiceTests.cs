using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Core;
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
    }

    [Fact]
    public void GenerateToken_ShouldCreateValidJwtWithCorrectClaims()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "user_test"
        };

        var tokenString = _tokenService.GenerateToken(user, TestSecret, TestIssuer, TestAudience, expiryInMinutes: 30);

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

        var action = () => _tokenService.GenerateToken(user, shortSecret, TestIssuer, TestAudience, 30);

        action.Should().Throw<ArgumentException>();
    }
}